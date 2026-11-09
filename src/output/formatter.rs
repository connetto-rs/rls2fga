use std::path::{Component, Path, PathBuf};

use crate::generator::tuple_generator::{self, TupleQuery};

/// Why writing the output files failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WriteError {
    /// The output name is unusable as a filename.
    #[error("Invalid output name '{name}': {reason}")]
    InvalidName {
        /// The name as the caller spelled it.
        name: String,
        /// What makes it unusable.
        reason: &'static str,
    },
    /// The output directory could not be created.
    #[error("Failed to create output directory: {source}")]
    CreateDirectory {
        /// The underlying filesystem error.
        source: std::io::Error,
    },
    /// One of the output files could not be written.
    #[error("Failed to write {}: {source}", path.display())]
    WriteFile {
        /// The file that failed.
        path: PathBuf,
        /// The underlying filesystem error.
        source: std::io::Error,
    },
}

/// Write the model, the tuple SQL and the report into `output_dir`.
///
/// # Errors
///
/// Returns [`WriteError`] when `name` is unusable as a filename or a write fails.
pub(crate) fn write_output(
    output_dir: &Path,
    name: &str,
    dsl: &str,
    tuples: &[TupleQuery],
    report: &str,
) -> Result<(), WriteError> {
    let name = validate_output_name(name)?;

    std::fs::create_dir_all(output_dir).map_err(|source| WriteError::CreateDirectory { source })?;

    let write_file = |path: PathBuf, contents: &str| {
        std::fs::write(&path, contents).map_err(|source| WriteError::WriteFile { path, source })
    };
    write_file(name.file_in(output_dir, ".fga"), dsl)?;
    write_file(
        name.file_in(output_dir, "_tuples.sql"),
        &tuple_generator::format_tuples(tuples),
    )?;
    write_file(name.file_in(output_dir, "_report.md"), report)?;

    Ok(())
}

/// An output name [`validate_output_name`] has accepted.
///
/// Holding one is the proof that a path built from it stays inside its directory, so
/// nothing else in this module may join a caller's name onto a path.
struct OutputName<'a>(&'a str);

impl OutputName<'_> {
    fn file_in(&self, dir: &Path, suffix: &str) -> PathBuf {
        dir.join(format!("{}{suffix}", self.0))
    }
}

/// Windows reserved device names that must not be used as output names.
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];
const WINDOWS_INVALID_FILENAME_CHARS: &[char] = &['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

fn validate_output_name(name: &str) -> Result<OutputName<'_>, WriteError> {
    let refuse = |reason: &'static str| {
        Err(WriteError::InvalidName {
            name: name.to_string(),
            reason,
        })
    };
    if name.trim().is_empty() {
        return refuse("must not be empty");
    }
    // Reject names containing null bytes or other control characters.
    if name.chars().any(char::is_control) {
        return refuse("control characters are not allowed");
    }
    // Substring rather than component form, which is what CodeQL's path-injection query
    // recognises as a barrier. The component check below is the one that actually holds.
    if name.contains("..") {
        return refuse("'..' is not allowed");
    }
    if name == "." {
        return refuse("'.' is not allowed");
    }
    // Reject invalid filename characters on Windows.
    if name
        .chars()
        .any(|ch| WINDOWS_INVALID_FILENAME_CHARS.contains(&ch))
    {
        return refuse("contains characters invalid in Windows filenames");
    }
    if name.ends_with(' ') || name.ends_with('.') {
        return refuse("trailing spaces or dots are not allowed");
    }
    // Reject Windows reserved device names (case-insensitive), including
    // names with extensions (`CON.txt`) and trailing dot/space variants.
    let windows_component = name.trim_end_matches([' ', '.']);
    let windows_stem = windows_component
        .split_once('.')
        .map_or(windows_component, |(stem, _)| stem);
    let upper = windows_stem.to_ascii_uppercase();
    if WINDOWS_RESERVED.contains(&upper.as_str()) {
        return refuse("Windows reserved device name");
    }
    let candidate = Path::new(name);
    if candidate.is_absolute() {
        return refuse("absolute paths are not allowed");
    }
    if candidate.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return refuse("traversal segments are not allowed");
    }
    Ok(OutputName(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_path(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}_{nanos}"))
    }

    const REPORT: &str = "# rls2fga Translation Report\n";

    #[test]
    fn write_output_reports_directory_creation_errors() {
        let path = unique_path("rls2fga_formatter_file");
        std::fs::write(&path, "not a directory").expect("should create marker file");

        let err = write_output(&path, "output", "model", &[], REPORT)
            .expect_err("directory creation should fail");
        assert!(matches!(err, WriteError::CreateDirectory { .. }));
    }

    #[test]
    fn write_output_rejects_unsafe_name_paths() {
        let dir = unique_path("rls2fga_formatter_dir");
        std::fs::create_dir_all(&dir).expect("should create temp directory");

        let err = write_output(&dir, "nested/output", "model", &[], REPORT)
            .expect_err("unsafe output name should fail validation");
        assert!(matches!(err, WriteError::InvalidName { .. }));

        let err = write_output(&dir, "../escape", "model", &[], REPORT)
            .expect_err("path traversal should fail validation");
        assert!(matches!(err, WriteError::InvalidName { .. }));
    }

    #[test]
    fn write_output_writes_all_artifacts_on_success() {
        let dir = unique_path("rls2fga_formatter_ok");
        let tuples = vec![TupleQuery {
            comment: "-- tuple".to_string(),
            sql: "SELECT 1;".to_string(),
            description: None,
            condition: None,
            skipped: None,
            monetary_locale: None,
        }];

        write_output(&dir, "docs", "model", &tuples, REPORT).expect("write_output should succeed");

        let fga = std::fs::read_to_string(dir.join("docs.fga")).expect("fga file should exist");
        let tuple_sql =
            std::fs::read_to_string(dir.join("docs_tuples.sql")).expect("tuple file should exist");
        let report =
            std::fs::read_to_string(dir.join("docs_report.md")).expect("report should exist");

        assert_eq!(fga, "model");
        assert!(tuple_sql.contains("SELECT 1;"));
        assert!(report.contains("# rls2fga Translation Report"));
    }

    #[test]
    fn validate_output_name_rejects_dot_and_dotdot() {
        assert!(
            validate_output_name(".").is_err(),
            "bare dot should be rejected"
        );
        assert!(
            validate_output_name("..").is_err(),
            "dotdot should be rejected"
        );
    }

    /// A double dot anywhere is refused, not only as a whole component, so the check is the
    /// substring form the path-injection query recognises as a barrier.
    #[test]
    fn validate_output_name_rejects_any_double_dot() {
        for name in ["a..b", "v1..2", "....//....//etc", "report..md"] {
            assert!(
                validate_output_name(name).is_err(),
                "{name} carries a double dot and must be refused"
            );
        }
    }

    #[test]
    fn validate_output_name_rejects_control_characters() {
        let with_null = "name\x00suffix";
        assert!(
            validate_output_name(with_null).is_err(),
            "null byte should be rejected"
        );
        let with_newline = "name\nsuffix";
        assert!(
            validate_output_name(with_newline).is_err(),
            "newline should be rejected"
        );
    }

    #[test]
    fn validate_output_name_rejects_colons() {
        assert!(
            validate_output_name("C:name").is_err(),
            "colon should be rejected"
        );
    }

    #[test]
    fn validate_output_name_rejects_windows_reserved_names() {
        for reserved in &["CON", "con", "NUL", "nul", "COM1", "LPT9"] {
            assert!(
                validate_output_name(reserved).is_err(),
                "Windows reserved name '{reserved}' should be rejected"
            );
        }
    }

    #[test]
    fn validate_output_name_rejects_windows_reserved_names_with_suffixes_or_trailing_chars() {
        for reserved in &[
            "CON.txt", "nul.md", "COM1.sql", "LPT9.log", "AUX.", "PRN ", "NUL..",
        ] {
            assert!(
                validate_output_name(reserved).is_err(),
                "Windows reserved variant '{reserved}' should be rejected"
            );
        }
    }

    #[test]
    fn validate_output_name_rejects_windows_invalid_characters() {
        for invalid in &[
            "bad*name",
            "bad?name",
            "bad|name",
            "bad<name",
            "bad>name",
            "bad\"name",
        ] {
            assert!(
                validate_output_name(invalid).is_err(),
                "Windows-invalid filename '{invalid}' should be rejected"
            );
        }
    }

    #[test]
    fn validate_output_name_rejects_trailing_dot_or_space() {
        for invalid in &["name.", "name ", "report..", "report  "] {
            assert!(
                validate_output_name(invalid).is_err(),
                "name with trailing dot/space '{invalid}' should be rejected"
            );
        }
    }

    #[test]
    fn validate_output_name_accepts_normal_names() {
        assert!(validate_output_name("my_output").is_ok());
        assert!(validate_output_name("schema-v1").is_ok());
        assert!(validate_output_name("report_2024").is_ok());
        // Internal dot is not a Windows-invalid char; only trailing dot or reserved stem (CON.txt) fails.
        assert!(validate_output_name("report.md").is_ok());
    }
}
