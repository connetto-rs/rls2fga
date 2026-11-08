//! rls2fga web app. Translates PostgreSQL DDL and Row Level Security policies
//! into an OpenFGA authorization model, tuple SQL, and a JSON model, entirely
//! client-side in WebAssembly.

mod examples;
mod settings;

use anyhow::{Context, Result};
use dioxus::html::FileData;
use dioxus::prelude::*;
use dioxus_code::{CodeTheme, Theme};
use dioxus_code_editor::{CodeEditor, Language};
use dioxus_free_icons::icons::fa_brands_icons::FaGithub;
use dioxus_free_icons::icons::fa_solid_icons::{
    FaCheck, FaCodeBranch, FaCopy, FaFileCode, FaFolderOpen, FaGlobe, FaGripVertical, FaHeart,
    FaListCheck, FaShareNodes, FaSitemap, FaTableList, FaTag, FaTriangleExclamation, FaUpload,
    FaUser, FaUserShield, FaUsers, FaXmark,
};
use dioxus_free_icons::Icon;

use rls2fga::generator::tuple_generator::format_tuples;
use rls2fga::parser::sql_parser::parse_schema_in_time_zone;
use rls2fga::types::ConfidenceLevel;
use rls2fga::types::{NoteSeverity, TranslationNote};

use crate::examples::{ExampleIcon, EXAMPLES};

const REPO_URL: &str = "https://github.com/connetto-rs/rls2fga";
const SPONSOR_URL: &str = "https://github.com/sponsors/LucaCappelletti94";
const OPENFGA_URL: &str = "https://openfga.dev/";
const PG_RLS_URL: &str = "https://www.postgresql.org/docs/current/ddl-rowsecurity.html";

/// The PostgreSQL elephant, rendered inline so it inherits `currentColor` and so
/// it matches the muted section icons and dark mode. Path from Simple Icons (CC0).
fn postgres_icon() -> Element {
    rsx! {
        svg {
            width: "16",
            height: "16",
            view_box: "0 0 24 24",
            fill: "currentColor",
            role: "img",
            class: "section-icon",
            title { "PostgreSQL" }
            path { d: "M23.5594 14.7228a.5269.5269 0 0 0-.0563-.1191c-.139-.2632-.4768-.3418-1.0074-.2321-1.6533.3411-2.2935.1312-2.5256-.0191 1.342-2.0482 2.445-4.522 3.0411-6.8297.2714-1.0507.7982-3.5237.1222-4.7316a1.5641 1.5641 0 0 0-.1509-.235C21.6931.9086 19.8007.0248 17.5099.0005c-1.4947-.0158-2.7705.3461-3.1161.4794a9.449 9.449 0 0 0-.5159-.0816 8.044 8.044 0 0 0-1.3114-.1278c-1.1822-.0184-2.2038.2642-3.0498.8406-.8573-.3211-4.7888-1.645-7.2219.0788C.9359 2.1526.3086 3.8733.4302 6.3043c.0409.818.5069 3.334 1.2423 5.7436.4598 1.5065.9387 2.7019 1.4334 3.582.553.9942 1.1259 1.5933 1.7143 1.7895.4474.1491 1.1327.1441 1.8581-.7279.8012-.9635 1.5903-1.8258 1.9446-2.2069.4351.2355.9064.3625 1.39.3772a.0569.0569 0 0 0 .0004.0041 11.0312 11.0312 0 0 0-.2472.3054c-.3389.4302-.4094.5197-1.5002.7443-.3102.064-1.1344.2339-1.1464.8115-.0025.1224.0329.2309.0919.3268.2269.4231.9216.6097 1.015.6331 1.3345.3335 2.5044.092 3.3714-.6787-.017 2.231.0775 4.4174.3454 5.0874.2212.5529.7618 1.9045 2.4692 1.9043.2505 0 .5263-.0291.8296-.0941 1.7819-.3821 2.5557-1.1696 2.855-2.9059.1503-.8707.4016-2.8753.5388-4.1012.0169-.0703.0357-.1207.057-.1362.0007-.0005.0697-.0471.4272.0307a.3673.3673 0 0 0 .0443.0068l.2539.0223.0149.001c.8468.0384 1.9114-.1426 2.5312-.4308.6438-.2988 1.8057-1.0323 1.5951-1.6698zM2.371 11.8765c-.7435-2.4358-1.1779-4.8851-1.2123-5.5719-.1086-2.1714.4171-3.6829 1.5623-4.4927 1.8367-1.2986 4.8398-.5408 6.108-.13-.0032.0032-.0066.0061-.0098.0094-2.0238 2.044-1.9758 5.536-1.9708 5.7495-.0002.0823.0066.1989.0162.3593.0348.5873.0996 1.6804-.0735 2.9184-.1609 1.1504.1937 2.2764.9728 3.0892.0806.0841.1648.1631.2518.2374-.3468.3714-1.1004 1.1926-1.9025 2.1576-.5677.6825-.9597.5517-1.0886.5087-.3919-.1307-.813-.5871-1.2381-1.3223-.4796-.839-.9635-2.0317-1.4155-3.5126zm6.0072 5.0871c-.1711-.0428-.3271-.1132-.4322-.1772.0889-.0394.2374-.0902.4833-.1409 1.2833-.2641 1.4815-.4506 1.9143-1.0002.0992-.126.2116-.2687.3673-.4426a.3549.3549 0 0 0 .0737-.1298c.1708-.1513.2724-.1099.4369-.0417.156.0646.3078.26.3695.4752.0291.1016.0619.2945-.0452.4444-.9043 1.2658-2.2216 1.2494-3.1676 1.0128zm2.094-3.988-.0525.141c-.133.3566-.2567.6881-.3334 1.003-.6674-.0021-1.3168-.2872-1.8105-.8024-.6279-.6551-.9131-1.5664-.7825-2.5004.1828-1.3079.1153-2.4468.079-3.0586-.005-.0857-.0095-.1607-.0122-.2199.2957-.2621 1.6659-.9962 2.6429-.7724.4459.1022.7176.4057.8305.928.5846 2.7038.0774 3.8307-.3302 4.7363-.084.1866-.1633.3629-.2311.5454zm7.3637 4.5725c-.0169.1768-.0358.376-.0618.5959l-.146.4383a.3547.3547 0 0 0-.0182.1077c-.0059.4747-.054.6489-.115.8693-.0634.2292-.1353.4891-.1794 1.0575-.11 1.4143-.8782 2.2267-2.4172 2.5565-1.5155.3251-1.7843-.4968-2.0212-1.2217a6.5824 6.5824 0 0 0-.0769-.2266c-.2154-.5858-.1911-1.4119-.1574-2.5551.0165-.5612-.0249-1.9013-.3302-2.6462.0044-.2932.0106-.5909.019-.8918a.3529.3529 0 0 0-.0153-.1126 1.4927 1.4927 0 0 0-.0439-.208c-.1226-.4283-.4213-.7866-.7797-.9351-.1424-.059-.4038-.1672-.7178-.0869.067-.276.1831-.5875.309-.9249l.0529-.142c.0595-.16.134-.3257.213-.5012.4265-.9476 1.0106-2.2453.3766-5.1772-.2374-1.0981-1.0304-1.6343-2.2324-1.5098-.7207.0746-1.3799.3654-1.7088.5321a5.6716 5.6716 0 0 0-.1958.1041c.0918-1.1064.4386-3.1741 1.7357-4.4823a4.0306 4.0306 0 0 1 .3033-.276.3532.3532 0 0 0 .1447-.0644c.7524-.5706 1.6945-.8506 2.802-.8325.4091.0067.8017.0339 1.1742.081 1.939.3544 3.2439 1.4468 4.0359 2.3827.8143.9623 1.2552 1.9315 1.4312 2.4543-1.3232-.1346-2.2234.1268-2.6797.779-.9926 1.4189.543 4.1729 1.2811 5.4964.1353.2426.2522.4522.2889.5413.2403.5825.5515.9713.7787 1.2552.0696.087.1372.1714.1885.245-.4008.1155-1.1208.3825-1.0552 1.717-.0123.1563-.0423.4469-.0834.8148-.0461.2077-.0702.4603-.0994.7662zm.8905-1.6211c-.0405-.8316.2691-.9185.5967-1.0105a2.8566 2.8566 0 0 0 .135-.0406 1.202 1.202 0 0 0 .1342.103c.5703.3765 1.5823.4213 3.0068.1344-.2016.1769-.5189.3994-.9533.6011-.4098.1903-1.0957.333-1.7473.3636-.7197.0336-1.0859-.0807-1.1721-.151zm.5695-9.2712c-.0059.3508-.0542.6692-.1054 1.0017-.055.3576-.112.7274-.1264 1.1762-.0142.4368.0404.8909.0932 1.3301.1066.887.216 1.8003-.2075 2.7014a3.5272 3.5272 0 0 1-.1876-.3856c-.0527-.1276-.1669-.3326-.3251-.6162-.6156-1.1041-2.0574-3.6896-1.3193-4.7446.3795-.5427 1.3408-.5661 2.1781-.463zm.2284 7.0137a12.3762 12.3762 0 0 0-.0853-.1074l-.0355-.0444c.7262-1.1995.5842-2.3862.4578-3.4385-.0519-.4318-.1009-.8396-.0885-1.2226.0129-.4061.0666-.7543.1185-1.0911.0639-.415.1288-.8443.1109-1.3505.0134-.0531.0188-.1158.0118-.1902-.0457-.4855-.5999-1.938-1.7294-3.253-.6076-.7073-1.4896-1.4972-2.6889-2.0395.5251-.1066 1.2328-.2035 2.0244-.1859 2.0515.0456 3.6746.8135 4.8242 2.2824a.908.908 0 0 1 .0667.1002c.7231 1.3556-.2762 6.2751-2.9867 10.5405zm-8.8166-6.1162c-.025.1794-.3089.4225-.6211.4225a.5821.5821 0 0 1-.0809-.0056c-.1873-.026-.3765-.144-.5059-.3156-.0458-.0605-.1203-.178-.1055-.2844.0055-.0401.0261-.0985.0925-.1488.1182-.0894.3518-.1226.6096-.0867.3163.0441.6426.1938.6113.4186zm7.9305-.4114c.0111.0792-.049.201-.1531.3102-.0683.0717-.212.1961-.4079.2232a.5456.5456 0 0 1-.075.0052c-.2935 0-.5414-.2344-.5607-.3717-.024-.1765.2641-.3106.5611-.352.297-.0414.6111.0088.6356.1851z" }
        }
    }
}

fn main() {
    dioxus::launch(App);
}

/// One of the four output views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Dsl,
    TupleSql,
    Json,
}

impl Tab {
    const ALL: [Tab; 3] = [Tab::Dsl, Tab::TupleSql, Tab::Json];

    fn label(self) -> &'static str {
        match self {
            Tab::Dsl => "DSL",
            Tab::TupleSql => "Tuple SQL",
            Tab::Json => "JSON model",
        }
    }

    /// Human sentence used for the tab's tooltip and accessible label.
    fn describe(self) -> &'static str {
        match self {
            Tab::Dsl => "the OpenFGA DSL authorization model",
            Tab::TupleSql => "the SQL that populates OpenFGA tuples from your tables",
            Tab::Json => "the OpenFGA JSON authorization model",
        }
    }
}

/// The full result of one translation run, one string per output view plus what the
/// translation had to say about itself.
#[derive(Clone, PartialEq)]
struct Rendered {
    dsl: String,
    tuple_sql: String,
    json: String,
    notes: Vec<TranslationNote>,
    diverging: Vec<TranslationNote>,
    confidence_summary: Vec<(String, ConfidenceLevel)>,
}

/// Run the parse, plan, render pipeline over the combined SQL. Pure and synchronous:
/// the whole pipeline is cheap enough to run inline on the main thread, so no worker
/// is needed.
fn translate(sql: &str, level: ConfidenceLevel) -> Result<Rendered> {
    let db = parse_schema_in_time_zone(
        &format!("{}{sql}", settings::ROLES),
        settings::SESSION_TIME_ZONE,
    )
    .context("parsing the SQL schema")?;
    let translator = settings::translator(level).context("loading the app's function registry")?;
    let translation = translator
        .translate(&db)
        .context("planning the authorization model")?;
    let diverging: Vec<TranslationNote> = translation
        .notes()
        .iter()
        .filter(|note| note.severity().diverges_from_database())
        .cloned()
        .collect();
    // Decision 10: browsing a partial result is the point of pasting a schema in, so
    // the app accepts the gaps on the reader's behalf and says plainly where the model
    // and the database disagree, above the outputs rather than behind a tab nobody
    // opens.
    let outputs = translation.outputs_accepting_gaps();
    Ok(Rendered {
        dsl: outputs.model(),
        tuple_sql: format_tuples(outputs.tuple_queries()),
        json: serde_json::to_string_pretty(&outputs.json_model())
            .context("serializing the JSON authorization model")?,
        notes: outputs.notes().to_vec(),
        diverging,
        confidence_summary: outputs.confidence_summary().to_vec(),
    })
}

/// Run the pipeline over the current editor contents and write the outcome into
/// the shared signals. Never blanks the output on error: the last good result
/// stays and the failure surfaces inline in the input pane.
fn run_translation(
    sql: Signal<String>,
    min_confidence: Signal<ConfidenceLevel>,
    mut result: Signal<Option<Rendered>>,
    mut parse_error: Signal<Option<String>>,
) {
    if sql.peek().trim().is_empty() {
        result.set(None);
        parse_error.set(None);
        return;
    }
    match translate(&sql.peek(), *min_confidence.peek()) {
        Ok(translation) => {
            result.set(Some(translation));
            parse_error.set(None);
        }
        Err(err) => parse_error.set(Some(format!("{err:#}"))),
    }
}

/// Read uploaded files, order them, concatenate into the editor, and translate.
/// Migrations are concatenated in apply order because later files reference
/// tables and policies created earlier: filename order for a plain multi-select,
/// relative-path order for a folder pick.
fn load_files(
    mut fs: Vec<FileData>,
    by_path: bool,
    mut sql: Signal<String>,
    mut files: Signal<Vec<(String, String)>>,
    min_confidence: Signal<ConfidenceLevel>,
    result: Signal<Option<Rendered>>,
    parse_error: Signal<Option<String>>,
) {
    if by_path {
        fs.sort_by_key(FileData::path);
    } else {
        fs.sort_by_key(FileData::name);
    }
    spawn(async move {
        let mut collected: Vec<(String, String)> = Vec::new();
        for f in &fs {
            if let Ok(text) = f.read_string().await {
                collected.push((f.name(), text));
            }
        }
        if !collected.is_empty() {
            sql.set(concat_files(&collected));
            files.set(collected);
            run_translation(sql, min_confidence, result, parse_error);
        }
    });
}

/// Concatenate uploaded file contents in list order.
fn concat_files(files: &[(String, String)]) -> String {
    files
        .iter()
        .map(|(_, content)| content.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Syntax theme that follows the OS light/dark preference via CSS media queries,
/// no JavaScript.
fn code_theme() -> CodeTheme {
    CodeTheme::system(Theme::GITHUB_LIGHT, Theme::GITHUB_DARK)
}

/// CSS class for a confidence level's colored badge.
fn level_class(level: ConfidenceLevel) -> &'static str {
    match level {
        ConfidenceLevel::A => "level-a",
        ConfidenceLevel::B => "level-b",
        ConfidenceLevel::C => "level-c",
        ConfidenceLevel::D => "level-d",
    }
}

/// CSS class for a note's severity badge, reusing the confidence palette.
fn severity_class(severity: NoteSeverity) -> &'static str {
    match severity {
        NoteSeverity::Unhandled => "level-d",
        NoteSeverity::BelowThreshold | NoteSeverity::Partial => "level-c",
        NoteSeverity::ActionRequired => "level-b",
        NoteSeverity::Faithful => "level-a",
        // A severity this build does not know draws attention rather than blending in.
        _ => "level-c",
    }
}

/// Font Awesome glyph for an example pill.
fn example_icon(icon: ExampleIcon) -> Element {
    match icon {
        ExampleIcon::Ownership => rsx! { Icon { width: 12, height: 12, icon: FaUser } },
        ExampleIcon::Membership => rsx! { Icon { width: 12, height: 12, icon: FaUsers } },
        ExampleIcon::Parent => rsx! { Icon { width: 12, height: 12, icon: FaSitemap } },
        ExampleIcon::PublicFlag => rsx! { Icon { width: 12, height: 12, icon: FaGlobe } },
        ExampleIcon::RoleList => rsx! { Icon { width: 12, height: 12, icon: FaUserShield } },
        ExampleIcon::Composite => rsx! { Icon { width: 12, height: 12, icon: FaCodeBranch } },
        ExampleIcon::Attribute => rsx! { Icon { width: 12, height: 12, icon: FaTag } },
    }
}

/// Font Awesome glyph for an output tab.
fn tab_icon(tab: Tab) -> Element {
    match tab {
        Tab::Dsl => rsx! { Icon { width: 13, height: 13, icon: FaShareNodes } },
        Tab::TupleSql => rsx! { Icon { width: 13, height: 13, icon: FaTableList } },
        Tab::Json => rsx! { Icon { width: 13, height: 13, icon: FaFileCode } },
    }
}

/// Copy text to the clipboard from a user gesture. `navigator.clipboard`
/// requires a secure context (the custom HTTPS domain qualifies) and a gesture,
/// so this runs inside an `onclick`.
fn copy_to_clipboard(text: String) {
    spawn(async move {
        let literal = serde_json::to_string(&text).unwrap_or_else(|_| "\"\"".to_string());
        let js = format!("navigator.clipboard && navigator.clipboard.writeText({literal});");
        let _ = document::eval(&js).await;
    });
}

#[component]
fn App() -> Element {
    let mut sql = use_signal(|| EXAMPLES[0].sql.to_string());
    let mut min_confidence = use_signal(|| ConfidenceLevel::B);
    let active_tab = use_signal(|| Tab::Dsl);
    let result = use_signal::<Option<Rendered>>(|| None);
    let parse_error = use_signal::<Option<String>>(|| None);
    // Ordered (name, content) list from uploads. Kept visible so the user can
    // reorder before translating; reordering rebuilds the editor contents.
    let mut files = use_signal::<Vec<(String, String)>>(Vec::new);
    let mut drag_from = use_signal::<Option<usize>>(|| None);
    let copied_tab = use_signal::<Option<Tab>>(|| None);
    // Which example pill is currently loaded, cleared once the user edits or
    // uploads so a hand-modified schema no longer shows a pill as selected.
    let mut active_example = use_signal::<Option<usize>>(|| Some(0));

    // Preload the first example and translate it once on mount so a first
    // visitor sees real output immediately. `peek` inside keeps it from
    // re-subscribing, so it runs a single time.
    use_effect(move || run_translation(sql, min_confidence, result, parse_error));

    rsx! {
        document::Link { rel: "icon", href: "/favicon.ico", sizes: "any" }
        document::Link { rel: "icon", r#type: "image/png", sizes: "32x32", href: "/favicon-32.png" }
        document::Link { rel: "icon", r#type: "image/png", sizes: "16x16", href: "/favicon-16.png" }
        document::Link { rel: "apple-touch-icon", sizes: "180x180", href: "/apple-touch-icon.png" }
        document::Link { rel: "manifest", href: "/manifest.json" }
        main {
            header {
                div { class: "subtitle-row",
                    h1 {
                        img { class: "logo", src: "/rls2fga.png", alt: "RLS2FGA", width: 76, height: 38 }
                        "RLS2FGA"
                    }
                    nav { class: "topbar-actions", aria_label: "Project resources",
                        a {
                            class: "icon-link",
                            href: REPO_URL,
                            target: "_blank",
                            rel: "noopener",
                            title: "GitHub repository. Opens in a new tab.",
                            "aria-label": "GitHub repository. Opens in a new tab.",
                            Icon { width: 15, height: 15, icon: FaGithub }
                        }
                        a {
                            class: if result.read().is_some() { "icon-link heartbtn heart-attention" } else { "icon-link heartbtn" },
                            href: SPONSOR_URL,
                            target: "_blank",
                            rel: "noopener",
                            title: "Support this project. Opens in a new tab.",
                            "aria-label": "Support this project. Opens in a new tab.",
                            Icon { width: 15, height: 15, icon: FaHeart }
                        }
                    }
                }
                p { class: "tagline",
                    "A no-std Rust crate that translates "
                    a { href: PG_RLS_URL, target: "_blank", rel: "noopener", "PostgreSQL RLS" }
                    " into an "
                    a { href: OPENFGA_URL, target: "_blank", rel: "noopener", "OpenFGA" }
                    " authorization model, in your browser."
                }
            }
            div { class: "layout",
                InputPane {
                    sql,
                    min_confidence,
                    parse_error: parse_error.read().clone(),
                    files: files.read().clone(),
                    active_example: active_example(),
                    on_pick_example: move |i: usize| {
                        sql.set(EXAMPLES[i].sql.to_string());
                        files.set(Vec::new());
                        active_example.set(Some(i));
                        run_translation(sql, min_confidence, result, parse_error);
                    },
                    on_set_confidence: move |level: ConfidenceLevel| {
                        min_confidence.set(level);
                        run_translation(sql, min_confidence, result, parse_error);
                    },
                    on_upload: move |fs: Vec<FileData>| {
                        active_example.set(None);
                        load_files(fs, false, sql, files, min_confidence, result, parse_error);
                    },
                    on_upload_folder: move |fs: Vec<FileData>| {
                        active_example.set(None);
                        load_files(fs, true, sql, files, min_confidence, result, parse_error);
                    },
                    on_edit: move |v: String| {
                        active_example.set(None);
                        sql.set(v);
                        run_translation(sql, min_confidence, result, parse_error);
                    },
                    on_drag_start: move |i: usize| drag_from.set(Some(i)),
                    on_drop: move |i: usize| {
                        if let Some(from) = drag_from.take() {
                            if from != i && from < files.read().len() {
                                let mut list = files.write();
                                let item = list.remove(from);
                                let at = i.min(list.len());
                                list.insert(at, item);
                            }
                        }
                        sql.set(concat_files(&files.read()));
                        run_translation(sql, min_confidence, result, parse_error);
                    },
                    on_remove: move |i: usize| {
                        files.write().remove(i);
                        sql.set(concat_files(&files.read()));
                        run_translation(sql, min_confidence, result, parse_error);
                    },
                }
                OutputPane {
                    result: result.read().clone(),
                    active_tab,
                    copied_tab,
                }
            }
        }
    }
}

#[component]
fn InputPane(
    sql: Signal<String>,
    min_confidence: Signal<ConfidenceLevel>,
    parse_error: Option<String>,
    files: Vec<(String, String)>,
    active_example: Option<usize>,
    on_pick_example: EventHandler<usize>,
    on_set_confidence: EventHandler<ConfidenceLevel>,
    on_upload: EventHandler<Vec<FileData>>,
    on_upload_folder: EventHandler<Vec<FileData>>,
    on_edit: EventHandler<String>,
    on_drag_start: EventHandler<usize>,
    on_drop: EventHandler<usize>,
    on_remove: EventHandler<usize>,
) -> Element {
    rsx! {
        section { class: "panel",
            div { class: "panel-header",
                h2 {
                    {postgres_icon()}
                    "Input"
                    span { class: "panel-sub", "PostgreSQL DDL & RLS" }
                }
                div { class: "actions",
                    label { class: "icon-link", title: "Upload one or more .sql files, sorted by filename and concatenated in that order", aria_label: "Upload .sql files",
                        Icon { width: 16, height: 16, icon: FaUpload }
                        input {
                            class: "file-input",
                            r#type: "file",
                            accept: ".sql",
                            multiple: true,
                            aria_label: "Upload one or more .sql files, ordered by filename",
                            onchange: move |evt| on_upload.call(evt.files()),
                        }
                    }
                    label { class: "icon-link", title: "Upload a folder of migrations, sorted by relative path and concatenated in that order", aria_label: "Upload a folder of migrations",
                        Icon { width: 16, height: 16, icon: FaFolderOpen }
                        input {
                            class: "file-input",
                            r#type: "file",
                            directory: true,
                            aria_label: "Upload a folder of .sql migrations, ordered by relative path",
                            onchange: move |evt| on_upload_folder.call(evt.files()),
                        }
                    }
                }
            }

            div { class: "pills",
                for (i, ex) in EXAMPLES.iter().enumerate() {
                    button {
                        class: if active_example == Some(i) { "pill active" } else { "pill" },
                        title: "{ex.description}",
                        aria_label: "Load the {ex.label} example schema",
                        "aria-pressed": (active_example == Some(i)).to_string(),
                        onclick: move |_| on_pick_example.call(i),
                        {example_icon(ex.icon)}
                        "{ex.label}"
                    }
                }
            }

            if !files.is_empty() {
                div {
                    span { class: "field-label", "Ordered input files (drag to reorder)" }
                    ul { class: "file-list",
                        for (i, (name, _)) in files.iter().enumerate() {
                            li {
                                key: "{name}-{i}",
                                draggable: true,
                                ondragstart: move |_| on_drag_start.call(i),
                                ondragover: move |e| e.prevent_default(),
                                ondrop: move |e| { e.prevent_default(); on_drop.call(i); },
                                Icon { width: 12, height: 12, icon: FaGripVertical, class: "drag-handle".to_string() }
                                span { class: "file-order", "{i + 1}." }
                                span { "{name}" }
                                button {
                                    class: "file-remove",
                                    title: "Remove this file from the input",
                                    aria_label: "Remove {name} from the input",
                                    onclick: move |_| on_remove.call(i),
                                    Icon { width: 12, height: 12, icon: FaXmark }
                                }
                            }
                        }
                    }
                }
            }

            CodeEditor {
                value: sql(),
                language: Language::Sql,
                theme: code_theme(),
                line_numbers: true,
                spellcheck: false,
                placeholder: "Paste PostgreSQL DDL and CREATE POLICY statements here".to_string(),
                aria_label: "SQL input".to_string(),
                class: "editor".to_string(),
                oninput: move |v| on_edit.call(v),
            }

            if let Some(err) = parse_error {
                div { class: "parse-error",
                    Icon { width: 14, height: 14, icon: FaTriangleExclamation }
                    span { "{err}" }
                }
            }

            div { class: "control-group",
                span { class: "field-label", "Minimum confidence" }
                div { class: "segmented", role: "group", aria_label: "Minimum confidence",
                    for level in [ConfidenceLevel::A, ConfidenceLevel::B, ConfidenceLevel::C, ConfidenceLevel::D] {
                        button {
                            class: format!("seg-option {}{}", level_class(level), if *min_confidence.read() == level { " active" } else { "" }),
                            title: "Only emit output for policies classified at confidence {level} or higher",
                            aria_label: "Set minimum confidence to {level}",
                            "aria-pressed": (*min_confidence.read() == level).to_string(),
                            onclick: move |_| on_set_confidence.call(level),
                            "{level}"
                        }
                    }
                }
                p { class: "field-help",
                    "Heuristic confidence of the policy translation. Level A is a fully recognised single pattern, such as ownership where owner_id = current_user. Level B is a composite of well-understood parts, such as owner OR a public flag. Level C is only partially recognised and mapped conservatively, such as an attribute check like status = 'active', which becomes a no_access relation to review by hand. Level D is unrecognised or unsupported."
                }
            }
        }
    }
}

#[component]
fn OutputPane(
    result: Option<Rendered>,
    active_tab: Signal<Tab>,
    copied_tab: Signal<Option<Tab>>,
) -> Element {
    let mut active_tab = active_tab;
    let mut copied_tab = copied_tab;

    let Some(translation) = result else {
        return rsx! {
            section { class: "panel",
                div { class: "panel-header",
                    h2 {
                        Icon { width: 16, height: 16, icon: FaShareNodes, class: "section-icon".to_string() }
                        "Output"
                        span { class: "panel-sub", "OpenFGA model" }
                    }
                }
                p { class: "output-empty", "Paste or upload PostgreSQL DDL and policies, or pick an example, to see the OpenFGA model here." }
            }
        };
    };

    let tab = *active_tab.read();
    let content = match tab {
        Tab::Dsl => translation.dsl.clone(),
        Tab::TupleSql => translation.tuple_sql.clone(),
        Tab::Json => translation.json.clone(),
    };
    let copied = *copied_tab.read() == Some(tab);
    let copy_text = content.clone();

    rsx! {
        section { class: "panel",
            div { class: "panel-header",
                h2 {
                    Icon { width: 16, height: 16, icon: FaShareNodes, class: "section-icon".to_string() }
                    "Output"
                    span { class: "panel-sub", "OpenFGA model" }
                }
                button {
                    class: if copied { "icon-btn copied" } else { "icon-btn" },
                    title: "Copy the current output to the clipboard",
                    "aria-label": "Copy the current output to the clipboard",
                    onclick: move |_| { copy_to_clipboard(copy_text.clone()); copied_tab.set(Some(tab)); },
                    if copied {
                        Icon { width: 14, height: 14, icon: FaCheck }
                    } else {
                        Icon { width: 14, height: 14, icon: FaCopy }
                    }
                }
            }
            div { class: "segmented", role: "tablist",
                for t in Tab::ALL {
                    button {
                        class: if t == tab { "seg-option active" } else { "seg-option" },
                        role: "tab",
                        title: "Show {t.describe()}",
                        aria_label: "Show {t.describe()}",
                        "aria-selected": (t == tab).to_string(),
                        onclick: move |_| { active_tab.set(t); copied_tab.set(None); },
                        {tab_icon(t)}
                        "{t.label()}"
                    }
                }
            }

            // Above the outputs, not behind a tab: a tab is easy never to open, which
            // is exactly how a model that disagrees with the database ships unnoticed.
            if !translation.diverging.is_empty() {
                div { class: "refusal-banner",
                    span { class: "refusal-title",
                        Icon { width: 14, height: 14, icon: FaTriangleExclamation, class: "section-icon".to_string() }
                        " The model below does not match the database for {translation.diverging.len()} clause(s)"
                    }
                    for note in translation.diverging.iter() {
                        div { class: "refusal-item",
                            span { class: "severity-badge {severity_class(note.severity())}", "{note.severity()}" }
                            span { class: "refusal-policy", "{note.subject()}" }
                            span { class: "refusal-message", "{note.message()}" }
                        }
                    }
                }
            }

            match tab {
                Tab::Dsl => rsx! { pre { class: "output-pre", "{content}" } },
                Tab::TupleSql => rsx! {
                    div { class: "output-body",
                        CodeEditor {
                            value: content.clone(),
                            language: Language::Sql,
                            theme: code_theme(),
                            line_numbers: true,
                            read_only: true,
                            class: "editor".to_string(),
                            aria_label: "Tuple SQL output".to_string(),
                            oninput: move |_| {},
                        }
                    }
                },
                Tab::Json => rsx! {
                    div { class: "output-body",
                        CodeEditor {
                            value: content.clone(),
                            language: Language::Json,
                            theme: code_theme(),
                            line_numbers: true,
                            read_only: true,
                            class: "editor".to_string(),
                            aria_label: "JSON authorization model".to_string(),
                            oninput: move |_| {},
                        }
                    }
                },
            }

            if !translation.confidence_summary.is_empty() {
                div {
                    span { class: "field-label",
                        Icon { width: 13, height: 13, icon: FaListCheck, class: "section-icon".to_string() }
                        " Policy confidence"
                    }
                    div { class: "confidence-summary",
                        for (name, level) in translation.confidence_summary.iter() {
                            span { class: "chip {level_class(*level)}",
                                span { class: "level-badge {level_class(*level)}", "{level}" }
                                "{name}"
                            }
                        }
                    }
                }
            }

            if !translation.notes.is_empty() {
                div { class: "note-panel",
                    span { class: "field-label",
                        Icon { width: 13, height: 13, icon: FaTriangleExclamation, class: "section-icon".to_string() }
                        " Review ({translation.notes.len()})"
                    }
                    for note in translation.notes.iter() {
                        div { class: "note-item {severity_class(note.severity())}",
                            span { class: "severity-badge {severity_class(note.severity())}", "{note.severity()}" }
                            div { class: "note-body",
                                div { class: "note-policy", "{note.subject()}" }
                                div { class: "note-message", "{note.message()}" }
                            }
                        }
                    }
                }
            }
        }
    }
}
