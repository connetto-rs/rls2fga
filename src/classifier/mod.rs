/// Maps SQL function names to their known semantics (role-threshold, current-user accessor, etc.).
pub mod function_registry;
// `exclusion` documents itself in the file.
pub(crate) mod exclusion;
// `expansion` documents itself in the file.
pub mod expansion;
// `oracle` documents itself in the file. A second doc here would merge with it and
// resolve its intra-doc links in this file's scope.
pub mod oracle;
/// Pattern enums, confidence levels, and classified expression/policy types.
pub mod patterns;
// `readability` documents itself in the file.
/// Top-level policy classification: walks each policy's USING/WITH CHECK expression tree.
pub mod policy_classifier;
pub(crate) mod readability;
/// Individual pattern recognizers (P1 to P6) that probe a single AST expression node.
pub mod recognizers;
// `role_keywords` documents itself in the file.
pub(crate) mod role_keywords;
