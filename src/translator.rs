#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
#[cfg(feature = "std")]
use std::path::Path;

use alloc::sync::Arc;

use crate::classifier::function_registry::{FunctionRegistry, RegistryLoadError, SessionAttribute};
use crate::classifier::patterns::{ClassifiedPolicy, ConfidenceLevel};
use crate::classifier::policy_classifier::classify_policies_with_effective_registry_and_settings;
use crate::generator::action_relations::action_relations;
use crate::generator::caller_roles::CallerRoles;
use crate::generator::json_model::{json_model_from_plan, AuthorizationModel};
use crate::generator::model_generator::{
    build_filtered_schema_plan, render_dsl_from_plan, GeneratorSettings, SchemaPlan,
};
use crate::generator::relations::relation_shapes;
use crate::generator::row_naming::row_naming;
use crate::generator::tuple_generator::{
    generate_tuple_queries_from_plan, record_from_tuple_row, TupleQuery, TupleRow, TupleRowError,
    UnboundedColumns,
};
use crate::generator::unrestricted::unrestricted_tables;
use crate::generator::well_known::WellKnownTypes;
#[cfg(feature = "std")]
use crate::output::formatter::{write_output, WriteError};
use crate::output::report::build_report;
use crate::parser::function_analyzer::AccessorInferenceSettings;
use crate::parser::sql_parser::DatabaseLike;
use crate::types::UnrestrictedTable;
use crate::types::{
    ActionRelations, NoteSeverity, Record, RelationShapes, RowNaming, TranslationNote,
};
use crate::types::{ConditionParameterName, ConditionParameterNameError};

pub use crate::generator::model_generator::PlanningError;

/// Builder for a [`Translator`].
#[derive(Debug, Clone)]
pub struct TranslatorBuilder {
    registry: FunctionRegistry,
    settings: AccessorInferenceSettings,
    min_confidence: ConfidenceLevel,
    generator: GeneratorSettings,
}

impl TranslatorBuilder {
    /// Create a new translator builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Name the condition parameter a caller supplies for a guard against statement
    /// time, which every check context then has to use. Defaults to `request_time`.
    ///
    /// # Errors
    ///
    /// Returns an error when `name` is not a usable `CEL` identifier.
    pub fn with_request_time_parameter(
        mut self,
        name: impl Into<String>,
    ) -> Result<Self, ConditionParameterNameError> {
        self.generator.request_time_parameter = ConditionParameterName::try_from(name.into())?;
        Ok(self)
    }

    /// Replace the type names the generator reserves for its own vocabulary.
    #[must_use]
    pub fn with_well_known_types(mut self, names: WellKnownTypes) -> Self {
        self.generator.well_known = names;
        self
    }

    /// Replace the base function registry.
    #[must_use]
    pub fn with_registry(mut self, registry: FunctionRegistry) -> Self {
        self.registry = registry;
        self
    }

    /// Merge function semantics from JSON into the base registry.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryLoadError`] when the JSON is not a registry payload.
    pub fn with_registry_json(mut self, json: &str) -> Result<Self, RegistryLoadError> {
        self.registry.load_from_json(json)?;
        Ok(self)
    }

    /// Replace the `current_setting` keys this builder names as holding the caller's
    /// identity. A key the base registry already names is kept.
    ///
    /// A call reading one names the caller wherever it appears: inline in a policy, or
    /// as the whole body of a function the policy calls.
    #[must_use]
    pub fn with_current_user_setting_keys<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.settings = AccessorInferenceSettings::from_keys(keys);
        self
    }

    /// Declare the request-scoped values a policy may read, of any kind.
    ///
    /// A source is a `current_setting` key, optionally with a field path taken out of
    /// the value at that key. Declaring one is a contract with the caller: the condition
    /// parameter it names has to be supplied in every check context.
    #[must_use]
    pub fn with_session_attributes<I>(mut self, attributes: I) -> Self
    where
        I: IntoIterator<Item = SessionAttribute>,
    {
        self.settings = AccessorInferenceSettings::from_attributes(
            self.settings
                .session_attributes()
                .iter()
                .cloned()
                .chain(attributes),
        );
        self
    }

    /// Set the output confidence threshold used by model/tuple/report generation.
    #[must_use]
    pub fn with_min_confidence(mut self, min_confidence: ConfidenceLevel) -> Self {
        self.min_confidence = min_confidence;
        self
    }

    /// Declare the database roles every caller's transaction runs as.
    ///
    /// Each `TO` clause is then settled against them through the role memberships the
    /// schema declares. A policy every caller role reaches reads as unscoped, one some
    /// reach is scoped to those caller roles, and one none reaches is left out.
    #[must_use]
    pub fn with_caller_roles(mut self, roles: CallerRoles) -> Self {
        self.generator.caller_roles = Some(roles);
        self
    }

    /// Build the translator.
    pub fn build(self) -> Translator {
        Translator {
            registry: self.registry,
            settings: self.settings,
            min_confidence: self.min_confidence,
            generator: self.generator,
        }
    }
}

impl Default for TranslatorBuilder {
    fn default() -> Self {
        Self {
            registry: FunctionRegistry::new(),
            settings: AccessorInferenceSettings::default(),
            generator: GeneratorSettings::default(),
            min_confidence: ConfidenceLevel::B,
        }
    }
}

/// High-level classification and translation facade.
#[derive(Debug, Clone)]
pub struct Translator {
    registry: FunctionRegistry,
    settings: AccessorInferenceSettings,
    min_confidence: ConfidenceLevel,
    generator: GeneratorSettings,
}

impl Translator {
    /// Classify policies using the configured settings.
    pub fn classify<DB: DatabaseLike>(&self, db: &DB) -> Vec<ClassifiedPolicy> {
        self.classify_with_effective_registry(db).0
    }

    /// Classify policies and return the effective registry after schema enrichment.
    pub fn classify_with_effective_registry<DB: DatabaseLike>(
        &self,
        db: &DB,
    ) -> (Vec<ClassifiedPolicy>, FunctionRegistry) {
        classify_policies_with_effective_registry_and_settings(db, &self.registry, &self.settings)
    }

    /// Plan a translation of `db`.
    ///
    /// Classification, planning, tuple queries, and relation shapes are each derived once.
    pub fn translate<DB: DatabaseLike>(&self, db: &DB) -> Result<Translation, PlanningError> {
        let (classified, effective_registry) = self.classify_with_effective_registry(db);
        Translation::plan(
            classified,
            db,
            &effective_registry,
            self.min_confidence,
            &self.generator,
        )
    }

    /// Read-only access to the configured base registry.
    pub fn registry(&self) -> &FunctionRegistry {
        &self.registry
    }

    /// Read-only access to accessor inference settings.
    pub fn settings(&self) -> &AccessorInferenceSettings {
        &self.settings
    }

    /// Configured minimum confidence for output generation.
    pub fn min_confidence(&self) -> ConfidenceLevel {
        self.min_confidence
    }
}

#[derive(Debug)]
struct DerivedOutputs {
    tuple_queries: Vec<TupleQuery>,
    relations: Vec<RelationShapes>,
    row_naming: Vec<RowNaming>,
    action_relations: Vec<ActionRelations>,
    unrestricted_tables: Vec<UnrestrictedTable>,
}

impl DerivedOutputs {
    fn build<DB: DatabaseLike>(plan: &SchemaPlan, bounds: &UnboundedColumns, db: &DB) -> Self {
        let generated = generate_tuple_queries_from_plan(plan, bounds, db);
        let relations = relation_shapes(plan, &generated.descriptions, db);
        Self {
            tuple_queries: generated.queries,
            relations,
            row_naming: row_naming(plan, db),
            action_relations: action_relations(plan, db),
            unrestricted_tables: unrestricted_tables(db),
        }
    }
}

/// A planned translation of one schema.
#[derive(Debug, Clone)]
pub struct Translation {
    plan: SchemaPlan,
    derived: Arc<DerivedOutputs>,
    policies: Vec<ClassifiedPolicy>,
    min_confidence: ConfidenceLevel,
}

impl Translation {
    /// Plan a translation from policies already classified, which is how an oracle's
    /// answers reach the generators.
    pub fn plan<DB: DatabaseLike>(
        policies: Vec<ClassifiedPolicy>,
        db: &DB,
        registry: &FunctionRegistry,
        min_confidence: ConfidenceLevel,
        settings: &GeneratorSettings,
    ) -> Result<Self, PlanningError> {
        let bounds = UnboundedColumns::resolve(db);
        let plan =
            build_filtered_schema_plan(&policies, db, registry, min_confidence, settings, &bounds)?;
        let derived = Arc::new(DerivedOutputs::build(&plan, &bounds, db));
        Ok(Self {
            plan,
            derived,
            policies,
            min_confidence,
        })
    }

    /// Everything the translation has to say about itself.
    #[must_use]
    pub fn notes(&self) -> &[TranslationNote] {
        &self.plan.notes
    }

    /// The notes about expressions nobody classified.
    pub fn unhandled(&self) -> impl Iterator<Item = &TranslationNote> {
        self.notes()
            .iter()
            .filter(|note| note.severity() == NoteSeverity::Unhandled)
    }

    /// Every relation the emitted model declares, with the shapes whose records fill
    /// it and whether one row decides them.
    #[must_use]
    pub fn relations(&self) -> &[RelationShapes] {
        &self.derived.relations
    }

    /// How rows of each table the model names are named as objects, which is what a
    /// consumer asking the authorization service about one changed row has to spell.
    ///
    /// Beside [`Translation::relations`] and read with it: the relations say what a type
    /// grants, this says which table's rows that type is. A partition is named after its
    /// root, so a row of one is asked about under the root's type.
    #[must_use]
    pub fn row_naming(&self) -> &[RowNaming] {
        &self.derived.row_naming
    }

    /// Which relations answer each action the model covers, and which version of the
    /// row each of them judges.
    ///
    /// Read with [`Translation::relations`] and [`Translation::row_naming`]: those say
    /// what a type grants and how its rows are named, this says what to ask about one.
    /// Which relations exist depends on how a policy spelled its clauses, so deriving
    /// this from the emitted model is the case analysis it exists to remove.
    #[must_use]
    pub fn action_relations(&self) -> &[ActionRelations] {
        &self.derived.action_relations
    }

    /// Every table the database restricts nothing on: row-level security is off on it, and
    /// off on every table it is a partition or an `INHERITS` child of, since a read through
    /// one of those applies that table's policies to these rows.
    ///
    /// Read beside [`Translation::action_relations`], and read positively: a table here
    /// shows every row to everybody, so a question about one of its rows is granted with
    /// nothing asked. A table absent from both this and the action report is one nothing
    /// covered, which says nothing about what the database allows.
    ///
    /// Reported by table because the emitted model defines no type for such a table.
    #[must_use]
    pub fn unrestricted_tables(&self) -> &[UnrestrictedTable] {
        &self.derived.unrestricted_tables
    }

    /// The outputs, refused while any note's severity [`diverges_from_database`](NoteSeverity::diverges_from_database).
    ///
    /// # Errors
    ///
    /// Returns every diverging note in [`DivergentTranslation`].
    pub fn outputs(self) -> Result<Outputs, DivergentTranslation> {
        if self
            .notes()
            .iter()
            .any(|note| note.severity().diverges_from_database())
        {
            let mut notes = self.plan.notes;
            notes.retain(|note| note.severity().diverges_from_database());
            Err(DivergentTranslation { notes })
        } else {
            Ok(Outputs(self))
        }
    }

    /// Accepts gaps that may widen access (`MembershipTableGuarded`, `AttributeNeedsRuntimeEnforcement`) or narrow it (unhandled expressions, dropped clauses, `NullableBooleanFlagNarrowed`, `InheritanceParentReadsOwnRowsOnly`).
    #[must_use]
    pub fn outputs_accepting_gaps(self) -> Outputs {
        Outputs(self)
    }
}

/// Translation outputs checked by [`Translation::outputs`] or explicitly accepted through [`Translation::outputs_accepting_gaps`].
#[derive(Debug, Clone)]
pub struct Outputs(Translation);

impl Outputs {
    /// The translation these outputs were rendered from, for the analysis
    /// surface ([`Translation::relations`], [`Translation::row_naming`],
    /// [`Translation::action_relations`], [`Translation::unrestricted_tables`])
    /// without cloning before [`Translation::outputs`] consumes it.
    #[must_use]
    pub fn translation(&self) -> &Translation {
        &self.0
    }

    /// The `OpenFGA` DSL model.
    #[must_use]
    pub fn model(&self) -> String {
        render_dsl_from_plan(&self.0.plan)
    }

    /// The `OpenFGA` JSON authorization model.
    #[must_use]
    pub fn json_model(&self) -> AuthorizationModel {
        json_model_from_plan(&self.0.plan)
    }

    /// The number of types the written model declares.
    ///
    /// Compare it with the server's `maxTypesPerAuthorizationModel` setting, which
    /// `openfga/openfga` `pkg/server/config/config.go` defaults to 100. A count above it
    /// is the server's refusal under its own configuration, not a translation error.
    #[must_use]
    pub fn type_count(&self) -> usize {
        self.0.plan.types.len()
    }

    /// The size `OpenFGA` compares with its `maxAuthorizationModelSizeInBytes` setting,
    /// as [`crate::client::model_size_in_bytes`] measures it.
    ///
    /// # Errors
    ///
    /// [`crate::client::WriteModelError::Untranslatable`] when the model does not
    /// translate into the client's types.
    #[cfg(feature = "client")]
    pub fn model_size_in_bytes(&self) -> Result<usize, crate::client::WriteModelError> {
        crate::client::model_size_in_bytes(&self.json_model())
    }

    /// SQL that populates the relationship tuples.
    #[must_use]
    pub fn tuple_queries(&self) -> &[TupleQuery] {
        &self.0.derived.tuple_queries
    }

    /// Read one row a [`Outputs::tuple_queries`] query returned back as the record
    /// it spells.
    ///
    /// The relation is looked up rather than taken, so a row naming something the
    /// model does not define is refused instead of loaded.
    ///
    /// # Errors
    ///
    /// Returns [`TupleRowError`] for a row this model has no such fact in.
    pub fn record_from_tuple_row(&self, row: TupleRow<'_>) -> Result<Record, TupleRowError> {
        record_from_tuple_row(&self.0.plan, row)
    }

    /// Everything the translation has to say about itself.
    #[must_use]
    pub fn notes(&self) -> &[TranslationNote] {
        self.0.notes()
    }

    /// Per-policy confidence levels.
    #[must_use]
    pub fn confidence_summary(&self) -> &[(String, ConfidenceLevel)] {
        &self.0.plan.confidence_summary
    }

    /// The markdown report, which is the only place a clause dropped by the threshold
    /// is visible.
    #[must_use]
    pub fn report(&self) -> String {
        build_report(self.notes(), &self.0.policies, self.0.min_confidence)
    }

    /// Write the model, the tuple SQL and the report into `output_dir`.
    ///
    /// # Errors
    ///
    /// Returns [`WriteError`] when the name is unusable as a filename or a write fails.
    #[cfg(feature = "std")]
    pub fn write(&self, output_dir: &Path, name: &str) -> Result<(), WriteError> {
        write_output(
            output_dir,
            name,
            &self.model(),
            self.tuple_queries(),
            &self.report(),
        )
    }
}

/// Every note that makes [`Translation::outputs`] refuse a model that diverges from the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergentTranslation {
    notes: Vec<TranslationNote>,
}

impl DivergentTranslation {
    /// Every note whose severity [`diverges_from_database`](NoteSeverity::diverges_from_database).
    #[must_use]
    pub fn notes(&self) -> &[TranslationNote] {
        &self.notes
    }
}

impl core::fmt::Display for DivergentTranslation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} note(s) disclose a model that diverges from the database",
            self.notes.len()
        )?;
        for note in &self.notes {
            write!(f, "\n  {}: {note}", note.subject())?;
        }
        Ok(())
    }
}

impl core::error::Error for DivergentTranslation {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use core::fmt::Write;

    use crate::generator::tuple_generator::{
        reset_unbounded_columns_resolutions, unbounded_columns_resolutions,
    };
    use crate::parser::sql_parser::parse_schema;

    fn schema_with_sources(source_count: usize) -> String {
        let mut schema = String::from("CREATE TABLE docs (\n    id UUID PRIMARY KEY");
        for index in 0..source_count {
            write!(schema, ",\n    owner_{index} TEXT").expect("column writes");
        }
        schema.push_str("\n);\nALTER TABLE docs ENABLE ROW LEVEL SECURITY;\n");
        for index in 0..source_count {
            writeln!(
                schema,
                "CREATE POLICY owner_{index} ON docs FOR SELECT USING (owner_{index} = current_user);"
            )
            .expect("policy writes");
        }
        schema
    }

    #[test]
    fn column_bound_discovery_runs_once_per_output_derivation() {
        for source_count in [1, 8, 32] {
            let db = parse_schema(&schema_with_sources(source_count)).expect("schema parses");
            reset_unbounded_columns_resolutions();

            let translation = TranslatorBuilder::new()
                .build()
                .translate(&db)
                .expect("translation plans");
            assert_eq!(
                translation
                    .clone()
                    .outputs_accepting_gaps()
                    .tuple_queries()
                    .len(),
                source_count
            );
            assert_eq!(unbounded_columns_resolutions(), 1);
        }
    }
}
