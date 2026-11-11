#[cfg(not(feature = "std"))]
use crate::no_std_prelude::*;
#[cfg(feature = "std")]
use std::path::Path;

use alloc::sync::Arc;

use crate::classifier::function_registry::{FunctionRegistry, RegistryLoadError};
use crate::classifier::patterns::{ClassifiedPolicy, ConfidenceLevel};
use crate::classifier::policy_classifier::classify_policies_with_effective_registry;
use crate::clock::{ClockContextError, ClockParameter};
use crate::generator::json_model::{json_model_from_plan, AuthorizationModel};
use crate::generator::model_generator::{
    build_filtered_schema_plan, render_dsl_from_plan, GeneratorSettings, SchemaPlan,
};
use crate::generator::policy_reads::policy_reads;
use crate::generator::relations::relation_shapes;
use crate::generator::row_naming::row_naming;
use crate::generator::tuple_generator::{
    generate_tuple_queries_from_plan, record_from_tuple_row, TupleQuery, TupleRow, TupleRowError,
    UnboundedColumns,
};
use crate::generator::well_known::{WellKnownTypes, SETTINGS_PARAMETER};
#[cfg(feature = "std")]
use crate::output::formatter::{write_output, WriteError};
use crate::output::report::build_report;
use crate::parser::sql_parser::{DatabaseLike, Deployment};
use crate::types::{
    ActionRelations, NoteSeverity, Record, RelationShapes, RowNaming, TranslationNote,
};
use crate::types::{ConditionParameterName, ConditionParameterNameError, PolicyReads};
use sql_values::{PgTimeZone, PgTimestampTz};

pub use crate::generator::model_generator::PlanningError;

/// Builder for a [`Translator`].
#[derive(Debug, Clone)]
pub struct TranslatorBuilder {
    deployment: Deployment,
    registry: FunctionRegistry,
    min_confidence: ConfidenceLevel,
    generator: GeneratorSettings,
}

impl TranslatorBuilder {
    /// A builder translating for `deployment`, the roles its requests run as and the
    /// session settings its policies may read.
    ///
    /// Every caller identity, value and set a policy reads comes from the deployment's
    /// settings, and a setting it does not declare is refused wherever a policy reads it.
    #[must_use]
    pub fn new(deployment: Deployment) -> Self {
        Self {
            deployment,
            registry: FunctionRegistry::new(),
            generator: GeneratorSettings::default(),
            min_confidence: ConfidenceLevel::B,
        }
    }

    /// Name the condition parameter a caller supplies for a guard against statement
    /// time, which every check context then has to use and every clock threshold
    /// parameter is named after. Defaults to `request_time`.
    ///
    /// # Errors
    ///
    /// Returns an error when `name` is not a usable `CEL` identifier, or when it is
    /// `settings`, the parameter single request values travel in.
    pub fn with_request_time_parameter(
        mut self,
        name: impl Into<String>,
    ) -> Result<Self, ConditionParameterNameError> {
        let name = name.into();
        if name == SETTINGS_PARAMETER {
            return Err(ConditionParameterNameError::Reserved { name });
        }
        self.generator.request_time_parameter = ConditionParameterName::try_from(name)?;
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

    /// Declare `SECURITY DEFINER` helpers a policy may compare a column with, named as a
    /// call spells them (`authz.projects_with`).
    ///
    /// A helper is otherwise refused, since its body reads rows the caller cannot. A
    /// declared one translates to the grants its body reads where `sql-traits` can answer
    /// what it returns, which takes a `STABLE` SQL helper returning `SETOF` one type, with a
    /// pinned `search_path`, owned by a declared role holding `SELECT` on what it reads and
    /// exempt from those tables' policies, whose body is a `UNION` of grant and parent
    /// reads. Every helper it calls has to be declared too.
    ///
    /// Declaring one asserts that every role a request runs as may execute it. A caller
    /// lacking `EXECUTE` gets an error from `PostgreSQL` where the model grants, and no
    /// such check is made here.
    #[must_use]
    pub fn with_declared_helpers<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.registry.declare_helpers(names);
        self
    }

    /// Declare the `lc_monetary` the schema's `money` literals were written in, such as
    /// `en_US.UTF-8`.
    ///
    /// `PostgreSQL` parses `'$10.00'::money` by that setting, so a clause casting to `money`
    /// is refused until it is declared. Every tuple query then carries it as
    /// [`TupleQuery::monetary_locale`] for its loader to set.
    #[must_use]
    pub fn with_monetary_locale(mut self, locale: impl Into<String>) -> Self {
        self.registry.declare_monetary_locale(locale);
        self
    }

    /// Set the output confidence threshold used by model/tuple/report generation.
    #[must_use]
    pub fn with_min_confidence(mut self, min_confidence: ConfidenceLevel) -> Self {
        self.min_confidence = min_confidence;
        self
    }

    /// Build the translator.
    pub fn build(self) -> Translator {
        Translator {
            deployment: self.deployment,
            registry: self.registry,
            min_confidence: self.min_confidence,
            generator: self.generator,
        }
    }
}

/// High-level classification and translation facade.
#[derive(Debug, Clone)]
pub struct Translator {
    deployment: Deployment,
    registry: FunctionRegistry,
    min_confidence: ConfidenceLevel,
    generator: GeneratorSettings,
}

impl Translator {
    /// Classify policies for the configured deployment.
    pub fn classify<DB: DatabaseLike>(&self, db: &DB) -> Vec<ClassifiedPolicy> {
        self.classify_with_effective_registry(db).0
    }

    /// Classify policies and return the effective registry after schema enrichment.
    pub fn classify_with_effective_registry<DB: DatabaseLike>(
        &self,
        db: &DB,
    ) -> (Vec<ClassifiedPolicy>, FunctionRegistry) {
        classify_policies_with_effective_registry(db, &self.registry, &self.deployment)
    }

    /// Plan a translation of `db`.
    ///
    /// Classification, planning, tuple queries, and relation shapes are each derived once.
    ///
    /// # Errors
    ///
    /// Returns [`PlanningError::Deployment`] when `db` does not declare a role the
    /// deployment names, and any other [`PlanningError`] planning raises.
    pub fn translate<DB: DatabaseLike>(&self, db: &DB) -> Result<Translation, PlanningError> {
        self.deployment.resolve(db)?;
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

    /// The deployment the translator reads every schema for.
    pub fn deployment(&self) -> &Deployment {
        &self.deployment
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
    policy_reads: Vec<PolicyReads>,
}

impl DerivedOutputs {
    fn build<DB: DatabaseLike>(
        plan: &SchemaPlan,
        policies: &[ClassifiedPolicy],
        bounds: &UnboundedColumns,
        db: &DB,
    ) -> Self {
        let generated = generate_tuple_queries_from_plan(plan, bounds, db);
        let relations = relation_shapes(plan, &generated.descriptions, db);
        Self {
            tuple_queries: generated.queries,
            relations,
            row_naming: row_naming(plan, db),
            policy_reads: policy_reads(policies, db),
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
    ///
    /// `registry` is the one the classification returned
    /// ([`Translator::classify_with_effective_registry`]), since it carries the
    /// deployment's settings and the semantics read from the schema, which planning reads
    /// again for every membership table a policy reads.
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
        let mut derived = DerivedOutputs::build(&plan, &policies, &bounds, db);
        if let Some(locale) = registry.monetary_locale() {
            for query in &mut derived.tuple_queries {
                query.monetary_locale = Some(locale.to_string());
            }
        }
        let derived = Arc::new(derived);
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
        &self.plan.action_relations
    }

    /// The tables each policy's clauses read, one entry per translated policy ordered by
    /// table and then name, for a consumer refusing a table it can no longer follow to
    /// refuse every policy reading it.
    ///
    /// Reports what the database reads, whatever the model enforces, and errs toward naming
    /// more. A clause the translation dropped or left unclassified counts, so does every
    /// function body the clauses reach, and a read the schema cannot name is listed in
    /// [`PolicyReads::unresolved`]. A policy whose table the catalog cannot place has no
    /// entry.
    #[must_use]
    pub fn policy_reads(&self) -> &[PolicyReads] {
        &self.derived.policy_reads
    }

    /// Every clock parameter the model's conditions read, ordered by name: the request
    /// clock itself, and each threshold `PostgreSQL` computes in the session `TimeZone`
    /// that CEL cannot, such as `now() - interval '1 day'`.
    #[must_use]
    pub fn clock_parameters(&self) -> &[ClockParameter] {
        &self.plan.clocks
    }

    /// The values of [`Translation::clock_parameters`] for one check, keyed by
    /// parameter, ready to merge into its context.
    ///
    /// Call it per check with the instant the request runs at and the `TimeZone` its
    /// session would run in, which for a deployment
    /// `sql_traits::ResolvedDeployment::time_zone` names for the acting role. A day or
    /// month window answers as `PostgreSQL` does only in that zone.
    ///
    /// ```
    /// use rls2fga::parser::sql_parser::{parse_schema, Deployment};
    /// use rls2fga::translator::TranslatorBuilder;
    /// use rls2fga::types::ConfidenceLevel;
    /// use sql_values::{InputContext, PgTimeZone, PgTimestampTz};
    ///
    /// let db = parse_schema(
    ///     "CREATE ROLE authenticator LOGIN;
    ///      CREATE ROLE web_user;
    ///      CREATE TABLE docs(id UUID PRIMARY KEY, expires_at TIMESTAMPTZ);
    ///      ALTER TABLE docs ENABLE ROW LEVEL SECURITY;
    ///      CREATE POLICY docs_sel ON docs FOR SELECT
    ///          USING (expires_at > now() - interval '1 day');",
    /// )
    /// .unwrap();
    /// let deployment = Deployment::new("authenticator", ["web_user"], []).unwrap();
    /// let translation = TranslatorBuilder::new(deployment)
    ///     .with_min_confidence(ConfidenceLevel::B)
    ///     .build()
    ///     .translate(&db)
    ///     .unwrap();
    /// let at = PgTimestampTz::parse("2026-03-29 12:00+02", InputContext::new()).unwrap();
    /// let context = translation
    ///     .clock_context(at, &PgTimeZone::parse("Europe/Rome").unwrap())
    ///     .unwrap();
    /// // Twenty three hours back, across the spring change.
    /// assert_eq!(context["request_time_minus_1_day"], "2026-03-28T11:00:00Z");
    /// ```
    ///
    /// # Errors
    ///
    /// The first parameter whose threshold `PostgreSQL` would refuse to compute, or that
    /// lies outside the years a CEL timestamp holds.
    pub fn clock_context(
        &self,
        request_time: PgTimestampTz,
        zone: &PgTimeZone,
    ) -> Result<serde_json::Map<String, serde_json::Value>, ClockContextError> {
        self.plan
            .clocks
            .iter()
            .map(|clock| {
                clock
                    .value(request_time, zone)
                    .map(|value| (clock.name().to_string(), serde_json::Value::String(value)))
                    .map_err(|source| ClockContextError {
                        parameter: clock.name().clone(),
                        source,
                    })
            })
            .collect()
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
    /// [`Translation::action_relations`], [`Translation::policy_reads`]) without cloning
    /// before [`Translation::outputs`] consumes it.
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
                "CREATE POLICY owner_{index} ON docs FOR SELECT \
                 USING (owner_{index} = current_setting('app.user_id'));"
            )
            .expect("policy writes");
        }
        schema
    }

    #[test]
    fn column_bound_discovery_runs_once_per_output_derivation() {
        for source_count in [1, 8, 32] {
            let schema = format!(
                "{}{}",
                crate::test_support::ROLES_SQL,
                schema_with_sources(source_count)
            );
            let db = parse_schema(&schema).expect("schema parses");
            reset_unbounded_columns_resolutions();

            let translation = TranslatorBuilder::new(crate::test_support::caller_deployment())
                .build()
                .translate(&db)
                .expect("translation plans");
            assert_eq!(
                translation
                    .clone()
                    .outputs_accepting_gaps()
                    .tuple_queries()
                    .len(),
                // One per owner column, beside the acting kind's fact and each row's link
                // to it.
                source_count + 2
            );
            assert_eq!(unbounded_columns_resolutions(), 1);
        }
    }
}
