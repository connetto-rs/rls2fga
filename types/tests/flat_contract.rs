use rls2fga_types::{
    records_from_row, ActionAnswer, ActionJudgement, ActionRelations, ActionStatement,
    AttributeLiteral, AttributeOperator, AttributePredicate, AttributeTest, BoundQuery,
    BoundQueryError, ColumnKind, ColumnName, ColumnRead, ConditionParameterName,
    ConditionParameterNameError, ConfidenceLevel, ContextRendering, ContextWitness, Guard,
    NoteSeverity, ObjectKey, Record, RecordContext, RecordContextEntry, RecordContextValue,
    RecordDerivation, RecordDescription, RecordError, RecordTemplate, RelationName,
    RelationNameError, RelationShapes, ReplayScope, RequestComparison, RolePrivilege, RowCell,
    RowDecision, RowList, RowNaming, RowValues, RowVersion, SubjectKey, TableId, TableRef,
    TranslationNote, TypeName, TypeNameError, UnrestrictedTable, ValueSource,
};

struct EmptyRow;

impl RowValues for EmptyRow {
    fn cell(&self, _column: &str, _kind: ColumnKind) -> RowCell<'_> {
        RowCell::Absent
    }

    fn list(&self, _column: &str, _kind: ColumnKind) -> RowList<'_> {
        RowList::Absent
    }

    fn json_text(&self, _column: &str, _path: &[String]) -> RowCell<'_> {
        RowCell::Absent
    }
}

fn assert_type<T>() {}

#[test]
fn every_contract_is_flat() {
    assert_type::<ActionAnswer>();
    assert_type::<ActionJudgement>();
    assert_type::<ActionRelations>();
    assert_type::<ActionStatement>();
    assert_type::<AttributeLiteral>();
    assert_type::<AttributeOperator>();
    assert_type::<AttributePredicate>();
    assert_type::<AttributeTest>();
    assert_type::<BoundQuery>();
    assert_type::<BoundQueryError>();
    assert_type::<ColumnKind>();
    assert_type::<ColumnName>();
    assert_type::<ColumnRead>();
    assert_type::<ConditionParameterName>();
    assert_type::<ConditionParameterNameError>();
    assert_type::<ConfidenceLevel>();
    assert_type::<ContextRendering>();
    assert_type::<ContextWitness>();
    assert_type::<Guard>();
    assert_type::<NoteSeverity>();
    assert_type::<ObjectKey>();
    assert_type::<Record>();
    assert_type::<RecordContext>();
    assert_type::<RecordContextEntry>();
    assert_type::<RecordContextValue>();
    assert_type::<RecordDerivation>();
    assert_type::<RecordDescription>();
    assert_type::<RecordError>();
    assert_type::<RecordTemplate>();
    assert_type::<RelationName>();
    assert_type::<RelationNameError>();
    assert_type::<RelationShapes>();
    assert_type::<ReplayScope>();
    assert_type::<RequestComparison>();
    assert_type::<RolePrivilege>();
    assert_type::<RowCell<'static>>();
    assert_type::<RowDecision>();
    assert_type::<RowList<'static>>();
    assert_type::<RowNaming>();
    assert_type::<RowVersion>();
    assert_type::<SubjectKey>();
    assert_type::<TableId>();
    assert_type::<TableRef>();
    assert_type::<TranslationNote>();
    assert_type::<TypeName>();
    assert_type::<TypeNameError>();
    assert_type::<UnrestrictedTable>();
    assert_type::<ValueSource>();
    let _ = records_from_row::<EmptyRow>;
}
