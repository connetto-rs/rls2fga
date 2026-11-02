//! Consumer invariants for the `pg_dump` round-trip model comparator.

use serde_json::{json, Map, Value};

use crate::support::model_equivalence;

use model_equivalence::{equivalent, TupleRows};

/// The `(object, relation, subject)` triples the tuple queries execute.
fn executed_rows(pairs: &[(&str, &str, &str)]) -> TupleRows {
    pairs
        .iter()
        .map(|&(object, relation, subject)| {
            (object.to_owned(), relation.to_owned(), subject.to_owned())
        })
        .collect()
}

/// One directly related user type.
fn subject_type(name: &str) -> Value {
    json!({ "type": name })
}

/// A directly related user type that must satisfy one named condition.
fn subject_type_with_condition(name: &str, condition: &str) -> Value {
    json!({ "type": name, "condition": condition })
}

/// A directly related user type open to the public wildcard.
fn public_wildcard(name: &str) -> Value {
    json!({ "type": name, "wildcard": {} })
}

/// One relation metadata entry, listing the types its tuples carry.
fn user_types(types: &[Value]) -> Value {
    json!({ "directly_related_user_types": types })
}

/// The `this` rewrite, whose tuples are assigned directly.
fn this_relation() -> Value {
    json!({ "this": {} })
}

/// The `computedUserset` rewrite, reading one relation of the same type.
fn computed_relation(relation: &str) -> Value {
    json!({ "computedUserset": { "relation": relation } })
}

/// The `tupleToUserset` rewrite, reading one relation of the row's target type.
fn tuple_to_userset(tupleset: &str, computed: &str) -> Value {
    json!({
        "tupleToUserset": {
            "tupleset": { "relation": tupleset },
            "computedUserset": { "relation": computed }
        }
    })
}

/// The `union` rewrite over its children, in declaration order.
fn union_children(children: &[Value]) -> Value {
    json!({ "union": { "child": children } })
}

/// The `intersection` rewrite over its children, in declaration order.
fn intersection_children(children: &[Value]) -> Value {
    json!({ "intersection": { "child": children } })
}

/// The `difference` rewrite, `base` minus `subtract`.
fn difference_relation(base: &Value, subtract: &Value) -> Value {
    json!({ "difference": { "base": base, "subtract": subtract } })
}

/// One type definition with its relation rewrites and their metadata.
fn type_definition(name: &str, relations: &[(&str, Value)], metadata: &[(&str, Value)]) -> Value {
    let mut definition = Map::new();
    definition.insert("type".to_owned(), Value::String(name.to_owned()));
    let mut rewrites = Map::new();
    for (relation, rewrite) in relations {
        rewrites.insert((*relation).to_owned(), rewrite.clone());
    }
    if !rewrites.is_empty() {
        definition.insert("relations".to_owned(), Value::Object(rewrites));
    }
    let mut metadata_map = Map::new();
    for (relation, entry) in metadata {
        metadata_map.insert((*relation).to_owned(), entry.clone());
    }
    if !metadata_map.is_empty() {
        definition.insert("metadata".to_owned(), json!({ "relations": metadata_map }));
    }
    Value::Object(definition)
}

/// The whole model, without conditions.
fn model(types: &[Value]) -> Value {
    json!({ "schema_version": "1.1", "type_definitions": types })
}

/// The whole model carrying its condition map.
fn model_with_conditions(types: &[Value], conditions: &Value) -> Value {
    json!({
        "schema_version": "1.1",
        "type_definitions": types,
        "conditions": conditions
    })
}

/// The temporal condition one membership source rides on.
fn clock_condition() -> Value {
    json!({
        "name": "clock",
        "expression": "ctx.time > tuple.start",
        "parameters": { "time": { "type_name": "TYPE_NAME_TIMESTAMP" } }
    })
}

/// The comparator must accept the two sides of one schema.
fn assert_models_agree(left: &Value, left_rows: &TupleRows, right: &Value, right_rows: &TupleRows) {
    assert!(
        equivalent(left, left_rows, right, right_rows),
        "the models share every declaration up to a one-to-one rename of generated \
         source relations. left {left}, rows {left_rows:?}, right {right}, rows \
         {right_rows:?}"
    );
}

/// The comparator must see every difference beyond a source rename.
fn assert_models_diverge(
    left: &Value,
    left_rows: &TupleRows,
    right: &Value,
    right_rows: &TupleRows,
) {
    assert!(
        !equivalent(left, left_rows, right, right_rows),
        "the models differ where the round-trip comparator must see the difference. \
         left {left}, rows {left_rows:?}, right {right}, rows {right_rows:?}"
    );
}

#[test]
fn a_renamed_source_identity_with_its_rows_and_userset_subject_still_agrees() {
    let conditions = json!({ "clock": clock_condition() });

    let left = model_with_conditions(
        &[
            json!({ "type": "user" }),
            type_definition(
                "team",
                &[("member", this_relation())],
                &[("member", user_types(&[subject_type("user")]))],
            ),
            type_definition(
                "docs",
                &[("member_of", this_relation())],
                &[(
                    "member_of",
                    user_types(&[subject_type_with_condition("team", "clock")]),
                )],
            ),
        ],
        &conditions,
    );

    let right = model_with_conditions(
        &[
            json!({ "type": "user" }),
            type_definition(
                "team",
                &[("admission", this_relation())],
                &[("admission", user_types(&[subject_type("user")]))],
            ),
            type_definition(
                "docs",
                &[("access_row", this_relation())],
                &[(
                    "access_row",
                    user_types(&[subject_type_with_condition("team", "clock")]),
                )],
            ),
        ],
        &conditions,
    );

    assert_models_agree(
        &left,
        &executed_rows(&[
            ("docs:d1", "member_of", "team:t1#member"),
            ("team:t1", "member", "user:alice"),
        ]),
        &right,
        &executed_rows(&[
            ("docs:d1", "access_row", "team:t1#admission"),
            ("team:t1", "admission", "user:alice"),
        ]),
    );
}

#[test]
fn the_same_relation_name_on_two_types_renames_independently() {
    let reader_side = |name: &str| -> Value {
        type_definition(
            name,
            &[("reader", this_relation())],
            &[("reader", user_types(&[subject_type("user")]))],
        )
    };

    let left = model(&[
        json!({ "type": "user" }),
        reader_side("docs"),
        reader_side("notes"),
    ]);

    let right = model(&[
        json!({ "type": "user" }),
        type_definition(
            "docs",
            &[("reading", this_relation())],
            &[("reading", user_types(&[subject_type("user")]))],
        ),
        reader_side("notes"),
    ]);

    assert_models_agree(
        &left,
        &executed_rows(&[
            ("docs:d1", "reader", "user:u1"),
            ("notes:n1", "reader", "user:u2"),
        ]),
        &right,
        &executed_rows(&[
            ("docs:d1", "reading", "user:u1"),
            ("notes:n1", "reader", "user:u2"),
        ]),
    );
}

#[test]
fn ambiguous_sources_pair_by_their_rows_not_by_name_order() {
    let docs = |first: &str, second: &str| -> Value {
        type_definition(
            "docs",
            &[(first, this_relation()), (second, this_relation())],
            &[
                (first, user_types(&[subject_type("user")])),
                (second, user_types(&[subject_type("user")])),
            ],
        )
    };

    let left = model(&[json!({ "type": "user" }), docs("src_a", "src_b")]);
    let right = model(&[json!({ "type": "user" }), docs("src_x", "src_y")]);
    let rows = executed_rows(&[
        ("docs:d1", "src_a", "user:u1"),
        ("docs:d2", "src_b", "user:u2"),
    ]);

    // Names sort in the order a name-driven pairing would pick, and the rows break the tie
    assert_models_agree(
        &left,
        &rows,
        &right,
        &executed_rows(&[
            ("docs:d1", "src_y", "user:u1"),
            ("docs:d2", "src_x", "user:u2"),
        ]),
    );

    // No pairing of the two sources reproduces a row set with both rows under one.
    assert_models_diverge(
        &left,
        &rows,
        &right,
        &executed_rows(&[
            ("docs:d1", "src_x", "user:u1"),
            ("docs:d2", "src_x", "user:u2"),
        ]),
    );
}

#[test]
fn a_graph_edge_forces_the_pairing_over_name_order() {
    let docs = |referenced: &str, first: &str, second: &str| -> Value {
        type_definition(
            "docs",
            &[
                ("can_read", computed_relation(referenced)),
                (first, this_relation()),
                (second, this_relation()),
            ],
            &[
                (first, user_types(&[subject_type("user")])),
                (second, user_types(&[subject_type("user")])),
            ],
        )
    };

    // The edge forces `src_b` against `src_x`, against the name order.
    let left = model(&[json!({ "type": "user" }), docs("src_b", "src_a", "src_b")]);
    let right = model(&[json!({ "type": "user" }), docs("src_x", "src_x", "src_y")]);

    assert_models_agree(
        &left,
        &executed_rows(&[
            ("docs:d1", "src_a", "user:u1"),
            ("docs:d2", "src_b", "user:u2"),
        ]),
        &right,
        &executed_rows(&[
            ("docs:d1", "src_y", "user:u1"),
            ("docs:d2", "src_x", "user:u2"),
        ]),
    );
}

#[test]
fn merged_sources_are_not_one_model() {
    let left = model(&[
        json!({ "type": "user" }),
        type_definition(
            "docs",
            &[("grant_a", this_relation()), ("grant_b", this_relation())],
            &[
                ("grant_a", user_types(&[subject_type("user")])),
                ("grant_b", user_types(&[subject_type("user")])),
            ],
        ),
    ]);

    let right = model(&[
        json!({ "type": "user" }),
        type_definition(
            "docs",
            &[("grant", this_relation())],
            &[("grant", user_types(&[subject_type("user")]))],
        ),
    ]);

    assert_models_diverge(
        &left,
        &executed_rows(&[
            ("docs:d1", "grant_a", "user:u1"),
            ("docs:d2", "grant_b", "user:u2"),
        ]),
        &right,
        &executed_rows(&[
            ("docs:d1", "grant", "user:u1"),
            ("docs:d2", "grant", "user:u2"),
        ]),
    );
}

#[test]
fn a_changed_tuple_binding_is_not_the_same_rows() {
    let docs = type_definition(
        "docs",
        &[("reader", this_relation()), ("editor", this_relation())],
        &[
            ("reader", user_types(&[subject_type("user")])),
            ("editor", user_types(&[subject_type("user")])),
        ],
    );
    let left = model(&[json!({ "type": "user" }), docs.clone()]);
    let right = model(&[json!({ "type": "user" }), docs.clone()]);
    let rows = executed_rows(&[("docs:d1", "reader", "user:u1")]);

    // The object moved.
    assert_models_diverge(
        &left,
        &rows,
        &right,
        &executed_rows(&[("docs:d9", "reader", "user:u1")]),
    );
    // The subject moved.
    assert_models_diverge(
        &left,
        &rows,
        &right,
        &executed_rows(&[("docs:d1", "reader", "user:u9")]),
    );
    // The relation the row sits on moved, and both names stay pinned.
    assert_models_diverge(
        &left,
        &rows,
        &right,
        &executed_rows(&[("docs:d1", "editor", "user:u1")]),
    );
}

#[test]
fn a_changed_tuple_to_userset_edge_or_target_is_not_equivalent() {
    let team = type_definition(
        "team",
        &[("member", this_relation())],
        &[("member", user_types(&[subject_type("user")]))],
    );
    let docs = |tupleset: &str| -> Value {
        type_definition(
            "docs",
            &[
                ("can_select", tuple_to_userset(tupleset, "member")),
                ("member_of", this_relation()),
                ("editor_of", this_relation()),
            ],
            &[
                ("member_of", user_types(&[subject_type("team")])),
                ("editor_of", user_types(&[subject_type("team")])),
            ],
        )
    };
    let rows = executed_rows(&[
        ("docs:d1", "member_of", "team:t1#member"),
        ("docs:d1", "editor_of", "team:t1#member"),
        ("team:t1", "member", "user:alice"),
    ]);

    // The edge now reads `editor_of` instead of `member_of`.
    assert_models_diverge(
        &model(&[json!({ "type": "user" }), team.clone(), docs("member_of")]),
        &rows,
        &model(&[json!({ "type": "user" }), team.clone(), docs("editor_of")]),
        &rows,
    );

    let docs_on = |target: &str| -> Value {
        type_definition(
            "docs",
            &[
                ("can_select", tuple_to_userset("member_of", "member")),
                ("member_of", this_relation()),
            ],
            &[("member_of", user_types(&[subject_type(target)]))],
        )
    };
    let group = type_definition(
        "group",
        &[("member", this_relation())],
        &[("member", user_types(&[subject_type("user")]))],
    );

    // The tupleset's target type moved from `team` to `group`.
    assert_models_diverge(
        &model(&[json!({ "type": "user" }), team, docs_on("team")]),
        &executed_rows(&[
            ("docs:d1", "member_of", "team:t1#member"),
            ("team:t1", "member", "user:alice"),
        ]),
        &model(&[json!({ "type": "user" }), group, docs_on("group")]),
        &executed_rows(&[
            ("docs:d1", "member_of", "group:g1#member"),
            ("group:g1", "member", "user:alice"),
        ]),
    );
}

#[test]
fn a_dropped_or_changed_condition_is_not_equivalent() {
    let reader = type_definition(
        "docs",
        &[("reader", this_relation())],
        &[(
            "reader",
            user_types(&[subject_type_with_condition("user", "clock")]),
        )],
    );
    let rows = executed_rows(&[("docs:d1", "reader", "user:u1")]);
    let left = model_with_conditions(
        &[json!({ "type": "user" }), reader.clone()],
        &json!({ "clock": clock_condition() }),
    );

    // A different comparison.
    let widened = model_with_conditions(
        &[json!({ "type": "user" }), reader.clone()],
        &json!({
            "clock": {
                "name": "clock",
                "expression": "ctx.time >= tuple.start",
                "parameters": { "time": { "type_name": "TYPE_NAME_TIMESTAMP" } }
            }
        }),
    );
    assert_models_diverge(&left, &rows, &widened, &rows);

    // A different parameter type.
    let mistyped = model_with_conditions(
        &[json!({ "type": "user" }), reader.clone()],
        &json!({
            "clock": {
                "name": "clock",
                "expression": "ctx.time > tuple.start",
                "parameters": { "time": { "type_name": "TYPE_NAME_STRING" } }
            }
        }),
    );
    assert_models_diverge(&left, &rows, &mistyped, &rows);

    // The condition dropped, and the reference that rode it with it.
    let bare_reader = type_definition(
        "docs",
        &[("reader", this_relation())],
        &[("reader", user_types(&[subject_type("user")]))],
    );
    let bare = model(&[json!({ "type": "user" }), bare_reader]);
    assert_models_diverge(&left, &rows, &bare, &rows);
}

#[test]
fn a_changed_relation_metadata_is_not_equivalent() {
    let rows = executed_rows(&[("docs:d1", "reader", "user:u1")]);

    // The subject type the relation accepts moved.
    assert_models_diverge(
        &model(&[
            json!({ "type": "user" }),
            type_definition(
                "docs",
                &[("reader", this_relation())],
                &[("reader", user_types(&[subject_type("user")]))],
            ),
        ]),
        &rows,
        &model(&[
            json!({ "type": "user2" }),
            type_definition(
                "docs",
                &[("reader", this_relation())],
                &[("reader", user_types(&[subject_type("user2")]))],
            ),
        ]),
        &rows,
    );

    // The public wildcard dropped.
    let public = type_definition(
        "docs",
        &[("public", this_relation())],
        &[("public", user_types(&[public_wildcard("user")]))],
    );
    let bare_public = type_definition(
        "docs",
        &[("public", this_relation())],
        &[("public", user_types(&[subject_type("user")]))],
    );
    let wildcard_rows = executed_rows(&[("docs:d1", "public", "user:*")]);
    assert_models_diverge(
        &model(&[json!({ "type": "user" }), public]),
        &wildcard_rows,
        &model(&[json!({ "type": "user" }), bare_public]),
        &wildcard_rows,
    );

    // A different condition the subject must satisfy.
    let conditions = json!({
        "clock": clock_condition(),
        "spare": {
            "name": "spare",
            "expression": "ctx.flag",
            "parameters": { "flag": { "type_name": "TYPE_NAME_BOOL" } }
        }
    });
    let gated = |condition: &str| -> Value {
        type_definition(
            "docs",
            &[("reader", this_relation())],
            &[(
                "reader",
                user_types(&[subject_type_with_condition("user", condition)]),
            )],
        )
    };
    assert_models_diverge(
        &model_with_conditions(&[json!({ "type": "user" }), gated("clock")], &conditions),
        &rows,
        &model_with_conditions(&[json!({ "type": "user" }), gated("spare")], &conditions),
        &rows,
    );

    // An unreachable relation with no rows still carries its metadata.
    let ghost = |subject: &str| -> Value {
        type_definition(
            "docs",
            &[("ghost", this_relation())],
            &[("ghost", user_types(&[subject_type(subject)]))],
        )
    };
    let empty = TupleRows::new();
    assert_models_diverge(
        &model(&[json!({ "type": "user" }), ghost("user")]),
        &empty,
        &model(&[json!({ "type": "user2" }), ghost("user2")]),
        &empty,
    );
}

#[test]
fn difference_order_is_significant() {
    let rows = executed_rows(&[("docs:d1", "deny", "user:u1")]);
    let metadata: &[(&str, Value)] = &[
        ("blocked", user_types(&[subject_type("user")])),
        ("deny", user_types(&[subject_type("user")])),
    ];

    // The base keeps the direct tuples and the subtraction removes deny.
    let left = model(&[
        json!({ "type": "user" }),
        type_definition(
            "docs",
            &[
                (
                    "blocked",
                    difference_relation(&this_relation(), &computed_relation("deny")),
                ),
                ("deny", this_relation()),
            ],
            metadata,
        ),
    ]);

    // The same two children swapped sides.
    let right = model(&[
        json!({ "type": "user" }),
        type_definition(
            "docs",
            &[
                (
                    "blocked",
                    difference_relation(&computed_relation("deny"), &this_relation()),
                ),
                ("deny", this_relation()),
            ],
            metadata,
        ),
    ]);

    assert_models_diverge(&left, &rows, &right, &rows);
}

#[test]
fn union_and_intersection_children_may_reorder() {
    let team = type_definition(
        "team",
        &[("member", this_relation())],
        &[("member", user_types(&[subject_type("user")]))],
    );
    let docs = |role: Value| -> Value {
        type_definition(
            "docs",
            &[
                ("src_a", this_relation()),
                ("src_b", this_relation()),
                ("role", role),
            ],
            &[
                ("src_a", user_types(&[subject_type("user")])),
                ("src_b", user_types(&[subject_type("team")])),
            ],
        )
    };
    let rows = executed_rows(&[
        ("docs:d1", "src_a", "user:u1"),
        ("docs:d1", "src_b", "team:t1#member"),
        ("team:t1", "member", "user:alice"),
    ]);

    let direct = this_relation();
    let from_a = computed_relation("src_a");
    let through_b = tuple_to_userset("src_b", "member");

    let union_left = model(&[
        json!({ "type": "user" }),
        team.clone(),
        docs(union_children(&[
            direct.clone(),
            from_a.clone(),
            through_b.clone(),
        ])),
    ]);
    let union_right = model(&[
        json!({ "type": "user" }),
        team.clone(),
        docs(union_children(&[
            through_b.clone(),
            from_a.clone(),
            direct.clone(),
        ])),
    ]);
    assert_models_agree(&union_left, &rows, &union_right, &rows);

    let intersection_left = model(&[
        json!({ "type": "user" }),
        team.clone(),
        docs(intersection_children(&[
            direct.clone(),
            from_a.clone(),
            through_b.clone(),
        ])),
    ]);
    let intersection_right = model(&[
        json!({ "type": "user" }),
        team,
        docs(intersection_children(&[from_a, through_b, direct])),
    ]);
    assert_models_agree(&intersection_left, &rows, &intersection_right, &rows);
}

#[test]
fn union_child_multiplicity_is_significant() {
    let left = model(&[
        json!({ "type": "user" }),
        type_definition(
            "docs",
            &[
                ("src_a", this_relation()),
                (
                    "role",
                    union_children(&[
                        this_relation(),
                        computed_relation("src_a"),
                        computed_relation("src_a"),
                    ]),
                ),
            ],
            &[("src_a", user_types(&[subject_type("user")]))],
        ),
    ]);

    // One of the two `src_a` children dropped.
    let right = model(&[
        json!({ "type": "user" }),
        type_definition(
            "docs",
            &[
                ("src_a", this_relation()),
                (
                    "role",
                    union_children(&[this_relation(), computed_relation("src_a")]),
                ),
            ],
            &[("src_a", user_types(&[subject_type("user")]))],
        ),
    ]);

    let rows = executed_rows(&[("docs:d1", "src_a", "user:u1")]);
    assert_models_diverge(&left, &rows, &right, &rows);
}

#[test]
fn tuple_to_userset_resolves_its_computed_reference_on_the_tupleset_target() {
    // The edge must read the target's untouched `reader` while the owner's own is renamed
    let left = model(&[
        json!({ "type": "user" }),
        type_definition(
            "reader_src",
            &[("reader", this_relation())],
            &[("reader", user_types(&[subject_type("user")]))],
        ),
        type_definition(
            "docs",
            &[
                ("can_select", tuple_to_userset("member_of", "reader")),
                ("member_of", this_relation()),
                ("reader", this_relation()),
            ],
            &[
                ("member_of", user_types(&[subject_type("reader_src")])),
                ("reader", user_types(&[subject_type("user")])),
            ],
        ),
    ]);

    let right = model(&[
        json!({ "type": "user" }),
        type_definition(
            "reader_src",
            &[("reader", this_relation())],
            &[("reader", user_types(&[subject_type("user")]))],
        ),
        type_definition(
            "docs",
            &[
                ("can_select", tuple_to_userset("member_of", "reader")),
                ("member_of", this_relation()),
                ("reading", this_relation()),
            ],
            &[
                ("member_of", user_types(&[subject_type("reader_src")])),
                ("reading", user_types(&[subject_type("user")])),
            ],
        ),
    ]);

    assert_models_agree(
        &left,
        &executed_rows(&[
            ("docs:d1", "member_of", "reader_src:s1"),
            ("reader_src:s1", "reader", "user:alice"),
            ("docs:d1", "reader", "user:bob"),
        ]),
        &right,
        &executed_rows(&[
            ("docs:d1", "member_of", "reader_src:s1"),
            ("reader_src:s1", "reader", "user:alice"),
            ("docs:d1", "reading", "user:bob"),
        ]),
    );
}

#[test]
fn the_schema_version_and_type_names_stay_exact() {
    let rows = executed_rows(&[("docs:d1", "reader", "user:u1")]);
    let docs = type_definition(
        "docs",
        &[("reader", this_relation())],
        &[("reader", user_types(&[subject_type("user")]))],
    );
    let types = vec![json!({ "type": "user" }), docs.clone()];
    let current = model(&types);

    // The schema version moved.
    let older = json!({ "schema_version": "1.0", "type_definitions": types.clone() });
    assert_models_diverge(&current, &rows, &older, &rows);

    // The type name moved, its rows following it.
    let documents = type_definition(
        "documents",
        &[("reader", this_relation())],
        &[("reader", user_types(&[subject_type("user")]))],
    );
    let renamed = model(&[json!({ "type": "user" }), documents]);
    assert_models_diverge(
        &current,
        &rows,
        &renamed,
        &executed_rows(&[("documents:d1", "reader", "user:u1")]),
    );
}
