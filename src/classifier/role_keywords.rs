//! `current_user`, `current_role`, `user` and `session_user`, read as the names of the
//! roles a request runs under.
//!
//! A request logs in as the deployment's login role and acts as one of its acting roles,
//! so `session_user` is the login role's name and the other three are the acting role's.
//! Where the deployment acts as one role, each keyword is a string literal the rest of
//! the classifier reads like any other. Where it acts as several, the acting role's name
//! differs by request and the model cannot tell them apart yet, so a read of it is
//! refused.

use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ops::ControlFlow;

use sqlparser::ast::{Expr, FunctionArguments, Value, VisitMut, VisitorMut};

use crate::classifier::constant_fold::fold_constant_comparisons;
use crate::classifier::function_registry::FunctionRegistry;
use crate::parser::names::{role_keyword, RoleKeyword};

/// Why a role keyword in a clause has no one name to stand for.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RoleKeywordError {
    /// The registry was not read for a deployment, so no role is named at all.
    #[error("{keyword} names a role a request runs as, and no deployment names one")]
    NoDeployment {
        /// The keyword as written.
        keyword: String,
    },
    /// The deployment acts as several roles, each a different value of the keyword.
    #[error(
        "{keyword} names the role a request acts as, and the deployment acts as {} roles \
         ({}), so it has no one value the model can compare",
        roles.len(),
        roles.join(", ")
    )]
    SeveralActingRoles {
        /// The keyword as written.
        keyword: String,
        /// The deployment's acting roles.
        roles: Vec<String>,
    },
}

/// The role keyword `expr` is, spelled as the parser leaves it: an unquoted identifier
/// (`current_role`), or a call with no argument list (`current_user`, `user`,
/// `session_user`).
fn keyword_of(expr: &Expr) -> Option<RoleKeyword> {
    match expr {
        Expr::Identifier(ident) if ident.quote_style.is_none() => role_keyword(&ident.value),
        Expr::Function(function)
            if matches!(function.args, FunctionArguments::None)
                && matches!(function.parameters, FunctionArguments::None)
                && function.over.is_none()
                && function.filter.is_none() =>
        {
            role_keyword(&function.name.to_string())
        }
        _ => None,
    }
}

/// `expr` with every role keyword replaced by the name of the role it reads, or why one
/// has no single name. Borrowed where no keyword occurs.
pub(crate) fn lower_role_keywords<'e>(
    expr: &'e Expr,
    registry: &FunctionRegistry,
) -> Result<Cow<'e, Expr>, RoleKeywordError> {
    let mut found = false;
    let _ = sqlparser::ast::visit_expressions(expr, |node| {
        if keyword_of(node).is_some() {
            found = true;
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    });
    if !found {
        return Ok(Cow::Borrowed(expr));
    }

    let mut lowered = expr.clone();
    let mut lower = Lower {
        registry,
        refused: None,
    };
    let _ = VisitMut::visit(&mut lowered, &mut lower);
    match lower.refused {
        Some(refused) => Err(refused),
        None => Ok(Cow::Owned(lowered)),
    }
}

/// `expr` as the classifier reads it, its role keywords named and every comparison
/// between constants that leaves folded to its truth.
///
/// # Errors
///
/// As [`lower_role_keywords`].
pub(crate) fn prepare_clause<'e>(
    expr: &'e Expr,
    registry: &FunctionRegistry,
) -> Result<Cow<'e, Expr>, RoleKeywordError> {
    lower_role_keywords(expr, registry).map(fold_constant_comparisons)
}

struct Lower<'r> {
    registry: &'r FunctionRegistry,
    refused: Option<RoleKeywordError>,
}

/// The name of the role `keyword`, written as `spelled`, reads for the deployment
/// `registry` was read for.
///
/// # Errors
///
/// [`RoleKeywordError::NoDeployment`] when the registry was read for none, and
/// [`RoleKeywordError::SeveralActingRoles`] for the acting role of a deployment acting as
/// more than one.
pub(crate) fn role_name(
    registry: &FunctionRegistry,
    keyword: RoleKeyword,
    spelled: &str,
) -> Result<String, RoleKeywordError> {
    let Some(deployment) = registry.deployment() else {
        return Err(RoleKeywordError::NoDeployment {
            keyword: spelled.to_string(),
        });
    };
    match keyword {
        RoleKeyword::Login => Ok(deployment.login_role().to_string()),
        RoleKeyword::Acting => {
            let roles: Vec<String> = deployment.acting_roles().map(str::to_string).collect();
            match <[String; 1]>::try_from(roles) {
                Ok([role]) => Ok(role),
                Err(roles) => Err(RoleKeywordError::SeveralActingRoles {
                    keyword: spelled.to_string(),
                    roles,
                }),
            }
        }
    }
}

impl VisitorMut for Lower<'_> {
    type Break = ();

    fn post_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<()> {
        let Some(keyword) = keyword_of(expr) else {
            return ControlFlow::Continue(());
        };
        match role_name(self.registry, keyword, &expr.to_string()) {
            Ok(name) => {
                *expr = Expr::Value(Value::SingleQuotedString(name).into());
                ControlFlow::Continue(())
            }
            Err(refused) => {
                self.refused = Some(refused);
                ControlFlow::Break(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::expr::parse_expr_for_tests as parse_expr;
    use crate::parser::sql_parser::Deployment;

    fn lowered(sql: &str, registry: &FunctionRegistry) -> Result<String, RoleKeywordError> {
        lower_role_keywords(&parse_expr(sql), registry).map(|expr| expr.to_string())
    }

    fn registry_acting_as(roles: &[&str]) -> FunctionRegistry {
        let mut registry = FunctionRegistry::new();
        registry.adopt(
            &Deployment::new("app_login", roles.iter().copied(), []).expect("a valid deployment"),
        );
        registry
    }

    /// Every spelling of the acting role reads its name, `session_user` the login
    /// role's, and a quoted or qualified spelling is a column or a call it leaves alone.
    #[test]
    fn each_keyword_reads_the_role_it_names() {
        let registry = registry_acting_as(&["app_user"]);
        for (written, read) in [
            ("owner = current_user", "owner = 'app_user'"),
            ("owner = CURRENT_ROLE", "owner = 'app_user'"),
            ("owner = user", "owner = 'app_user'"),
            ("owner = current_user::text", "owner = 'app_user'::TEXT"),
            ("owner = session_user", "owner = 'app_login'"),
            (
                "EXISTS (SELECT 1 FROM members m WHERE m.role = current_user)",
                "EXISTS (SELECT 1 FROM members m WHERE m.role = 'app_user')",
            ),
        ] {
            assert_eq!(
                lowered(written, &registry),
                Ok(read.to_string()),
                "{written}"
            );
        }
        for untouched in [r#"owner = "current_user""#, "owner = d.current_user"] {
            let input = parse_expr(untouched);
            let lowered =
                lower_role_keywords(&input, &registry).expect("no keyword, so nothing refuses");
            assert!(
                core::ptr::eq(
                    core::ptr::from_ref(lowered.as_ref()),
                    core::ptr::from_ref(&input)
                ),
                "{untouched} names no role keyword"
            );
        }
    }

    /// With several acting roles the keyword has one value per request, and the login
    /// role stays one name.
    #[test]
    fn several_acting_roles_leave_the_acting_role_unnamed() {
        let registry = registry_acting_as(&["anon", "authenticated"]);
        assert_eq!(
            lowered("owner = current_user", &registry),
            Err(RoleKeywordError::SeveralActingRoles {
                keyword: "current_user".to_string(),
                roles: vec!["anon".to_string(), "authenticated".to_string()],
            })
        );
        assert_eq!(
            lowered("owner = session_user", &registry),
            Ok("owner = 'app_login'".to_string())
        );
    }

    /// A registry nobody read for a deployment names no role, and an expression without
    /// a keyword needs none.
    #[test]
    fn without_a_deployment_only_keyword_free_clauses_read() {
        let registry = FunctionRegistry::new();
        assert_eq!(
            lowered("owner = session_user", &registry),
            Err(RoleKeywordError::NoDeployment {
                keyword: "session_user".to_string(),
            })
        );
        assert_eq!(
            lowered("owner = 'alice'", &registry),
            Ok("owner = 'alice'".to_string())
        );
    }
}
