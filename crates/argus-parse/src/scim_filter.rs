pub const MAX_DEPTH: u32 = 16;
pub const MAX_TOKENS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Co,
    Sw,
    Ew,
    Gt,
    Lt,
    Ge,
    Le,
}

impl CompareOp {
    fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "eq" => Some(Self::Eq),
            "ne" => Some(Self::Ne),
            "co" => Some(Self::Co),
            "sw" => Some(Self::Sw),
            "ew" => Some(Self::Ew),
            "gt" => Some(Self::Gt),
            "lt" => Some(Self::Lt),
            "ge" => Some(Self::Ge),
            "le" => Some(Self::Le),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_ordered(&self) -> bool {
        matches!(self, Self::Gt | Self::Lt | Self::Ge | Self::Le)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Number(f64),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    Present {
        path: String,
    },
    Compare {
        path: String,
        op: CompareOp,
        value: Value,
    },
    And(Box<Filter>, Box<Filter>),
    Or(Box<Filter>, Box<Filter>),
    Not(Box<Filter>),
    ValuePath {
        path: String,
        filter: Box<Filter>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    #[error("the filter is empty")]
    Empty,

    #[error("unexpected token at position {position}")]
    Unexpected { position: usize },

    #[error("the filter nests deeper than the accepted maximum")]
    TooDeep,

    #[error("the filter has more tokens than the accepted maximum")]
    TooLong,

    #[error("an unterminated string literal")]
    UnterminatedString,

    #[error("{operator} cannot be applied to a boolean or null value")]
    UnorderedComparison { operator: &'static str },

    #[error("unknown operator")]
    UnknownOperator,
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Str(String),
    Number(f64),
    True,
    False,
    Null,
    OpenParen,
    CloseParen,
    OpenBracket,
    CloseBracket,
}

fn tokenise(input: &str) -> Result<Vec<Token>, FilterError> {
    let bytes: Vec<char> = input.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let c = *bytes.get(i).unwrap_or(&' ');

        if c.is_whitespace() {
            i += 1;
            continue;
        }

        if out.len() >= MAX_TOKENS {
            return Err(FilterError::TooLong);
        }

        match c {
            '(' => {
                out.push(Token::OpenParen);
                i += 1;
            }
            ')' => {
                out.push(Token::CloseParen);
                i += 1;
            }
            '[' => {
                out.push(Token::OpenBracket);
                i += 1;
            }
            ']' => {
                out.push(Token::CloseBracket);
                i += 1;
            }
            '"' => {
                let mut value = String::new();
                i += 1;
                let mut closed = false;
                while i < bytes.len() {
                    let ch = *bytes.get(i).unwrap_or(&' ');
                    if ch == '\\' && i + 1 < bytes.len() {
                        let next = *bytes.get(i + 1).unwrap_or(&' ');
                        value.push(match next {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            other => other,
                        });
                        i += 2;
                        continue;
                    }
                    if ch == '"' {
                        closed = true;
                        i += 1;
                        break;
                    }
                    value.push(ch);
                    i += 1;
                }
                if !closed {
                    return Err(FilterError::UnterminatedString);
                }
                out.push(Token::Str(value));
            }
            _ => {
                let start = i;
                while i < bytes.len() {
                    let ch = *bytes.get(i).unwrap_or(&' ');
                    if ch.is_whitespace() || matches!(ch, '(' | ')' | '[' | ']' | '"') {
                        break;
                    }
                    i += 1;
                }
                let word: String = bytes.get(start..i).unwrap_or_default().iter().collect();
                out.push(match word.to_ascii_lowercase().as_str() {
                    "true" => Token::True,
                    "false" => Token::False,
                    "null" => Token::Null,
                    _ => word
                        .parse::<f64>()
                        .map_or_else(|_| Token::Ident(word.clone()), Token::Number),
                });
            }
        }
    }

    Ok(out)
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
    depth: u32,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn peek_keyword(&self, word: &str) -> bool {
        matches!(self.peek(), Some(Token::Ident(v)) if v.eq_ignore_ascii_case(word))
    }

    fn bump(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.position).cloned();
        self.position += 1;
        token
    }

    fn expect(&mut self, expected: &Token) -> Result<(), FilterError> {
        if self.peek() == Some(expected) {
            self.position += 1;
            return Ok(());
        }
        Err(FilterError::Unexpected {
            position: self.position,
        })
    }

    fn enter(&mut self) -> Result<(), FilterError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(FilterError::TooDeep);
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_or(&mut self) -> Result<Filter, FilterError> {
        let mut left = self.parse_and()?;
        while self.peek_keyword("or") {
            self.position += 1;
            let right = self.parse_and()?;
            left = Filter::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Filter, FilterError> {
        let mut left = self.parse_not()?;
        while self.peek_keyword("and") {
            self.position += 1;
            let right = self.parse_not()?;
            left = Filter::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Filter, FilterError> {
        if self.peek_keyword("not") {
            self.position += 1;
            self.enter()?;
            self.expect(&Token::OpenParen)?;
            let inner = self.parse_or()?;
            self.expect(&Token::CloseParen)?;
            self.leave();
            return Ok(Filter::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Filter, FilterError> {
        if self.peek() == Some(&Token::OpenParen) {
            self.position += 1;
            self.enter()?;
            let inner = self.parse_or()?;
            self.expect(&Token::CloseParen)?;
            self.leave();
            return Ok(inner);
        }

        let position = self.position;
        let Some(Token::Ident(path)) = self.bump() else {
            return Err(FilterError::Unexpected { position });
        };

        if self.peek() == Some(&Token::OpenBracket) {
            self.position += 1;
            self.enter()?;
            let inner = self.parse_or()?;
            self.expect(&Token::CloseBracket)?;
            self.leave();

            let mut full = path;
            if let Some(Token::Ident(sub)) = self.peek()
                && sub.starts_with('.')
            {
                full.push_str(sub);
                self.position += 1;
            }

            return Ok(Filter::ValuePath {
                path: full,
                filter: Box::new(inner),
            });
        }

        let position = self.position;
        let Some(Token::Ident(operator)) = self.bump() else {
            return Err(FilterError::Unexpected { position });
        };

        if operator.eq_ignore_ascii_case("pr") {
            return Ok(Filter::Present { path });
        }

        let op = CompareOp::parse(&operator).ok_or(FilterError::UnknownOperator)?;

        let position = self.position;
        let value = match self.bump() {
            Some(Token::Str(v)) => Value::Str(v),
            Some(Token::Number(v)) => Value::Number(v),
            Some(Token::True) => Value::Bool(true),
            Some(Token::False) => Value::Bool(false),
            Some(Token::Null) => Value::Null,
            _ => return Err(FilterError::Unexpected { position }),
        };

        if op.is_ordered() && matches!(value, Value::Bool(_) | Value::Null) {
            return Err(FilterError::UnorderedComparison {
                operator: match op {
                    CompareOp::Gt => "gt",
                    CompareOp::Lt => "lt",
                    CompareOp::Ge => "ge",
                    _ => "le",
                },
            });
        }

        Ok(Filter::Compare { path, op, value })
    }
}

pub fn parse(input: &str) -> Result<Filter, FilterError> {
    let tokens = tokenise(input)?;
    if tokens.is_empty() {
        return Err(FilterError::Empty);
    }

    let mut parser = Parser {
        tokens,
        position: 0,
        depth: 0,
    };

    let filter = parser.parse_or()?;

    if parser.position != parser.tokens.len() {
        return Err(FilterError::Unexpected {
            position: parser.position,
        });
    }

    Ok(filter)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{CompareOp, Filter, FilterError, MAX_DEPTH, Value, parse};

    fn ok(input: &str) -> Filter {
        parse(input).unwrap_or_else(|e| panic!("{input:?} rejected: {e}"))
    }

    #[test]
    fn the_specs_own_examples_parse() {
        for input in [
            r#"userName eq "bjensen""#,
            r#"name.familyName co "O'Malley""#,
            r#"userName sw "J""#,
            r#"urn:ietf:params:scim:schemas:core:2.0:User:userName sw "J""#,
            "title pr",
            r#"meta.lastModified gt "2011-05-13T04:42:34Z""#,
            r#"title pr and userType eq "Employee""#,
            r#"title pr or userType eq "Intern""#,
            r#"schemas eq "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User""#,
            r#"userType eq "Employee" and (emails co "example.com" or emails.value co "example.org")"#,
            r#"userType ne "Employee" and not (emails co "example.com" or emails.value co "example.org")"#,
            r#"userType eq "Employee" and (emails.type eq "work")"#,
            r#"emails[type eq "work" and value co "@example.com"]"#,
        ] {
            let _ = ok(input);
        }
    }

    #[test]
    fn a_patch_path_is_not_a_filter() {
        assert!(
            parse(r#"emails[type eq "work"].value eq "x""#).is_err(),
            "valuePath subAttr is PATH grammar (figure 8), not FILTER grammar"
        );
    }

    #[test]
    fn errata_7319_allows_a_space_after_not() {
        assert!(parse(r#"not (userName eq "a")"#).is_ok());
        assert!(parse(r#"not(userName eq "a")"#).is_ok());
    }

    #[test]
    fn errata_7322_allows_a_grouped_logical_expression_inside_a_value_path() {
        let _ = ok(r#"emails[type eq "work" or (type eq "home" and value ew "@example.com")]"#);
    }

    #[test]
    fn errata_4670_binds_and_tighter_than_or() {
        let parsed = ok(r#"a eq "1" or b eq "2" and c eq "3""#);
        let Filter::Or(_, right) = parsed else {
            panic!("or must be the outermost node");
        };
        assert!(
            matches!(*right, Filter::And(_, _)),
            "and must bind tighter than or"
        );
    }

    #[test]
    fn not_binds_tighter_than_and() {
        let parsed = ok(r#"not (a eq "1") and b eq "2""#);
        let Filter::And(left, _) = parsed else {
            panic!("and must be outermost");
        };
        assert!(matches!(*left, Filter::Not(_)));
    }

    #[test]
    fn operators_are_case_insensitive() {
        for input in [
            r#"userName EQ "john""#,
            r#"userName Eq "john""#,
            "title PR",
            r#"a eq "1" AND b eq "2""#,
            r#"a eq "1" Or b eq "2""#,
            r#"NOT (a eq "1")"#,
        ] {
            assert!(parse(input).is_ok(), "{input:?} rejected");
        }
    }

    #[test]
    fn a_dollar_sign_is_accepted_in_an_attribute_name() {
        let parsed = ok(r#"$ref eq "https://example.com/Users/1""#);
        let Filter::Compare { path, .. } = parsed else {
            panic!("expected a comparison");
        };
        assert_eq!(path, "$ref", "RFC 7643 nameChar allows $, 7644's does not");
    }

    #[test]
    fn ordered_operators_are_refused_on_booleans_and_null() {
        for op in ["gt", "lt", "ge", "le"] {
            for value in ["true", "false", "null"] {
                assert!(
                    matches!(
                        parse(&format!("active {op} {value}")),
                        Err(FilterError::UnorderedComparison { .. })
                    ),
                    "{op} {value} was accepted"
                );
            }
        }
    }

    #[test]
    fn ordered_operators_are_fine_on_numbers_and_strings() {
        assert!(parse(r#"meta.lastModified gt "2011-05-13T04:42:34Z""#).is_ok());
        assert!(parse("count gt 5").is_ok());
    }

    #[test]
    fn an_unknown_operator_is_named_as_such() {
        assert_eq!(
            parse(r#"userName like "john""#).unwrap_err(),
            FilterError::UnknownOperator
        );
    }

    #[test]
    fn nesting_deeper_than_the_ceiling_is_refused_rather_than_overflowing_the_stack() {
        let deep = format!(
            "{}a eq \"1\"{}",
            "not (".repeat((MAX_DEPTH as usize) + 4),
            ")".repeat((MAX_DEPTH as usize) + 4)
        );
        assert_eq!(parse(&deep).unwrap_err(), FilterError::TooDeep);
    }

    #[test]
    fn a_filter_with_too_many_tokens_is_refused() {
        let long = (0..300)
            .map(|i| format!("a{i} pr"))
            .collect::<Vec<_>>()
            .join(" and ");
        assert_eq!(parse(&long).unwrap_err(), FilterError::TooLong);
    }

    #[test]
    fn an_unterminated_string_is_refused() {
        assert_eq!(
            parse(r#"userName eq "john"#).unwrap_err(),
            FilterError::UnterminatedString
        );
    }

    #[test]
    fn an_empty_filter_is_refused() {
        assert_eq!(parse("").unwrap_err(), FilterError::Empty);
        assert_eq!(parse("   ").unwrap_err(), FilterError::Empty);
    }

    #[test]
    fn trailing_rubbish_is_refused_rather_than_ignored() {
        assert!(matches!(
            parse(r#"userName eq "john" garbage"#),
            Err(FilterError::Unexpected { .. })
        ));
        assert!(matches!(
            parse(r#"userName eq "john")"#),
            Err(FilterError::Unexpected { .. })
        ));
    }

    #[test]
    fn a_value_path_carries_its_inner_filter() {
        let parsed = ok(r#"emails[type eq "work"]"#);
        let Filter::ValuePath { path, filter } = parsed else {
            panic!("expected a value path");
        };
        assert_eq!(path, "emails");
        assert!(matches!(*filter, Filter::Compare { .. }));
    }

    #[test]
    fn every_comparison_operator_round_trips() {
        for (raw, want) in [
            ("eq", CompareOp::Eq),
            ("ne", CompareOp::Ne),
            ("co", CompareOp::Co),
            ("sw", CompareOp::Sw),
            ("ew", CompareOp::Ew),
        ] {
            let parsed = ok(&format!(r#"userName {raw} "x""#));
            let Filter::Compare { op, value, .. } = parsed else {
                panic!("expected a comparison");
            };
            assert_eq!(op, want);
            assert_eq!(value, Value::Str("x".to_owned()));
        }
    }
}
