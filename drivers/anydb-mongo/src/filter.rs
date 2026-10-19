//! Filter statement language for `find ... with <filter-text>`.
//!
//! The filter text is parsed into an AST and compiled to a BSON filter
//! document WITH typed parameter values — the document is built
//! client-side from typed values (mongo has no bind stage on the wire,
//! so this is the jdbc-bind analog), never by string interpolation:
//! injection-safe by construction.
//!
//! Grammar (v1, conjunctive only — `or`/`not`/grouping are explicit
//! protocol errors, never ignored):
//!
//! ```text
//! filter    := predicate ( ('and' | ',') predicate )*
//! predicate := path op value | path 'in' '(' (value (',' value)*)? ')'
//! op        := '=' | '!=' | '<' | '<=' | '>' | '>=' | 'in'
//! value     := number | string | true | false | null | '?' (param)
//! path      := segment ('.' segment)*   // segments: [A-Za-z0-9_], no '$'
//! string    := 'single quoted ('' escapes)' | "double quoted ("" escapes)"
//! ```
//!
//! Literals: integers become `Int32` when they fit (mongo shell
//! convention), `Int64` when they do not; decimal/exponent forms become
//! `Double`. Keywords are case-insensitive. `?` placeholders bind
//! positionally to the statement parameters: `Integer` maps to `Int64`
//! (mongo compares numerically across widths), `Float` to `Double`,
//! `Text` to `String`, `Binary` to `Binary`, `Boolean` to `Boolean`,
//! `Null` to `null`. A literal `?` character cannot exist unquoted in
//! filter text.
//!
//! Predicates on the same path merge into ONE operator document
//! (`n > 1 and n < 5` becomes `{n: {$gt: 1, $lt: 5}}`, mongo's canonical
//! range shape); a lone equality keeps the natural shorthand
//! (`{n: 3}`); equality sharing a path with a range renders through
//! `$eq`; a second equality, a repeated operator, or an `in` next to
//! anything else on the same path is a conflict error instead of a
//! silently contradictory or ambiguous filter.

use crate::bson::{Bson, Document};
use anydb_shared::ConnectionError;
use anydb_shared::driver::statement::QueryParameter;

fn protocol(message: String) -> ConnectionError {
    ConnectionError::Protocol(format!("mongo filter: {message}"))
}

/// One comparison operation of a predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
}

impl Op {
    /// The mongo operator key (`$ne`, `$gt`, `$in`, ...).
    fn key(self) -> &'static str {
        match self {
            Self::Eq => "$eq",
            Self::Ne => "$ne",
            Self::Lt => "$lt",
            Self::Le => "$lte",
            Self::Gt => "$gt",
            Self::Ge => "$gte",
            Self::In => "$in",
        }
    }
}

/// A filter value: a literal BSON value or a positional parameter ref.
#[derive(Debug, Clone, PartialEq)]
enum Value {
    Literal(Bson),
    /// Index into the statement parameters (one `?`).
    Param(usize),
}

/// One predicate: a field path, the operation, and the bound value(s).
#[derive(Debug, Clone, PartialEq)]
struct Predicate {
    path: Vec<String>,
    op: Op,
    /// The single right-hand value (unused for `in`).
    value: Value,
    /// The list entries of an `in (...)` predicate.
    values: Vec<Value>,
}

/// A parsed filter: the output of the two-phase compile (parse ->
/// bind), mirroring the postgres Parse/Bind split.
#[derive(Debug, Clone, PartialEq)]
pub struct Filter {
    predicates: Vec<Predicate>,
    placeholders: usize,
}

/// Per-path merge state of the compile phase.
#[derive(Debug)]
struct Merged {
    path: Vec<String>,
    /// Operator slots other than `in`, first seen first.
    slots: Vec<(Op, Bson)>,
    /// The values of the `in` list, when the path has one.
    in_list: Option<Vec<Bson>>,
}

impl Filter {
    /// Binds the statement parameters positionally and produces the
    /// final BSON filter document. The parameter count must be exactly
    /// the number of `?` placeholders, always; every value of every
    /// predicate is bound before anything is materialized.
    pub fn document(&self, params: &[QueryParameter]) -> Result<Document, ConnectionError> {
        if params.len() != self.placeholders {
            return Err(protocol(format!(
                "statement expects {} parameter(s), got {}",
                self.placeholders,
                params.len()
            )));
        }

        let mut merged: Vec<Merged> = Vec::new();
        for predicate in &self.predicates {
            let path = predicate.path.join(".");
            match predicate.op {
                Op::In => {
                    let values = predicate
                        .values
                        .iter()
                        .map(|value| bind_value(value, params))
                        .collect::<Result<Vec<_>, _>>()?;
                    match merged.iter_mut().find(|m| m.path == predicate.path) {
                        Some(_) => {
                            return Err(protocol(format!(
                                "conflicting 'in' predicates for path '{path}'"
                            )));
                        }
                        None => merged.push(Merged {
                            path: predicate.path.clone(),
                            slots: Vec::new(),
                            in_list: Some(values),
                        }),
                    }
                }
                op => {
                    let value = bind_value(&predicate.value, params)?;
                    match merged.iter_mut().find(|m| m.path == predicate.path) {
                        Some(entry) => {
                            if entry.in_list.is_some() {
                                return Err(protocol(format!(
                                    "'in' and '{op_key}' cannot share path '{path}'",
                                    op_key = op.key()
                                )));
                            }
                            if entry.slots.iter().any(|(slot, _)| *slot == op) {
                                return Err(protocol(format!(
                                    "repeated {} predicate for path '{path}'",
                                    if op == Op::Eq { "equality" } else { op.key() }
                                )));
                            }
                            entry.slots.push((op, value));
                        }
                        None => merged.push(Merged {
                            path: predicate.path.clone(),
                            slots: vec![(op, value)],
                            in_list: None,
                        }),
                    }
                }
            }
        }

        Ok(merged
            .into_iter()
            .map(|entry| {
                let field = entry.path.join(".");
                let value = if entry.slots.len() == 1 && entry.slots[0].0 == Op::Eq {
                    // A lone equality keeps the natural shorthand.
                    entry.slots[0].1.clone()
                } else {
                    let mut operators: Vec<(String, Bson)> = Vec::new();
                    for (op, value) in entry.slots {
                        operators.push((op.key().to_owned(), value));
                    }
                    if let Some(list) = entry.in_list {
                        operators.push((Op::In.key().to_owned(), Bson::Array(list)));
                    }
                    Bson::Document(operators)
                };
                (field, value)
            })
            .collect())
    }
}

fn bind_value(value: &Value, params: &[QueryParameter]) -> Result<Bson, ConnectionError> {
    match value {
        Value::Literal(literal) => Ok(literal.clone()),
        Value::Param(index) => {
            let parameter = params
                .get(*index)
                .ok_or_else(|| protocol(format!("missing parameter #{}", index + 1)))?;
            Ok(bson_value(parameter))
        }
    }
}

fn bson_value(parameter: &QueryParameter) -> Bson {
    match parameter {
        QueryParameter::Null => Bson::Null,
        QueryParameter::Boolean(value) => Bson::Boolean(*value),
        // Mongo compares numerically across int widths, so the SPI's
        // widest-integer rule lands on Int64.
        QueryParameter::Integer(value) => Bson::Int64(*value),
        QueryParameter::Float(value) => Bson::Double(*value),
        QueryParameter::Text(value) => Bson::String(value.clone()),
        QueryParameter::Binary(value) => Bson::Binary(value.clone()),
    }
}

// ---------- parser ----------

/// Parses the full filter text of a `with` clause.
pub fn parse_filter(text: &str) -> Result<Filter, ConnectionError> {
    let mut tokens = Tokenizer::new(text);
    if tokens.peek()?.is_none() {
        return Err(protocol("empty filter".to_owned()));
    }
    let mut predicates = Vec::new();
    let mut placeholders = 0usize;

    // The first predicate admits no leading separator.
    predicates.push(parse_predicate(&mut tokens, &mut placeholders)?);
    while let Some(token) = tokens.next()? {
        match token {
            Token::Comma => {}
            Token::Ident(ref name) if name.eq_ignore_ascii_case("and") => {}
            _ => return Err(protocol("expected 'and' between predicates".to_owned())),
        }
        // A trailing separator dies here on the missing path.
        predicates.push(parse_predicate(&mut tokens, &mut placeholders)?);
    }

    Ok(Filter {
        predicates,
        placeholders,
    })
}

/// One `path op value` or `path in (...)`.
fn parse_predicate(
    tokens: &mut Tokenizer,
    placeholders: &mut usize,
) -> Result<Predicate, ConnectionError> {
    let path = parse_path(tokens)?;
    let op = tokens.next()?.ok_or_else(|| {
        protocol(format!(
            "missing an operator after path '{}'",
            path.join(".")
        ))
    })?;
    let empty = Vec::new();
    let predicate = match op {
        Token::Eq | Token::Ne | Token::Lt | Token::Le | Token::Gt | Token::Ge => {
            let parsed = parse_op(&op)?;
            let value = parse_value(tokens, placeholders, parsed.key())?;
            Predicate {
                path,
                op: parsed,
                value,
                values: empty,
            }
        }
        Token::Ident(name) if name.eq_ignore_ascii_case("in") => {
            match tokens.next()? {
                Some(Token::LParen) => {}
                _ => return Err(protocol("expected '(' after 'in'".to_owned())),
            }
            let mut values = Vec::new();
            loop {
                // `)` right away: `in ()` matches nothing, explicitly.
                if matches!(tokens.peek()?, Some(Token::RParen)) {
                    tokens.next()?;
                    break;
                }
                values.push(parse_value(tokens, placeholders, "an $in list")?);
                match tokens.next()? {
                    Some(Token::Comma) => continue,
                    Some(Token::RParen) => break,
                    _ => return Err(protocol("expected ',' or ')' in the $in list".to_owned())),
                }
            }
            Predicate {
                path,
                op: Op::In,
                // The single-value slot stays unused for `in`.
                value: Value::Literal(Bson::Null),
                values,
            }
        }
        token => {
            return Err(protocol(format!("unsupported operator '{token:?}'")));
        }
    };
    Ok(predicate)
}

fn parse_op(token: &Token) -> Result<Op, ConnectionError> {
    match token {
        Token::Eq => Ok(Op::Eq),
        Token::Ne => Ok(Op::Ne),
        Token::Lt => Ok(Op::Lt),
        Token::Le => Ok(Op::Le),
        Token::Gt => Ok(Op::Gt),
        Token::Ge => Ok(Op::Ge),
        _ => Err(protocol("expected a comparison operator".to_owned())),
    }
}

/// One dotted path of plain segments (`user.profile.score`).
fn parse_path(tokens: &mut Tokenizer) -> Result<Vec<String>, ConnectionError> {
    let mut path = Vec::new();
    loop {
        let segment = match tokens.next()? {
            Some(Token::Ident(segment)) => segment,
            _ => return Err(protocol("expected a field name".to_owned())),
        };
        if segment.contains('$') {
            return Err(protocol(format!(
                "path segments may not contain '$': '{segment}'"
            )));
        }
        path.push(segment);
        match tokens.peek()? {
            Some(Token::Dot) => {
                tokens.next()?;
            }
            _ => break,
        }
    }
    Ok(path)
}

fn parse_value(
    tokens: &mut Tokenizer,
    placeholders: &mut usize,
    context: &str,
) -> Result<Value, ConnectionError> {
    match tokens.next()? {
        Some(Token::Number(raw)) => Ok(Value::Literal(number_bson(&raw)?)),
        Some(Token::Str(text)) => Ok(Value::Literal(Bson::String(text))),
        Some(Token::Param) => {
            let index = *placeholders;
            *placeholders += 1;
            Ok(Value::Param(index))
        }
        Some(Token::Ident(word)) => match keyword(&word) {
            Some(Keyword::True) => Ok(Value::Literal(Bson::Boolean(true))),
            Some(Keyword::False) => Ok(Value::Literal(Bson::Boolean(false))),
            Some(Keyword::Null) => Ok(Value::Literal(Bson::Null)),
            None => Err(protocol(format!(
                "a bare identifier is not a literal in {context}"
            ))),
        },
        _ => Err(protocol(format!("expected a literal or '?' in {context}"))),
    }
}

enum Keyword {
    True,
    False,
    Null,
}

fn keyword(ident: &str) -> Option<Keyword> {
    if ident.eq_ignore_ascii_case("true") {
        Some(Keyword::True)
    } else if ident.eq_ignore_ascii_case("false") {
        Some(Keyword::False)
    } else if ident.eq_ignore_ascii_case("null") {
        Some(Keyword::Null)
    } else {
        None
    }
}

/// BSON shape of a numeric literal: integers fit `Int32` when they can
/// (mongo shell convention), fall back to `Int64`; decimals and
/// exponents render as `Double`.
fn number_bson(raw: &str) -> Result<Bson, ConnectionError> {
    if let Ok(value) = raw.parse::<i32>() {
        return Ok(Bson::Int32(value));
    }
    if let Ok(value) = raw.parse::<i64>() {
        return Ok(Bson::Int64(value));
    }
    if !raw.contains(['.', 'e', 'E']) {
        return Err(protocol(format!(
            "integer literal '{raw}' does not fit i64"
        )));
    }
    raw.parse::<f64>()
        .map(Bson::Double)
        .map_err(|_| protocol(format!("invalid numeric literal '{raw}'")))
}

// ---------- tokenizer ----------

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Dot,
    Number(String),
    Str(String),
    Param,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    LParen,
    RParen,
    Comma,
}

/// Hand-rolled scanner: no regex, no dependencies, position-aware
/// errors. One-token lookahead is internal.
struct Tokenizer {
    text: Vec<char>,
    position: usize,
    pending: Option<Token>,
}

impl Tokenizer {
    fn new(text: &str) -> Self {
        Self {
            text: text.chars().collect(),
            position: 0,
            pending: None,
        }
    }

    fn next(&mut self) -> Result<Option<Token>, ConnectionError> {
        if let Some(token) = self.pending.take() {
            return Ok(Some(token));
        }
        self.scan()
    }

    fn peek(&mut self) -> Result<Option<Token>, ConnectionError> {
        if self.pending.is_none() {
            self.pending = self.scan()?;
        }
        Ok(self.pending.clone())
    }

    fn scan(&mut self) -> Result<Option<Token>, ConnectionError> {
        loop {
            let Some(&character) = self.text.get(self.position) else {
                return Ok(None);
            };
            let token = match character {
                space if space.is_whitespace() => {
                    self.position += 1;
                    continue;
                }
                '=' => {
                    self.position += 1;
                    Some(Token::Eq)
                }
                '!' => {
                    self.position += 1;
                    match self.text.get(self.position) {
                        Some('=') => {
                            self.position += 1;
                            Some(Token::Ne)
                        }
                        _ => return Err(protocol("'!' must form the '!=' operator".to_owned())),
                    }
                }
                '<' => {
                    self.position += 1;
                    match self.text.get(self.position) {
                        Some('=') => {
                            self.position += 1;
                            Some(Token::Le)
                        }
                        _ => Some(Token::Lt),
                    }
                }
                '>' => {
                    self.position += 1;
                    match self.text.get(self.position) {
                        Some('=') => {
                            self.position += 1;
                            Some(Token::Ge)
                        }
                        _ => Some(Token::Gt),
                    }
                }
                '(' => {
                    self.position += 1;
                    Some(Token::LParen)
                }
                ')' => {
                    self.position += 1;
                    Some(Token::RParen)
                }
                ',' => {
                    self.position += 1;
                    Some(Token::Comma)
                }
                '.' => {
                    self.position += 1;
                    Some(Token::Dot)
                }
                '?' => {
                    self.position += 1;
                    Some(Token::Param)
                }
                '"' => Some(self.read_string('"')?),
                '\'' => Some(self.read_string('\'')?),
                digit if digit.is_ascii_digit() || digit == '-' => Some(self.read_number()?),
                letter if letter.is_ascii_alphabetic() || letter == '_' => Some(self.read_ident()),
                other => {
                    return Err(protocol(format!("unexpected character '{other}'")));
                }
            };
            return Ok(token);
        }
    }

    fn read_ident(&mut self) -> Token {
        let start = self.position;
        while let Some(&character) = self.text.get(self.position) {
            if character.is_ascii_alphanumeric() || character == '_' {
                self.position += 1;
            } else {
                break;
            }
        }
        Token::Ident(self.text[start..self.position].iter().collect())
    }

    /// `-` starts a number only when it glues onto digits; anything else
    /// degenerates to a number error below.
    fn read_number(&mut self) -> Result<Token, ConnectionError> {
        let start = self.position;
        if self.text.get(self.position) == Some(&'-') {
            self.position += 1;
        }
        let mut dotted = false;
        let mut exponent = false;
        loop {
            match self.text.get(self.position) {
                Some(digit) if digit.is_ascii_digit() => self.position += 1,
                Some('.') if !dotted && !exponent => {
                    dotted = true;
                    self.position += 1;
                }
                Some('e') | Some('E') if !exponent && start != self.position => {
                    exponent = true;
                    self.position += 1;
                    if matches!(self.text.get(self.position), Some('+') | Some('-')) {
                        self.position += 1;
                    }
                }
                _ => break,
            }
        }
        let raw: String = self.text[start..self.position].iter().collect();
        let ends_with_digit = raw
            .chars()
            .last()
            .map(|character| character.is_ascii_digit())
            .unwrap_or(false);
        if !ends_with_digit {
            return Err(protocol(format!("invalid numeric literal '{raw}'")));
        }
        Ok(Token::Number(raw))
    }

    fn read_string(&mut self, quote: char) -> Result<Token, ConnectionError> {
        self.position += 1; // opening quote
        let mut text = String::new();
        loop {
            match self.text.get(self.position) {
                None => {
                    return Err(protocol("string literal is never closed".to_owned()));
                }
                Some(&found) if found == quote => {
                    self.position += 1;
                    // A doubled quote is the escape; a single one ends it.
                    if self.text.get(self.position) == Some(&quote) {
                        text.push(quote);
                        self.position += 1;
                    } else {
                        return Ok(Token::Str(text));
                    }
                }
                Some(&found) => {
                    text.push(found);
                    self.position += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Document {
        parse_filter(text)
            .expect("parse")
            .document(&[])
            .expect("bind")
    }

    fn bind(text: &str, params: &[QueryParameter]) -> Document {
        parse_filter(text)
            .expect("parse")
            .document(params)
            .expect("bind")
    }

    fn error(text: &str) -> String {
        match parse_filter(text).and_then(|filter| filter.document(&[])) {
            Ok(_) => panic!("filter must fail: {text}"),
            Err(ConnectionError::Protocol(message)) => message,
            Err(other) => panic!("unexpected error class: {other:?}"),
        }
    }

    #[test]
    fn lone_equality_stays_in_shorthand_form() {
        assert_eq!(parse("n = 3"), vec![("n".to_owned(), Bson::Int32(3))]);
        assert_eq!(
            parse("name = 'ada'"),
            vec![("name".to_owned(), Bson::String("ada".to_owned()))]
        );
        assert_eq!(
            parse("n = 9223372036854775807"),
            vec![("n".to_owned(), Bson::Int64(9_223_372_036_854_775_807))]
        );
    }

    #[test]
    fn operators_map_to_their_dollar_keys() {
        assert_eq!(
            parse("n != 1"),
            vec![(
                "n".to_owned(),
                Bson::Document(vec![("$ne".to_owned(), Bson::Int32(1))])
            )]
        );
        assert_eq!(
            parse("n >= 7"),
            vec![(
                "n".to_owned(),
                Bson::Document(vec![("$gte".to_owned(), Bson::Int32(7))])
            )]
        );
        assert_eq!(
            parse("at <= 5"),
            vec![(
                "at".to_owned(),
                Bson::Document(vec![("$lte".to_owned(), Bson::Int32(5))])
            )]
        );
    }

    #[test]
    fn predicates_merge_per_path_into_one_operator_document() {
        assert_eq!(
            parse("n > 1 and n < 5, flag = true"),
            vec![
                (
                    "n".to_owned(),
                    Bson::Document(vec![
                        ("$gt".to_owned(), Bson::Int32(1)),
                        ("$lt".to_owned(), Bson::Int32(5)),
                    ])
                ),
                ("flag".to_owned(), Bson::Boolean(true)),
            ]
        );
        // Equality sharing a path with a range renders through $eq.
        assert_eq!(
            parse("n = 3 and n > 1"),
            vec![(
                "n".to_owned(),
                Bson::Document(vec![
                    ("$eq".to_owned(), Bson::Int32(3)),
                    ("$gt".to_owned(), Bson::Int32(1)),
                ])
            )]
        );
    }

    #[test]
    fn in_list_binds_every_entry() {
        assert_eq!(
            parse("tag in ('a', \"b\")"),
            vec![(
                "tag".to_owned(),
                Bson::Document(vec![(
                    "$in".to_owned(),
                    Bson::Array(vec![
                        Bson::String("a".to_owned()),
                        Bson::String("b".to_owned()),
                    ])
                )])
            )]
        );
        assert_eq!(
            parse("n in ()"),
            vec![(
                "n".to_owned(),
                Bson::Document(vec![("$in".to_owned(), Bson::Array(vec![]))])
            )]
        );
    }

    #[test]
    fn dot_paths_and_null_and_decimals() {
        assert_eq!(
            parse("user.profile.score >= 1.5"),
            vec![(
                "user.profile.score".to_owned(),
                Bson::Document(vec![("$gte".to_owned(), Bson::Double(1.5))])
            )]
        );
        assert_eq!(
            parse("deleted = null"),
            vec![("deleted".to_owned(), Bson::Null)]
        );
        assert_eq!(
            parse("ratio = 2.5e-1"),
            vec![("ratio".to_owned(), Bson::Double(0.25))]
        );
    }

    #[test]
    fn negative_numbers_parse_through_the_sign() {
        assert_eq!(parse("n = -3"), vec![("n".to_owned(), Bson::Int32(-3))]);
        assert_eq!(
            parse("n > -1.5"),
            vec![(
                "n".to_owned(),
                Bson::Document(vec![("$gt".to_owned(), Bson::Double(-1.5))])
            )]
        );
    }

    #[test]
    fn params_bind_positionally_across_types() {
        let parameters = [
            QueryParameter::Text("ada".to_owned()),
            QueryParameter::Integer(10),
            QueryParameter::Float(0.5),
            QueryParameter::Boolean(false),
            QueryParameter::Binary(vec![0xCA]),
            QueryParameter::Null,
        ];
        assert_eq!(
            bind(
                "name = ? and score > ? and ratio = ? and ok = ? and blob = ? and gone = ?",
                &parameters
            ),
            vec![
                ("name".to_owned(), Bson::String("ada".to_owned())),
                (
                    "score".to_owned(),
                    Bson::Document(vec![("$gt".to_owned(), Bson::Int64(10))])
                ),
                ("ratio".to_owned(), Bson::Double(0.5)),
                ("ok".to_owned(), Bson::Boolean(false)),
                ("blob".to_owned(), Bson::Binary(vec![0xCA])),
                ("gone".to_owned(), Bson::Null),
            ]
        );
    }

    #[test]
    fn arity_is_checked_exactly() {
        let filter = parse_filter("n = ?").expect("parses");
        // Exactly one placeholder: one param binds, zero and two fail.
        assert_eq!(
            filter
                .document(&[QueryParameter::Integer(1)])
                .expect("binds"),
            vec![("n".to_owned(), Bson::Int64(1))]
        );
        assert!(matches!(
            filter.document(&[]),
            Err(ConnectionError::Protocol(ref message)) if message.contains("expects 1 parameter")
        ));
        assert!(matches!(
            filter.document(&[
                QueryParameter::Integer(1),
                QueryParameter::Integer(2)
            ]),
            Err(ConnectionError::Protocol(ref message)) if message.contains("got 2")
        ));
        // '?' inside a string is a literal character, not a placeholder.
        let filter = parse_filter("q = 'why?'").expect("parses");
        filter.document(&[]).expect("no parameters needed");
    }

    #[test]
    fn conflicting_equality_and_repeats_are_errors() {
        assert!(error("n = 1 and n = 2").contains("repeated equality"));
        // Detected pre-bind: even equal parameter values conflict.
        let filter = parse_filter("n = ? and n = ?").expect("parses");
        assert!(matches!(
            filter.document(&[QueryParameter::Integer(1), QueryParameter::Integer(1)]),
            Err(ConnectionError::Protocol(ref message)) if message.contains("repeated equality")
        ));
        assert!(error("n > 1 and n > 2").contains("repeated"));
        assert!(error("n in (1) and n = 2").contains("cannot share path"));
        // A range plus a different range is NOT a conflict: conjunctive.
        let _ = parse("n > 1 and n <= 5");
    }

    #[test]
    fn syntax_errors_name_the_problem() {
        assert!(error("").contains("empty filter"));
        assert!(error("n").contains("missing an operator"));
        assert!(error("n =").contains("expected a literal"));
        assert!(error("n = and").contains("bare identifier"));
        assert!(error("n = 'open").contains("never closed"));
        assert!(error("n = 5 or n = 6").contains("expected 'and'"));
        assert!(error("n = 1!(").contains("'!' must form the '!='"));
        assert!(error("n = 1 2").contains("expected 'and'"));
        assert!(error("n in ('a'").contains("expected ',' or ')'"));
        assert!(error("n = -").contains("invalid numeric literal"));
        assert!(error("n = 1e+").contains("invalid numeric literal"));
        assert!(error("a..b = 1").contains("expected a field name"));
        assert!(error("n in 3").contains("expected '(' after 'in'"));
        // The tokenizer never even forms a '$'-prefixed identifier.
        assert!(error("$where = 1").contains("unexpected character '$'"));
    }

    #[test]
    fn quote_escaping_is_doubling_only_on_both_quote_kinds() {
        assert_eq!(
            parse("txt = 'it''s' and label = \"A\"\"B\""),
            vec![
                ("txt".to_owned(), Bson::String("it's".to_owned())),
                ("label".to_owned(), Bson::String("A\"B".to_owned()))
            ]
        );
    }

    #[test]
    fn separators_and_trailing_garbage_are_rejected() {
        // A leading 'and' reads as a field path, so 'n' then fails as an
        // operator position.
        assert!(error("and n = 1").contains("unsupported operator"));
        assert!(error("n = 1 and").contains("expected a field name"));
        assert!(error("n = 1 ,").contains("expected a field name"));
        assert!(error("s = )").contains("expected a literal"));
        assert!(error("n in (1) and 5 = 1").contains("expected a field name"));
        assert!(error("%").contains("unexpected character"));
    }
}
