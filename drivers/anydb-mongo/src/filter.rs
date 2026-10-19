//! Filter statement language for `find ... with <filter-text>`.
//!
//! The filter text is parsed into an AST and compiled to a BSON filter
//! document WITH typed parameter values — the document is built
//! client-side from typed values (mongo has no bind stage on the wire,
//! so this is the jdbc-bind analog), never by string interpolation:
//! injection-safe by construction.
//!
//! Grammar (v3 adds unary `not`; `and` binds tighter than `or`, `not`
//! binds tighter than both):
//!
//! ```text
//! filter     := or_expr
//! or_expr    := and_expr ('or' and_expr)*        // lowest precedence
//! and_expr   := atom ( ('and' | ',') atom )*
//! atom       := 'not'* core                      // parity-folded in place
//! core       := '(' or_expr ')' | predicate
//! predicate  := path op value | path 'in' '(' (value (',' value)*)? ')'
//! op         := '=' | '!=' | '<' | '<=' | '>' | '>=' | 'in'
//! value      := number | string | true | false | null | '?' (param)
//! path       := segment ('.' segment)*   // segments: [A-Za-z0-9_], no '$'
//! string     := 'single quoted ('' escapes)' | "double quoted ("" escapes)"
//! ```
//!
//! `and` binds tighter than `or` (`a = 1 and b = 2 or c = 3` is
//! `{a=1, b=2} or {c=3}`); `not` binds tightest (`not a = 1 or b = 2`
//! negates only `a = 1`). A leading field named exactly `not` is
//! reserved — a dotted segment may still be named `not`. Parenthesized
//! groups cut anywhere; nesting is capped at 16 levels and an empty
//! group is an error. Literals: integers become `Int32` when they fit
//! (mongo shell convention), `Int64` when they do not; decimal/exponent
//! forms become `Double`. Keywords are case-insensitive. `?`
//! placeholders bind positionally to the statement parameters (in
//! first-seen order across all branches): `Integer` maps to `Int64`
//! (mongo compares numerically across widths), `Float` to `Double`,
//! `Text` to `String`, `Binary` to `Binary`, `Boolean` to `Boolean`,
//! `Null` to `null`, and `BigDecimal` parses to exact BSON
//! `decimal128` (invalid decimal text is a bind-time protocol error).
//! A literal `?` character cannot exist unquoted in filter text.
//!
//! Compiling: a conjunctive run of predicates on the same path merges
//! into ONE operator document (`n > 1 and n < 5` becomes
//! `{n: {$gt: 1, $lt: 5}}`, mongo's canonical range shape; a lone
//! equality keeps the natural shorthand `{n: 3}`); equality sharing a
//! path with a range renders through `$eq`; a second equality, a
//! repeated operator, an `in` next to anything else on the same path,
//! or an equality contradicting its own negation is a conflict error
//! instead of a silently contradictory or ambiguous filter. `or`
//! renders as the mongo `$or` top-level key over compiled branch
//! documents — a conflict-free single branch stays a plain document
//! (no `$or` wrapper for one alternative). An `and` chain mixing
//! predicates with TWO or more parenthesized alternatives wraps the
//! extra branch documents under mongo's `$and`; one alternative sits
//! directly beside the merged fields. A negated predicate merges as an
//! operator slot beside positive siblings (`a = 1 and not a > 2`
//! becomes `{a: {$eq: 1, $not: {$gt: 2}}}`); negating an `or` renders
//! mongo's `$nor`; negating an `and` applies de Morgan as an `$or`
//! over the negated conjuncts. Because paths reject `$` at the
//! tokenizer, compiled `$or`/`$and`/`$not`/`$nor` keys can never
//! collide with field names. Merge/conflict checks apply within each
//! conjunctive run: predicates equal by text but in different
//! or-branches are independent and merge freely.

use crate::bson::{Bson, Document};
use anydb_shared::ConnectionError;
use anydb_shared::driver::statement::QueryParameter;

fn protocol(message: String) -> ConnectionError {
    ConnectionError::Protocol(format!("mongo filter: {message}"))
}

/// One comparison operation of a predicate. `Not` is render-only: the
/// parser never yields it; the compile of unary `not` slots it so a
/// negated predicate merges beside sibling operators on its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    Not,
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
            Self::Not => "$not",
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

/// One node of the grammatical precedence tree: `and` chains merge
/// per-path, `or` chains take branch documents, `not` negates its child.
#[derive(Debug, Clone, PartialEq)]
enum Node {
    /// All children must match (an `and` chain or a bare predicate
    /// promoted by the one-atom unwrapping).
    And(Vec<Node>),
    /// At least one child must match.
    Or(Vec<Node>),
    /// Negated child; consecutive `not`s fold by parity at parse time.
    Not(Box<Node>),
    Pred(Predicate),
}

/// A parsed filter: the output of the two-phase compile (parse ->
/// bind), mirroring the postgres Parse/Bind split.
#[derive(Debug, Clone, PartialEq)]
pub struct Filter {
    /// The whole expression tree.
    root: Node,
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

/// Maximum parenthesized-group nesting the parser accepts (recursion
/// guard; deeper filters are an explicit error, never truncated).
const MAX_GROUP_DEPTH: usize = 16;

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
        self.compile(&self.root, params)
    }

    /// Compiles one node of the precedence tree. `And` children that
    /// are predicates merge per path (the v1 rules, now scoped to the
    /// conjunctive run); non-predicate children compile to their own
    /// documents — at most one sits beside the fields, two or more
    /// wrap under mongo's top-level `$and`.
    fn compile(&self, node: &Node, params: &[QueryParameter]) -> Result<Document, ConnectionError> {
        match node {
            Node::Pred(_) => {
                let mut merged = Vec::new();
                merge_into(&mut merged, node, params)?;
                Ok(render_merged(merged))
            }
            // Parity is folded at parse time, so the child is never a
            // `Not`; render its complement once.
            Node::Not(inner) => self.compile_negated(inner, params),
            Node::Or(children) => {
                let mut branches = Vec::new();
                for child in children {
                    branches.push(Bson::Document(self.compile(child, params)?));
                }
                Ok(vec![("$or".to_owned(), Bson::Array(branches))])
            }
            Node::And(children) => {
                let mut merged: Vec<Merged> = Vec::new();
                let mut groups: Vec<Document> = Vec::new();
                for child in children {
                    match child {
                        // `not <predicate>` is an operator slot beside
                        // positive siblings; any negated group compiles
                        // to its own branch document.
                        Node::Pred(_) => merge_into(&mut merged, child, params)?,
                        Node::Not(inner) if matches!(inner.as_ref(), Node::Pred(_)) => {
                            merge_into(&mut merged, child, params)?;
                        }
                        other => groups.push(self.compile(other, params)?),
                    }
                }
                // `$or`/`$and` cannot collide with fields (paths reject
                // `$` at the tokenizer), so appending group documents
                // beside merged fields is unambiguous in shape.
                if groups.is_empty() {
                    return Ok(render_merged(merged));
                }
                if groups.len() == 1 {
                    return Ok(render_merged(merged)
                        .into_iter()
                        .chain(groups.into_iter().next().expect("len checked"))
                        .collect());
                }
                let mut entries = render_merged(merged);
                entries.push((
                    "$and".to_owned(),
                    Bson::Array(groups.into_iter().map(Bson::Document).collect()),
                ));
                Ok(entries)
            }
        }
    }

    /// Renders the COMPLEMENT of a node: `¬node`. A field predicate
    /// negates in place (`{path: {$not: {...}}}`), an `or` negates into
    /// mongo's `$nor` (no branch holds, so the branches keep their
    /// plain compile), and an `and` negates by de Morgan as an `$or`
    /// over the negated conjuncts (`¬child` for each). A leading
    /// `Node::Not` child folds back to the plain compile (`¬¬x = x`);
    /// nested `$or`/`$nor` keys cannot collide with fields because
    /// paths reject `$` at the tokenizer.
    fn compile_negated(
        &self,
        node: &Node,
        params: &[QueryParameter],
    ) -> Result<Document, ConnectionError> {
        match node {
            // ¬(¬x) = x — and a plain predicate must merge NEGATIVELY,
            // so it travels wrapped in a `Not` for the merge rules.
            Node::Not(inner) => self.compile(inner, params),
            Node::Pred(_) => {
                let negated = Node::Not(Box::new(node.clone()));
                let mut merged = Vec::new();
                merge_into(&mut merged, &negated, params)?;
                Ok(render_merged(merged))
            }
            // ¬(a or b) — `$nor` matches documents where NONE of the
            // conditions hold, so the branches are the plain compiles.
            Node::Or(children) => {
                let mut branches = Vec::new();
                for child in children {
                    branches.push(Bson::Document(self.compile(child, params)?));
                }
                Ok(vec![("$nor".to_owned(), Bson::Array(branches))])
            }
            // ¬(a and b) = ¬a or ¬b — every conjunct negates into its
            // own alternative branch.
            Node::And(children) => {
                let mut branches = Vec::new();
                for child in children {
                    branches.push(Bson::Document(self.compile_negated(child, params)?));
                }
                Ok(vec![("$or".to_owned(), Bson::Array(branches))])
            }
        }
    }
}

/// Applies one predicate (possibly negated) to the per-path merge state
/// (binding its values first): the conflict rules — repeated operators,
/// `in` sharing a path with another operator, double `in`, repeated
/// `$not`, and an equality contradicting its own negation.
fn merge_into(
    merged: &mut Vec<Merged>,
    node: &Node,
    params: &[QueryParameter],
) -> Result<(), ConnectionError> {
    // Unwrap the negation; parity is already folded at parse time.
    let (predicate, negative) = match node {
        Node::Pred(predicate) => (predicate, false),
        Node::Not(inner) => match inner.as_ref() {
            Node::Pred(predicate) => (predicate, true),
            _ => {
                return Err(protocol(
                    "internal: only predicates merge per path".to_owned(),
                ));
            }
        },
        _ => {
            return Err(protocol(
                "internal: only predicates merge per path".to_owned(),
            ));
        }
    };
    let path = predicate.path.join(".");
    if negative {
        // The negated operand renders as the `$not` inner doc: a lone
        // equality becomes `$eq` (the shorthand is for field position
        // only) and `in` keeps its list form.
        let inner = match predicate.op {
            Op::In => {
                let values = predicate
                    .values
                    .iter()
                    .map(|value| bind_value(value, params))
                    .collect::<Result<Vec<_>, _>>()?;
                vec![("$in".to_owned(), Bson::Array(values))]
            }
            op => {
                let value = bind_value(&predicate.value, params)?;
                vec![(op.key().to_owned(), value.clone())]
            }
        };
        match merged.iter_mut().find(|m| m.path == predicate.path) {
            Some(entry) => {
                if entry.in_list.is_some() {
                    return Err(protocol(format!(
                        "'in' and 'not' cannot share path '{path}'"
                    )));
                }
                if entry.slots.iter().any(|(slot, _)| *slot == Op::Not) {
                    return Err(protocol(format!(
                        "repeated $not predicate for path '{path}'"
                    )));
                }
                // `a = 1 and not a = 1` is the same contradiction the
                // v1 rules refuse for two equalities.
                if let [(key, value)] = &inner[..]
                    && key == "$eq"
                    && entry
                        .slots
                        .iter()
                        .any(|(slot, stored)| slot == &Op::Eq && stored == value)
                {
                    return Err(protocol(format!(
                        "equality contradicts 'not' at path '{path}'"
                    )));
                }
                entry.slots.push((Op::Not, Bson::Document(inner)));
                Ok(())
            }
            None => {
                merged.push(Merged {
                    path: predicate.path.clone(),
                    slots: vec![(Op::Not, Bson::Document(inner))],
                    in_list: None,
                });
                Ok(())
            }
        }
    } else {
        match predicate.op {
            Op::In => {
                let values = predicate
                    .values
                    .iter()
                    .map(|value| bind_value(value, params))
                    .collect::<Result<Vec<_>, _>>()?;
                match merged.iter_mut().find(|m| m.path == predicate.path) {
                    Some(_) => Err(protocol(format!(
                        "conflicting 'in' predicates for path '{path}'"
                    ))),
                    None => {
                        merged.push(Merged {
                            path: predicate.path.clone(),
                            slots: Vec::new(),
                            in_list: Some(values),
                        });
                        Ok(())
                    }
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
                        // Mirror orientation: `not a = 1 and a = 1`.
                        if op == Op::Eq
                            && entry
                                .slots
                                .iter()
                                .any(|(_, stored)| not_slot_eq_operand(stored) == Some(&value))
                        {
                            return Err(protocol(format!(
                                "equality contradicts 'not' at path '{path}'"
                            )));
                        }
                        entry.slots.push((op, value));
                        Ok(())
                    }
                    None => {
                        merged.push(Merged {
                            path: predicate.path.clone(),
                            slots: vec![(op, value)],
                            in_list: None,
                        });
                        Ok(())
                    }
                }
            }
        }
    }
}

/// The inner `$eq` operand of a `$not` slot, when the negated doc holds
/// exactly an equality (used by the contradiction check).
fn not_slot_eq_operand(slot: &Bson) -> Option<&Bson> {
    match slot {
        Bson::Document(entries) => match entries[..] {
            [(ref key, ref value)] if key == "$eq" => Some(value),
            _ => None,
        },
        _ => None,
    }
}

/// Renders the per-path merge state into the final field entries.
fn render_merged(merged: Vec<Merged>) -> Document {
    merged
        .into_iter()
        .map(|entry| {
            let field = entry.path.join(".");
            let value = if entry.slots.len() == 1
                && entry.slots[0].0 == Op::Eq
                && entry.in_list.is_none()
            {
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
        .collect()
}

fn bind_value(value: &Value, params: &[QueryParameter]) -> Result<Bson, ConnectionError> {
    match value {
        Value::Literal(literal) => Ok(literal.clone()),
        Value::Param(index) => {
            let parameter = params
                .get(*index)
                .ok_or_else(|| protocol(format!("missing parameter #{}", index + 1)))?;
            bson_value(parameter)
        }
    }
}

/// Maps one SPI parameter to its BSON value. Mongo compares numbers
/// numerically across int widths, so the SPI's widest-integer rule
/// lands on `Int64`; `BigDecimal` parses to exact BSON `decimal128`
/// (invalid decimal text is a named bind error, checked before any
/// wire round-trip).
fn bson_value(parameter: &QueryParameter) -> Result<Bson, ConnectionError> {
    Ok(match parameter {
        QueryParameter::Null => Bson::Null,
        QueryParameter::Boolean(value) => Bson::Boolean(*value),
        // Mongo compares numerically across int widths, so the SPI's
        // widest-integer rule lands on Int64.
        QueryParameter::Integer(value) => Bson::Int64(*value),
        QueryParameter::Float(value) => Bson::Double(*value),
        QueryParameter::Text(value) => Bson::String(value.clone()),
        QueryParameter::Binary(value) => Bson::Binary(value.clone()),
        // The decode side of `decimal128` (BSON type 0x13) produced
        // `TypedValue::BigDecimal`; the bind side runs the same
        // parse in reverse, so the filter docs and stored documents
        // share one encoding. `Float` stays `Double` (binary float);
        // exact decimal comparisons need this variant.
        QueryParameter::BigDecimal(text) => Bson::Decimal128(crate::bson::parse_decimal128(text)?),
    })
}

// ---------- parser ----------

/// Parses the full filter text of a `with` clause.
pub fn parse_filter(text: &str) -> Result<Filter, ConnectionError> {
    let mut tokens = Tokenizer::new(text);
    if tokens.peek()?.is_none() {
        return Err(protocol("empty filter".to_owned()));
    }
    let mut placeholders = 0usize;
    let root = parse_or(&mut tokens, &mut placeholders, 0)?;
    // Everything above belongs to the grammar; trailing tokens are
    // structural garbage.
    if tokens.peek()?.is_some() {
        return Err(protocol("expected end of filter".to_owned()));
    }

    Ok(Filter { root, placeholders })
}

/// `and_expr ('or' and_expr)*` — the lowest-precedence connector.
fn parse_or(
    tokens: &mut Tokenizer,
    placeholders: &mut usize,
    depth: usize,
) -> Result<Node, ConnectionError> {
    let mut terms = vec![parse_and(tokens, placeholders, depth)?];
    while matches!(
        tokens.peek()?,
        Some(Token::Ident(ref word)) if word.eq_ignore_ascii_case("or")
    ) {
        tokens.next()?; // the 'or'
        terms.push(parse_and(tokens, placeholders, depth)?);
    }
    // A one-term `or` unwrap keeps a bare predicate tree from wearing
    // a pointless wrapper.
    Ok(if terms.len() == 1 {
        terms.pop().expect("len checked")
    } else {
        Node::Or(terms)
    })
}

/// `atom ( ('and' | ',') atom )*` — `and` binds tighter than `or`.
fn parse_and(
    tokens: &mut Tokenizer,
    placeholders: &mut usize,
    depth: usize,
) -> Result<Node, ConnectionError> {
    let mut atoms = vec![parse_atom(tokens, placeholders, depth)?];
    loop {
        match tokens.peek()? {
            // The comma stays as the SQL-style explicit separator.
            Some(Token::Comma) => {
                tokens.next()?;
            }
            Some(Token::Ident(ref word)) if word.eq_ignore_ascii_case("and") => {
                tokens.next()?;
            }
            _ => break,
        }
        atoms.push(parse_atom(tokens, placeholders, depth)?);
    }
    if atoms.len() == 1 {
        return Ok(atoms.pop().expect("len checked"));
    }
    // A parenthesized and-chain flattens one level so `(n = 1 and
    // m = 2)` merges beside its neighbors instead of nesting.
    let mut children = Vec::with_capacity(atoms.len());
    for atom in atoms {
        match atom {
            Node::And(inner) => children.extend(inner),
            other => children.push(other),
        }
    }
    Ok(Node::And(children))
}

/// `('not')? core` — the unary folds by parity in place, so an even
/// chain is identity and an odd chain wraps its core in `Node::Not`
/// exactly once (consecutive `not`s never recurse into the parser).
fn parse_atom(
    tokens: &mut Tokenizer,
    placeholders: &mut usize,
    depth: usize,
) -> Result<Node, ConnectionError> {
    let mut negations = 0usize;
    while matches!(
        tokens.peek()?,
        Some(Token::Ident(ref word)) if word.eq_ignore_ascii_case("not")
    ) {
        tokens.next()?; // a 'not'
        negations += 1;
    }
    let inner = if matches!(tokens.peek()?, Some(Token::LParen)) {
        if depth >= MAX_GROUP_DEPTH {
            return Err(protocol(format!(
                "parenthesized groups nest deeper than {MAX_GROUP_DEPTH}"
            )));
        }
        tokens.next()?; // the '('
        let inner = parse_or(tokens, placeholders, depth + 1)?;
        match tokens.next()? {
            Some(Token::RParen) => inner,
            _ => return Err(protocol("expected ')' to close the group".to_owned())),
        }
    } else if matches!(tokens.peek()?, Some(Token::RParen)) {
        return Err(protocol("empty '(...)' group".to_owned()));
    } else {
        Node::Pred(parse_predicate(tokens, placeholders)?)
    };
    Ok(if negations % 2 == 1 {
        Node::Not(Box::new(inner))
    } else {
        inner
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
        // Note: `not` can only reach a dotted path position here
        // (a segment after a dot); a leading `not` is consumed as the
        // unary keyword in `parse_atom`, so it is a reserved field.
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
/// exponents render as `Double`. The shape itself is shared with the
/// insert document literal (`bson::number_literal`); only the
/// statement-context prefix belongs to the filter.
fn number_bson(raw: &str) -> Result<Bson, ConnectionError> {
    crate::bson::number_literal(raw).map_err(|error| match error {
        ConnectionError::Protocol(message) => protocol(message),
        other => other,
    })
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

    #[test]
    fn big_decimal_binds_to_exact_decimal128() {
        // The bind side of `decimal128` runs the same parse the decode
        // side produced `TypedValue::BigDecimal` from, so filter docs
        // and stored documents share one encoding.
        assert_eq!(
            bind("v = ?", &[QueryParameter::BigDecimal("123.456".to_owned())]),
            vec![(
                "v".to_owned(),
                Bson::Decimal128(crate::bson::parse_decimal128("123.456").expect("literal"))
            )]
        );
        // Trailing-zero scale is carried (exactness is the point).
        assert_eq!(
            bind(
                "v = ? and w = ?",
                &[
                    QueryParameter::BigDecimal("1.50".to_owned()),
                    QueryParameter::BigDecimal("-0.0".to_owned()),
                ]
            ),
            vec![
                (
                    "v".to_owned(),
                    Bson::Decimal128(crate::bson::parse_decimal128("1.50").expect("literal"))
                ),
                (
                    "w".to_owned(),
                    Bson::Decimal128(crate::bson::parse_decimal128("-0.0").expect("literal"))
                ),
            ]
        );
        // Invalid decimal text is a named bind-time protocol error,
        // checked BEFORE any wire round-trip.
        let filter = parse_filter("v = ?").expect("parses");
        assert!(matches!(
            filter.document(&[QueryParameter::BigDecimal("oops".to_owned())]),
            Err(ConnectionError::Protocol(ref message)) if message.contains("invalid decimal128 literal")
        ));
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
    fn or_chains_render_branch_documents_without_precedence_confusion() {
        // A bare two-branch or.
        assert_eq!(
            parse("n = 5 or n = 6"),
            vec![(
                "$or".to_owned(),
                Bson::Array(vec![
                    Bson::Document(vec![("n".to_owned(), Bson::Int32(5))]),
                    Bson::Document(vec![("n".to_owned(), Bson::Int32(6))]),
                ])
            )]
        );
        // `and` binds tighter: a=... and b=... or c=... groups the
        // conjunction into the first branch.
        let or = |text: &str| match parse(text).pop() {
            Some((key, Bson::Array(branches))) if key == "$or" => branches,
            other => panic!("expected an $or array, got {other:?}"),
        };
        assert_eq!(
            or("flag = true and n < 5 or tag = 'a'"),
            vec![
                Bson::Document(vec![
                    ("flag".to_owned(), Bson::Boolean(true)),
                    (
                        "n".to_owned(),
                        Bson::Document(vec![("$lt".to_owned(), Bson::Int32(5))])
                    ),
                ]),
                Bson::Document(vec![("tag".to_owned(), Bson::String("a".to_owned()))]),
            ]
        );
        assert_eq!(
            or("a = 1 or b = 2 and c = 3"),
            vec![
                Bson::Document(vec![("a".to_owned(), Bson::Int32(1))]),
                Bson::Document(vec![
                    ("b".to_owned(), Bson::Int32(2)),
                    ("c".to_owned(), Bson::Int32(3)),
                ]),
            ]
        );
    }

    #[test]
    fn parenthesized_groups_cut_anywhere() {
        // A group beside a plain predicate.
        assert_eq!(
            parse("(n > 1 or tag = 'a') and flag = true"),
            vec![
                ("flag".to_owned(), Bson::Boolean(true)),
                (
                    "$or".to_owned(),
                    Bson::Array(vec![
                        Bson::Document(vec![(
                            "n".to_owned(),
                            Bson::Document(vec![("$gt".to_owned(), Bson::Int32(1))])
                        )]),
                        Bson::Document(vec![("tag".to_owned(), Bson::String("a".to_owned()))]),
                    ])
                ),
            ]
        );
        // Merging keeps working INSIDE a group.
        assert_eq!(
            parse("(n > 1 and n < 5) or tag in ('z')"),
            vec![(
                "$or".to_owned(),
                Bson::Array(vec![
                    Bson::Document(vec![(
                        "n".to_owned(),
                        Bson::Document(vec![
                            ("$gt".to_owned(), Bson::Int32(1)),
                            ("$lt".to_owned(), Bson::Int32(5)),
                        ])
                    )]),
                    Bson::Document(vec![(
                        "tag".to_owned(),
                        Bson::Document(vec![(
                            "$in".to_owned(),
                            Bson::Array(vec![Bson::String("z".to_owned())])
                        )])
                    )]),
                ])
            )]
        );
        // Two or-groups in one conjunction wrap under mongo's `$and`.
        assert_eq!(
            parse("(a = 1 or b = 2) and (c = 3 or d = 4)"),
            vec![(
                "$and".to_owned(),
                Bson::Array(vec![
                    Bson::Document(vec![(
                        "$or".to_owned(),
                        Bson::Array(vec![
                            Bson::Document(vec![("a".to_owned(), Bson::Int32(1))]),
                            Bson::Document(vec![("b".to_owned(), Bson::Int32(2))]),
                        ])
                    )]),
                    Bson::Document(vec![(
                        "$or".to_owned(),
                        Bson::Array(vec![
                            Bson::Document(vec![("c".to_owned(), Bson::Int32(3))]),
                            Bson::Document(vec![("d".to_owned(), Bson::Int32(4))]),
                        ])
                    )]),
                ])
            )]
        );
        // A parenthesized and-chain flattens: `(x = 1) and (flag = false,
        // tag = 'z')` merges into one document.
        assert_eq!(
            parse("(x = 1) and (flag = false, tag = 'z')"),
            vec![
                ("x".to_owned(), Bson::Int32(1)),
                ("flag".to_owned(), Bson::Boolean(false)),
                ("tag".to_owned(), Bson::String("z".to_owned())),
            ]
        );
        // A nested or branch.
        assert_eq!(
            parse("(a = 1 or (b = 2 and c = 3)) or d = 4")
                .into_iter()
                .find(|(key, _)| key == "$or")
                .map(|(_, value)| value),
            Some(Bson::Array(vec![
                Bson::Document(vec![(
                    "$or".to_owned(),
                    Bson::Array(vec![
                        Bson::Document(vec![("a".to_owned(), Bson::Int32(1))]),
                        Bson::Document(vec![
                            ("b".to_owned(), Bson::Int32(2)),
                            ("c".to_owned(), Bson::Int32(3)),
                        ]),
                    ])
                )]),
                Bson::Document(vec![("d".to_owned(), Bson::Int32(4))]),
            ]))
        );
    }

    #[test]
    fn params_bind_in_first_seen_order_across_branches() {
        let document = bind(
            "(tag = ? or n > ?) and ok = ?",
            &[
                QueryParameter::Text("b".to_owned()),
                QueryParameter::Integer(2),
                QueryParameter::Boolean(true),
            ],
        );
        // Expected shape: {ok: true, $or: [{tag: 'b'}, {n: {$gt: 2}}]}.
        assert_eq!(
            document
                .iter()
                .find(|(key, _)| key == "ok")
                .map(|(_, value)| value.clone()),
            Some(Bson::Boolean(true))
        );
        let or = match document.iter().find(|(key, _)| key == "$or") {
            Some((_, Bson::Array(branches))) => branches,
            other => panic!("expected $or, got {other:?}"),
        };
        match &or[0] {
            Bson::Document(branch) => assert_eq!(
                branch.iter().next(),
                Some(&("tag".to_owned(), Bson::String("b".to_owned()))),
                "first '?' belongs to the first branch"
            ),
            other => panic!("expected a branch document, got {other:?}"),
        }
        match &or[1] {
            Bson::Document(branch) => assert_eq!(
                branch.iter().next(),
                Some(&(
                    "n".to_owned(),
                    Bson::Document(vec![("$gt".to_owned(), Bson::Int64(2))])
                )),
                "second '?' belongs to the second branch"
            ),
            other => panic!("expected a branch document, got {other:?}"),
        }
        // Arity still exact across the whole tree: dropping one fails.
        let filter = parse_filter("n = ? or tag = ?").expect("parses");
        assert!(matches!(
            filter.document(&[QueryParameter::Integer(1)]),
            Err(ConnectionError::Protocol(ref message)) if message.contains("expects 2 parameter")
        ));
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
        // Conflicts are scoped to each conjunctive run: the same path
        // in different or-branches is free (each branch merges alone),
        // but a conflict INSIDE one branch still fails.
        let _ = parse("n = 1 or n = 2");
        assert!(error("(n = 1 and n = 2) or tag = 'a'").contains("repeated equality"));
    }

    #[test]
    fn syntax_errors_name_the_problem() {
        assert!(error("").contains("empty filter"));
        assert!(error("n").contains("missing an operator"));
        assert!(error("n =").contains("expected a literal"));
        assert!(error("n = and").contains("bare identifier"));
        assert!(error("n = 'open").contains("never closed"));
        assert!(error("n = 1!(").contains("'!' must form the '!='"));
        assert!(error("n = 1 2").contains("expected end of filter"));
        assert!(error("n in ('a'").contains("expected ',' or ')'"));
        assert!(error("n = -").contains("invalid numeric literal"));
        assert!(error("n = 1e+").contains("invalid numeric literal"));
        assert!(error("a..b = 1").contains("expected a field name"));
        assert!(error("n in 3").contains("expected '(' after 'in'"));
        // The tokenizer never even forms a '$'-prefixed identifier.
        assert!(error("$where = 1").contains("unexpected character '$'"));
        // Structural garbage after the grammar ends.
        assert!(error("n = 1) and flag = true").contains("expected end of filter"));
        assert!(error("n = 1 and (").contains("expected a field name"));
        assert!(error("n = 1 and (x = 2").contains("expected ')'"));
        assert!(error("n = 1 and ()").contains("empty '(...)' group"));
        // A trailing `not` and a `not` in operator position fail with
        // the predicate-position messages.
        assert!(error("n = 1 and not").contains("expected a field name"));
        assert!(error("n not 1").contains("unsupported operator"));
    }

    #[test]
    fn not_negates_field_predicates_in_place() {
        // A lone negated equality: `$eq` (the shorthand is for field
        // position only, never inside `$not`).
        assert_eq!(
            parse("not n = 1"),
            vec![(
                "n".to_owned(),
                Bson::Document(vec!((
                    "$not".to_owned(),
                    Bson::Document(vec![("$eq".to_owned(), Bson::Int32(1))])
                )))
            )]
        );
        // A negated range keeps its operator doc.
        assert_eq!(
            parse("not n > 1"),
            vec![(
                "n".to_owned(),
                Bson::Document(vec![(
                    "$not".to_owned(),
                    Bson::Document(vec![("$gt".to_owned(), Bson::Int32(1))])
                )])
            )]
        );
        // A negated `in` keeps its list inside `$not`.
        assert_eq!(
            parse("not n in (1, 2)"),
            vec![(
                "n".to_owned(),
                Bson::Document(vec![(
                    "$not".to_owned(),
                    Bson::Document(vec![(
                        "$in".to_owned(),
                        Bson::Array(vec![Bson::Int32(1), Bson::Int32(2)])
                    )])
                )])
            )]
        );
        // `not` binds tighter than every connector: only `a = 1`
        // negates here.
        assert_eq!(
            parse("not a = 1 or b = 2"),
            vec![(
                "$or".to_owned(),
                Bson::Array(vec![
                    Bson::Document(vec![(
                        "a".to_owned(),
                        Bson::Document(vec![(
                            "$not".to_owned(),
                            Bson::Document(vec![("$eq".to_owned(), Bson::Int32(1))])
                        )])
                    )]),
                    Bson::Document(vec![("b".to_owned(), Bson::Int32(2))]),
                ])
            )]
        );
    }

    #[test]
    fn not_folds_by_parity_and_negates_groups_by_denior() {
        // Double negation: identity on the compiled shape.
        assert_eq!(parse("not not n = 3"), parse("n = 3"));
        assert_eq!(
            parse("not not n = 3"),
            vec![("n".to_owned(), Bson::Int32(3))]
        );
        // `not (a or b)` renders mongo's `$nor` over the plain branches.
        assert_eq!(
            parse("not (tag = 'a' or flag = false)"),
            vec![(
                "$nor".to_owned(),
                Bson::Array(vec![
                    Bson::Document(vec![("tag".to_owned(), Bson::String("a".to_owned()))]),
                    Bson::Document(vec![("flag".to_owned(), Bson::Boolean(false))]),
                ])
            )]
        );
        // `not (a and b)` = de Morgan: `$or` over the negated conjuncts
        // (an `and` inside a negation cannot be a single field doc).
        assert_eq!(
            parse("not (n > 1 and flag = true)"),
            vec![(
                "$or".to_owned(),
                Bson::Array(vec![
                    Bson::Document(vec![(
                        "n".to_owned(),
                        Bson::Document(vec![(
                            "$not".to_owned(),
                            Bson::Document(vec![("$gt".to_owned(), Bson::Int32(1))])
                        )])
                    )]),
                    Bson::Document(vec![(
                        "flag".to_owned(),
                        Bson::Document(vec![(
                            "$not".to_owned(),
                            Bson::Document(vec![("$eq".to_owned(), Bson::Boolean(true))])
                        )])
                    )]),
                ])
            )]
        );
        // A negated or-group beside plain predicates: the `$nor` doc
        // chains beside the fields (one group, no `$and` wrapper).
        assert_eq!(
            parse("flag = true and not (tag = 'a' or tag = 'b')"),
            vec![
                ("flag".to_owned(), Bson::Boolean(true)),
                (
                    "$nor".to_owned(),
                    Bson::Array(vec![
                        Bson::Document(vec![("tag".to_owned(), Bson::String("a".to_owned()))]),
                        Bson::Document(vec![("tag".to_owned(), Bson::String("b".to_owned()))]),
                    ])
                ),
            ]
        );
        // Triple `not` folds back to one negation.
        assert_eq!(parse("not not not n = 1"), parse("not n = 1"));
    }

    #[test]
    fn negated_predicates_merge_and_conflict_like_positive_ones() {
        // A `$not` slot merges beside positive operators on the path.
        assert_eq!(
            parse("a = 1 and not a = 2"),
            vec![(
                "a".to_owned(),
                Bson::Document(vec![
                    ("$eq".to_owned(), Bson::Int32(1)),
                    (
                        "$not".to_owned(),
                        Bson::Document(vec![("$eq".to_owned(), Bson::Int32(2))])
                    ),
                ])
            )]
        );
        // The mirrored text renders the mirrored (equivalent) shape.
        assert_eq!(
            parse("not a = 2 and a = 1"),
            vec![(
                "a".to_owned(),
                Bson::Document(vec![
                    (
                        "$not".to_owned(),
                        Bson::Document(vec![("$eq".to_owned(), Bson::Int32(2))])
                    ),
                    ("$eq".to_owned(), Bson::Int32(1)),
                ])
            )]
        );
        // `a = 1 and not a = 1` is the v1 contradiction, refused.
        assert!(error("a = 1 and not a = 1").contains("equality contradicts 'not'"));
        assert!(error("not a = 1 and a = 1").contains("equality contradicts 'not'"));
        // Two negations on the same path cannot share one operator doc.
        assert!(error("not a > 1 and not a < 5").contains("repeated $not"));
        // A negation beside `in` refuses the shared path (v1 rule).
        assert!(error("a in (1, 2) and not a = 3").contains("cannot share path"));
        assert!(error("not a = 3 and a in (1, 2)").contains("conflicting 'in'"));
        // The contradiction check binds VALUES, so params work.
        let filter = parse_filter("a = ? and not a = ?");
        assert!(filter.is_ok());
        let conflict = parse_filter("a = ? and not a = ?")
            .expect("parses")
            .document(&[QueryParameter::Integer(7), QueryParameter::Integer(7)]);
        assert!(matches!(
            conflict,
            Err(ConnectionError::Protocol(ref message)) if message.contains("contradicts")
        ));
        // Same path in different or-branches stays independent.
        let _ = parse("not a = 1 or not a = 2");
    }

    const MANY_PARENS: &str = "((((((((((((((((n = 1))))))))))))))))";
    const TOO_MANY_PARENS: &str = "(((((((((((((((((n = 1))))))))))))))))"; // 17

    #[test]
    fn groups_nest_up_to_the_cap_and_not_one_more() {
        assert_eq!(parse(MANY_PARENS), vec![("n".to_owned(), Bson::Int32(1))]);
        assert!(error(TOO_MANY_PARENS).contains("nest deeper than 16"));
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
