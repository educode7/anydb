//! JSON document literal for the `insert <collection> with <document>`
//! statement (the write-side sibling of the `find ... with <filter>`
//! text in `filter`).
//!
//! The accepted text is RFC 8259 JSON restricted to an OBJECT at the
//! top level: mongo inserts documents, never arrays or scalars. Nested
//! objects and arrays, double-quoted keys and strings with JSON
//! backslash escapes, numbers, `true`, `false` and `null`. Numbers take
//! the same BSON shape as a filter literal (shared `number_literal`),
//! so `1` binds as `Int32`, `9223372036854775807` as `Int64` and
//! `1.5` / `1e3` as `Double`.
//!
//! Everything is validated client-side: a syntax failure is
//! `ConnectionError::Protocol` raised before any wire round-trip, which
//! is the write-side analogue of the filter parser's arity and syntax
//! errors. Unlike a filter this text takes NO `?` placeholders — the
//! statement carries no parameters at all.

use anydb_shared::ConnectionError;

use crate::bson::{Bson, Document, number_literal};

/// Parses one JSON object into a BSON document.
pub fn parse_document_literal(text: &str) -> Result<Document, ConnectionError> {
    let mut parser = Parser::new(text);
    parser.skip_whitespace();
    if parser.peek() != Some('{') {
        return Err(protocol(
            "expected a JSON object at the top level of an insert document".to_owned(),
        ));
    }
    let document = parser.parse_object()?;
    parser.skip_whitespace();
    if parser.peek().is_some() {
        return Err(protocol(
            "unexpected trailing text after the JSON object".to_owned(),
        ));
    }
    Ok(document)
}

fn protocol(message: String) -> ConnectionError {
    ConnectionError::Protocol(format!("mongo insert document: {message}"))
}

/// Re-contextualizes a shared helper's error (the numeric shape lives
/// in `bson`, the statement prefix belongs to the caller).
fn contextualize(error: ConnectionError) -> ConnectionError {
    match error {
        ConnectionError::Protocol(message) => protocol(message),
        other => other,
    }
}

/// Recursive-descent scan over the raw characters: position-aware
/// errors, no lookahead beyond one character, no dependencies.
struct Parser {
    text: Vec<char>,
    position: usize,
}

impl Parser {
    fn new(text: &str) -> Self {
        Self {
            text: text.chars().collect(),
            position: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.text.get(self.position).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let found = self.peek();
        if found.is_some() {
            self.position += 1;
        }
        found
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(found) if found.is_whitespace()) {
            self.position += 1;
        }
    }

    /// `object := '{' [ field (',' field)* ] '}'`, with the trailing
    /// comma rejected because the loop demands a field name after it.
    fn parse_object(&mut self) -> Result<Document, ConnectionError> {
        debug_assert_eq!(self.peek(), Some('{'));
        self.position += 1;
        let mut document = Document::new();
        self.skip_whitespace();
        if self.peek() == Some('}') {
            self.position += 1;
            return Ok(document);
        }
        loop {
            self.skip_whitespace();
            let key = match self.peek() {
                Some('"') => self.parse_string()?,
                _ => {
                    return Err(protocol(
                        "expected a field name (a double-quoted JSON key)".to_owned(),
                    ));
                }
            };
            self.skip_whitespace();
            if self.peek() != Some(':') {
                return Err(protocol(format!(
                    "expected ':' after the field name '{key}'"
                )));
            }
            self.position += 1;
            self.skip_whitespace();
            let value = self.parse_value()?;
            document.push((key.clone(), value));
            self.skip_whitespace();
            match self.peek() {
                Some(',') => self.position += 1,
                Some('}') => {
                    self.position += 1;
                    return Ok(document);
                }
                None => {
                    return Err(protocol(format!(
                        "expected '}}' to close the object holding the field '{key}'"
                    )));
                }
                Some(found) => {
                    return Err(protocol(format!(
                        "unexpected '{found}': expected ',' or '}}' after the value of the field '{key}'"
                    )));
                }
            }
        }
    }

    /// `array := '[' [ value (',' value)* ] ']'`.
    fn parse_array(&mut self) -> Result<Vec<Bson>, ConnectionError> {
        debug_assert_eq!(self.peek(), Some('['));
        self.position += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(']') {
            self.position += 1;
            return Ok(items);
        }
        loop {
            self.skip_whitespace();
            items.push(self.parse_value()?);
            self.skip_whitespace();
            match self.peek() {
                Some(',') => self.position += 1,
                Some(']') => {
                    self.position += 1;
                    return Ok(items);
                }
                None => return Err(protocol("expected ']' to close the array".to_owned())),
                Some(found) => {
                    return Err(protocol(format!(
                        "unexpected '{found}': expected ',' or ']' after an array value"
                    )));
                }
            }
        }
    }

    fn parse_value(&mut self) -> Result<Bson, ConnectionError> {
        match self.peek() {
            Some('{') => Ok(Bson::Document(self.parse_object()?)),
            Some('[') => Ok(Bson::Array(self.parse_array()?)),
            Some('"') => Ok(Bson::String(self.parse_string()?)),
            Some(found) if found == '-' || found.is_ascii_digit() => self.parse_number(),
            Some(found) if found.is_ascii_alphabetic() => {
                let word = self.read_identifier();
                match word.as_str() {
                    "true" => Ok(Bson::Boolean(true)),
                    "false" => Ok(Bson::Boolean(false)),
                    "null" => Ok(Bson::Null),
                    _ => Err(protocol(format!(
                        "expected a value, found the bare identifier '{word}'"
                    ))),
                }
            }
            Some(found) => Err(protocol(format!("expected a value, found '{found}'"))),
            None => Err(protocol(
                "expected a value, found the end of the document text".to_owned(),
            )),
        }
    }

    /// Strict JSON number scan (sign, integer part, fraction,
    /// exponent — each part's digits required where the grammar
    /// requires them); the BSON shape comes from the shared helper.
    fn parse_number(&mut self) -> Result<Bson, ConnectionError> {
        let start = self.position;
        if self.peek() == Some('-') {
            self.position += 1;
        }
        let integer_start = self.position;
        self.skip_digits();
        if self.position == integer_start {
            return Err(protocol(
                "invalid number literal: expected a digit after '-'".to_owned(),
            ));
        }
        if self.peek() == Some('.') {
            self.position += 1;
            let fraction_start = self.position;
            self.skip_digits();
            if self.position == fraction_start {
                return Err(protocol(
                    "invalid number literal: expected a digit after '.'".to_owned(),
                ));
            }
        }
        if matches!(self.peek(), Some('e') | Some('E')) {
            self.position += 1;
            if matches!(self.peek(), Some('+') | Some('-')) {
                self.position += 1;
            }
            let exponent_start = self.position;
            self.skip_digits();
            if self.position == exponent_start {
                return Err(protocol(
                    "invalid number literal: expected a digit in the exponent".to_owned(),
                ));
            }
        }
        let raw: String = self.text[start..self.position].iter().collect();
        number_literal(&raw).map_err(contextualize)
    }

    fn skip_digits(&mut self) {
        while matches!(self.peek(), Some(found) if found.is_ascii_digit()) {
            self.position += 1;
        }
    }

    fn read_identifier(&mut self) -> String {
        let start = self.position;
        while matches!(self.peek(), Some(found) if found.is_ascii_alphanumeric() || found == '_') {
            self.position += 1;
        }
        self.text[start..self.position].iter().collect()
    }

    /// `string := '"' chars* '"'` with JSON backslash escapes; the
    /// opening quote is the caller's contract.
    fn parse_string(&mut self) -> Result<String, ConnectionError> {
        debug_assert_eq!(self.peek(), Some('"'));
        self.position += 1;
        let mut text = String::new();
        loop {
            match self.peek() {
                None => return Err(protocol("unterminated string literal".to_owned())),
                Some('"') => {
                    self.position += 1;
                    return Ok(text);
                }
                Some('\\') => {
                    self.position += 1;
                    text.push_str(&self.read_escape()?);
                }
                Some(found) => {
                    text.push(found);
                    self.position += 1;
                }
            }
        }
    }

    fn read_escape(&mut self) -> Result<String, ConnectionError> {
        let Some(escape) = self.bump() else {
            return Err(protocol("unterminated string literal".to_owned()));
        };
        match escape {
            '"' => Ok(String::from('"')),
            '\\' => Ok(String::from('\\')),
            '/' => Ok(String::from('/')),
            'b' => Ok(String::from('\u{8}')),
            'f' => Ok(String::from('\u{c}')),
            'n' => Ok(String::from('\n')),
            'r' => Ok(String::from('\r')),
            't' => Ok(String::from('\t')),
            'u' => self.read_unicode_escape(),
            other => Err(protocol(format!("invalid string escape '\\{other}'"))),
        }
    }

    /// `\uXXXX`, including a surrogate pair: JSON encodes astral
    /// characters as `high low`, and a lone half is a protocol error
    /// instead of a replacement character.
    fn read_unicode_escape(&mut self) -> Result<String, ConnectionError> {
        let first = self.read_hex_quad()?;
        let scalar = if (0xD800..=0xDBFF).contains(&first) {
            if self.peek() != Some('\\') {
                return Err(protocol(
                    "a high surrogate \\u escape must be followed by a low surrogate".to_owned(),
                ));
            }
            self.position += 1;
            if self.peek() != Some('u') {
                return Err(protocol(
                    "a high surrogate \\u escape must be followed by a low surrogate".to_owned(),
                ));
            }
            self.position += 1;
            let second = self.read_hex_quad()?;
            if !(0xDC00..=0xDFFF).contains(&second) {
                return Err(protocol(
                    "a high surrogate \\u escape must be followed by a low surrogate".to_owned(),
                ));
            }
            0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
        } else if (0xDC00..=0xDFFF).contains(&first) {
            return Err(protocol(
                "a low surrogate \\u escape has no preceding high surrogate".to_owned(),
            ));
        } else {
            first
        };
        char::from_u32(scalar)
            .map(|found| found.to_string())
            .ok_or_else(|| protocol(format!("invalid '\\u' escape value {scalar:#x}")))
    }

    fn read_hex_quad(&mut self) -> Result<u32, ConnectionError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let Some(digit) = self.peek().and_then(|found| found.to_digit(16)) else {
                return Err(protocol(
                    "expected four hex digits after the '\\u' escape".to_owned(),
                ));
            };
            value = value * 16 + digit;
            self.position += 1;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(text: &str) -> Document {
        parse_document_literal(text).expect("document literal parses")
    }

    fn protocol_error(text: &str) -> String {
        match parse_document_literal(text) {
            Err(ConnectionError::Protocol(message)) => message,
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }

    // ---------- values ----------

    #[test]
    fn scalar_values_take_their_bson_shape() {
        let parsed = document(
            r#"{"int":1,"big":9223372036854775807,"double":1.5,"exp":1e3,"text":"hi","yes":true,"no":false,"nothing":null}"#,
        );
        assert_eq!(
            parsed,
            vec![
                ("int".to_owned(), Bson::Int32(1)),
                ("big".to_owned(), Bson::Int64(i64::MAX)),
                ("double".to_owned(), Bson::Double(1.5)),
                ("exp".to_owned(), Bson::Double(1000.0)),
                ("text".to_owned(), Bson::String("hi".to_owned())),
                ("yes".to_owned(), Bson::Boolean(true)),
                ("no".to_owned(), Bson::Boolean(false)),
                ("nothing".to_owned(), Bson::Null),
            ]
        );
    }

    #[test]
    fn field_order_is_preserved() {
        let parsed = document(r#"{"z":1,"a":2,"m":3}"#);
        let keys: Vec<&str> = parsed.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, ["z", "a", "m"]);
    }

    #[test]
    fn nested_objects_and_arrays_parse() {
        let parsed =
            document(r#"{"group":{"components":[{"code":1},{"code":2}],"tags":["a","b"]}}"#);
        let expected: Document = vec![(
            "group".to_owned(),
            Bson::Document(vec![
                (
                    "components".to_owned(),
                    Bson::Array(vec![
                        Bson::Document(vec![("code".to_owned(), Bson::Int32(1))]),
                        Bson::Document(vec![("code".to_owned(), Bson::Int32(2))]),
                    ]),
                ),
                (
                    "tags".to_owned(),
                    Bson::Array(vec![
                        Bson::String("a".to_owned()),
                        Bson::String("b".to_owned()),
                    ]),
                ),
            ]),
        )];
        assert_eq!(parsed, expected);
    }

    #[test]
    fn empty_object_is_an_empty_document() {
        assert_eq!(document("{}"), Vec::new());
    }

    #[test]
    fn surrounding_and_inner_whitespace_is_ignored() {
        assert_eq!(
            document("  { \"a\" :  1 ,\n\t \"b\" : [ 2 , 3 ] }  "),
            vec![
                ("a".to_owned(), Bson::Int32(1)),
                (
                    "b".to_owned(),
                    Bson::Array(vec![Bson::Int32(2), Bson::Int32(3)])
                ),
            ]
        );
    }

    #[test]
    fn json_string_escapes_decode() {
        assert_eq!(
            document(r#"{"text":"quote:\" backslash:\\ newline:\n tab:\t"}"#),
            vec![(
                "text".to_owned(),
                Bson::String("quote:\" backslash:\\ newline:\n tab:\t".to_owned())
            )]
        );
    }

    #[test]
    fn a_json_key_may_be_any_unicode_text() {
        assert_eq!(
            document(r#"{"Mercancías Restringidas - IPEN":"AUTH2"}"#),
            vec![(
                "Mercancías Restringidas - IPEN".to_owned(),
                Bson::String("AUTH2".to_owned())
            )]
        );
    }

    // ---------- shape errors ----------

    #[test]
    fn an_empty_text_is_an_error() {
        assert!(protocol_error("").contains("expected a JSON object"));
    }

    #[test]
    fn a_top_level_array_is_an_error() {
        assert!(protocol_error(r#"[{"a":1}]"#).contains("expected a JSON object"));
    }

    #[test]
    fn a_top_level_scalar_is_an_error() {
        assert!(protocol_error("1").contains("expected a JSON object"));
    }

    // ---------- syntax errors ----------

    #[test]
    fn trailing_garbage_is_an_error() {
        assert!(protocol_error(r#"{"a":1} x"#).contains("unexpected trailing text"));
    }

    #[test]
    fn a_missing_value_is_an_error() {
        assert!(protocol_error(r#"{"a":}"#).contains("expected a value"));
    }

    #[test]
    fn a_missing_colon_is_an_error() {
        assert!(protocol_error(r#"{"a" 1}"#).contains("expected ':'"));
    }

    #[test]
    fn a_trailing_comma_is_an_error() {
        assert!(protocol_error(r#"{"a":1,}"#).contains("expected a field name"));
    }

    #[test]
    fn an_unterminated_string_is_an_error() {
        assert!(protocol_error(r#"{"a":"x}"#).contains("unterminated string"));
    }

    #[test]
    fn an_unclosed_object_is_an_error() {
        assert!(protocol_error(r#"{"a":1"#).contains("expected '}'"));
    }

    #[test]
    fn a_single_quoted_string_is_an_error() {
        assert!(protocol_error("{'a':1}").contains("expected a field name"));
    }

    #[test]
    fn a_bare_identifier_value_is_an_error() {
        assert!(protocol_error(r#"{"a":AUTH1}"#).contains("expected a value"));
    }

    #[test]
    fn an_integer_that_does_not_fit_i64_is_an_error() {
        assert!(protocol_error(r#"{"a":99999999999999999999}"#).contains("does not fit i64"));
    }
}
