// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

//! Decode image JSON exactly as Go's `encoding/json` decodes it into containerd's types.
//!
//! containerd reads indexes, manifests and configs with `json.Unmarshal`, so a reader that
//! must agree with containerd on what an image holds decodes the same way:
//!
//! - the whole input is validated first (strict JSON, nesting depth at most 10000);
//! - an object key selects the field whose name it equals, else the one it equals under
//!   Unicode case folding; keys matching no field are skipped;
//! - a later duplicate key decodes *into* the earlier value: objects merge into a struct, a
//!   pointer's target or a map, and an array decodes element by element into the slice's
//!   existing elements, keeping the old elements' backing store for reuse;
//! - `null` leaves a string or struct as it was and sets a slice, map or pointer to nil;
//! - in strings, each invalid UTF-8 byte and each unpaired surrogate escape reads as U+FFFD;
//! - a value of the wrong JSON type for its field fails the whole decode.
//!
//! Callers describe the Go type with a [`Shape`] listing only the fields they read: Go's
//! type checks on other fields are not reproduced, so this accepts a superset of what
//! containerd accepts.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

/// Go's `maxNestingDepth` in `encoding/json`.
const MAX_DEPTH: usize = 10_000;

/// Image JSON that containerd's decoder rejects as well: no container can be created from it.
#[derive(Debug, thiserror::Error)]
#[error("unparsable image JSON: {0}")]
pub struct Unparsable(pub String);

/// The Go type a JSON value decodes into.
pub enum Shape {
    /// `string` (or a string type such as `digest.Digest`).
    Str,
    /// `map[string]string`.
    StrMap,
    /// `[]T`.
    List(&'static Shape),
    /// A struct and its fields, by their JSON names.
    Struct(&'static [(&'static str, Shape)]),
    /// `*T` for a struct `T`.
    Ptr(&'static Shape),
    /// `json.RawMessage`: only whether the key appeared (any value, `null` included).
    Raw,
}

/// A Rust type read from the canonical JSON [`decode`] builds for its Go [`Shape`]: every
/// field under its JSON name, a nil slice as `[]`, a nil map omitted, a nil pointer as
/// `null`, a raw message as whether it appeared.
pub trait GoType: DeserializeOwned {
    const SHAPE: Shape;
}

/// Decode `bytes` as `json.Unmarshal` decodes them into a fresh value of `T`'s Go type.
pub fn decode<T: GoType>(bytes: &[u8]) -> Result<T, Unparsable> {
    validate(bytes).map_err(Unparsable)?;
    let mut value = zero(&T::SHAPE);
    let mut parser = Parser { b: bytes, i: 0 };
    parser.decode(&T::SHAPE, &mut value).map_err(Unparsable)?;
    serde_json::from_value(value.into_json(&T::SHAPE)).map_err(|e| Unparsable(e.to_string()))
}

/// A Go value in memory.
enum Val {
    Str(String),
    Map(Option<BTreeMap<String, String>>),
    /// A slice: its length and its backing store, which may hold elements past the length.
    List(Vec<Val>, usize),
    Struct(Vec<Val>),
    Ptr(Option<Box<Val>>),
    Raw(bool),
}

fn zero(shape: &Shape) -> Val {
    match shape {
        Shape::Str => Val::Str(String::new()),
        Shape::StrMap => Val::Map(None),
        Shape::List(_) => Val::List(Vec::new(), 0),
        Shape::Struct(fields) => Val::Struct(fields.iter().map(|(_, s)| zero(s)).collect()),
        Shape::Ptr(_) => Val::Ptr(None),
        Shape::Raw => Val::Raw(false),
    }
}

impl Val {
    fn into_json(self, shape: &Shape) -> Value {
        match (self, shape) {
            (Val::Str(s), _) => Value::String(s),
            (Val::Map(m), _) => m.map_or(Value::Null, |m| {
                Value::Object(m.into_iter().map(|(k, v)| (k, Value::String(v))).collect())
            }),
            (Val::List(mut items, len), Shape::List(elem)) => {
                items.truncate(len);
                Value::Array(items.into_iter().map(|v| v.into_json(elem)).collect())
            }
            (Val::Struct(vals), Shape::Struct(fields)) => {
                let mut out = Map::new();
                for ((name, field), v) in fields.iter().zip(vals) {
                    if !matches!(v, Val::Map(None)) {
                        out.insert((*name).to_string(), v.into_json(field));
                    }
                }
                Value::Object(out)
            }
            (Val::Ptr(p), Shape::Ptr(inner)) => p.map_or(Value::Null, |v| v.into_json(inner)),
            (Val::Raw(seen), _) => Value::Bool(seen),
            _ => unreachable!("a value always has its shape"),
        }
    }
}

/// Go's key folding for an ASCII field name: ASCII letters fold case, and the only
/// non-ASCII characters in an ASCII letter's fold set are U+017F (s) and U+212A (k).
fn key_matches(key: &str, field: &str) -> bool {
    let fold = |c: char| match c {
        '\u{17f}' => 'S',
        '\u{212a}' => 'K',
        c => c.to_ascii_uppercase(),
    };
    key.chars().map(fold).eq(field.chars().map(fold))
}

fn field_index(fields: &[(&str, Shape)], key: &str) -> Option<usize> {
    fields
        .iter()
        .position(|(name, _)| *name == key)
        .or_else(|| fields.iter().position(|(name, _)| key_matches(key, name)))
}

/// Go's scanner: strict JSON, at most [`MAX_DEPTH`] nested objects and arrays.
fn validate(b: &[u8]) -> Result<(), String> {
    let mut stack: Vec<u8> = Vec::new();
    let mut i = 0;
    let mut want_value = true;
    let err = |what: &str, i: usize| Err(format!("{what} at offset {i}"));
    loop {
        skip_ws(b, &mut i);
        if want_value {
            match b.get(i) {
                Some(&open @ (b'{' | b'[')) => {
                    i += 1;
                    stack.push(open);
                    if stack.len() > MAX_DEPTH {
                        return err("exceeded max depth", i);
                    }
                    skip_ws(b, &mut i);
                    let close = if open == b'{' { b'}' } else { b']' };
                    if b.get(i) == Some(&close) {
                        i += 1;
                        stack.pop();
                        want_value = false;
                    } else if open == b'{' {
                        scan_key(b, &mut i)?;
                    }
                    continue;
                }
                Some(b'"') => scan_string(b, &mut i)?,
                Some(b't') => scan_literal(b, &mut i, b"true")?,
                Some(b'f') => scan_literal(b, &mut i, b"false")?,
                Some(b'n') => scan_literal(b, &mut i, b"null")?,
                Some(b'-' | b'0'..=b'9') => scan_number(b, &mut i)?,
                Some(_) => return err("invalid character looking for a value", i),
                None => return err("unexpected end of JSON input", i),
            }
            want_value = false;
            continue;
        }
        match (stack.last(), b.get(i)) {
            (None, None) => return Ok(()),
            (None, Some(_)) => return err("invalid character after top-level value", i),
            (Some(b'{'), Some(b',')) => {
                i += 1;
                skip_ws(b, &mut i);
                scan_key(b, &mut i)?;
                want_value = true;
            }
            (Some(b'['), Some(b',')) => {
                i += 1;
                want_value = true;
            }
            (Some(b'{'), Some(b'}')) | (Some(b'['), Some(b']')) => {
                i += 1;
                stack.pop();
            }
            (_, None) => return err("unexpected end of JSON input", i),
            _ => return err("invalid character after a value", i),
        }
    }
}

fn skip_ws(b: &[u8], i: &mut usize) {
    while matches!(b.get(*i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        *i += 1;
    }
}

/// An object key and its colon.
fn scan_key(b: &[u8], i: &mut usize) -> Result<(), String> {
    if b.get(*i) != Some(&b'"') {
        return Err(format!("expected an object key at offset {i}"));
    }
    scan_string(b, i)?;
    skip_ws(b, i);
    if b.get(*i) != Some(&b':') {
        return Err(format!("expected ':' at offset {i}"));
    }
    *i += 1;
    Ok(())
}

fn scan_string(b: &[u8], i: &mut usize) -> Result<(), String> {
    *i += 1;
    loop {
        match b.get(*i) {
            Some(b'"') => {
                *i += 1;
                return Ok(());
            }
            Some(b'\\') => match b.get(*i + 1) {
                Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => *i += 2,
                Some(b'u') if hex4(b, *i + 2).is_some() => *i += 6,
                _ => return Err(format!("invalid escape at offset {i}")),
            },
            Some(&c) if c < 0x20 => return Err(format!("control character in string at {i}")),
            Some(_) => *i += 1,
            None => return Err("unexpected end of JSON input in a string".to_string()),
        }
    }
}

fn scan_literal(b: &[u8], i: &mut usize, lit: &[u8]) -> Result<(), String> {
    if b.get(*i..*i + lit.len()) != Some(lit) {
        return Err(format!("invalid literal at offset {i}"));
    }
    *i += lit.len();
    Ok(())
}

fn scan_number(b: &[u8], i: &mut usize) -> Result<(), String> {
    let digits = |i: &mut usize| {
        let start = *i;
        while matches!(b.get(*i), Some(b'0'..=b'9')) {
            *i += 1;
        }
        *i > start
    };
    let bad = |i: &usize| Err(format!("invalid number at offset {i}"));
    if b.get(*i) == Some(&b'-') {
        *i += 1;
    }
    match b.get(*i) {
        Some(b'0') => *i += 1,
        Some(b'1'..=b'9') => {
            digits(i);
        }
        _ => return bad(i),
    }
    if b.get(*i) == Some(&b'.') {
        *i += 1;
        if !digits(i) {
            return bad(i);
        }
    }
    if matches!(b.get(*i), Some(b'e' | b'E')) {
        *i += 1;
        if matches!(b.get(*i), Some(b'+' | b'-')) {
            *i += 1;
        }
        if !digits(i) {
            return bad(i);
        }
    }
    Ok(())
}

fn hex4(b: &[u8], at: usize) -> Option<u32> {
    let s = std::str::from_utf8(b.get(at..at + 4)?).ok()?;
    if !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(s, 16).ok()
}

/// Decoder over input [`validate`] accepted.
struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&mut self) -> u8 {
        skip_ws(self.b, &mut self.i);
        self.b[self.i]
    }

    fn type_error(&self, shape: &Shape) -> String {
        let want = match shape {
            Shape::Str => "string",
            Shape::StrMap | Shape::Struct(_) | Shape::Ptr(_) => "object",
            Shape::List(_) => "array",
            Shape::Raw => "value",
        };
        format!("expected {want} at offset {}", self.i)
    }

    fn decode(&mut self, shape: &Shape, val: &mut Val) -> Result<(), String> {
        let c = self.peek();
        if let Shape::Raw = shape {
            self.skip();
            *val = Val::Raw(true);
            return Ok(());
        }
        if c == b'n' {
            self.i += 4;
            match val {
                Val::Map(m) => *m = None,
                Val::List(items, len) => (*items, *len) = (Vec::new(), 0),
                Val::Ptr(p) => *p = None,
                _ => {}
            }
            return Ok(());
        }
        match (shape, val) {
            (Shape::Str, Val::Str(s)) if c == b'"' => *s = self.string(),
            (Shape::StrMap, Val::Map(m)) if c == b'{' => {
                let m = m.get_or_insert_default();
                self.members(|p, key| {
                    let value = match p.peek() {
                        b'"' => p.string(),
                        b'n' => {
                            p.i += 4;
                            String::new()
                        }
                        _ => return Err(p.type_error(&Shape::Str)),
                    };
                    m.insert(key, value);
                    Ok(())
                })?;
            }
            (Shape::List(elem), Val::List(items, len)) if c == b'[' => {
                self.i += 1;
                let mut n = 0;
                while self.peek() != b']' {
                    if n == items.len() {
                        items.push(zero(elem));
                    }
                    self.decode(elem, &mut items[n])?;
                    n += 1;
                    if self.peek() == b',' {
                        self.i += 1;
                    }
                }
                self.i += 1;
                *len = n;
                if n == 0 {
                    items.clear();
                }
            }
            (Shape::Struct(fields), Val::Struct(vals)) if c == b'{' => {
                self.members(|p, key| match field_index(fields, &key) {
                    Some(f) => p.decode(&fields[f].1, &mut vals[f]),
                    None => {
                        p.skip();
                        Ok(())
                    }
                })?;
            }
            (Shape::Ptr(inner), Val::Ptr(p)) if c == b'{' => {
                let target = p.get_or_insert_with(|| Box::new(zero(inner)));
                self.decode(inner, target)?;
            }
            _ => return Err(self.type_error(shape)),
        }
        Ok(())
    }

    /// Each member of the object at the cursor, in order.
    fn members(
        &mut self,
        mut each: impl FnMut(&mut Self, String) -> Result<(), String>,
    ) -> Result<(), String> {
        self.i += 1;
        while self.peek() != b'}' {
            let key = self.string();
            self.peek();
            self.i += 1; // ':'
            each(self, key)?;
            if self.peek() == b',' {
                self.i += 1;
            }
        }
        self.i += 1;
        Ok(())
    }

    /// Skip one value without building it.
    fn skip(&mut self) {
        let mut depth = 0usize;
        loop {
            match self.peek() {
                b'"' => {
                    let _ = scan_string(self.b, &mut self.i);
                }
                b'{' | b'[' => {
                    depth += 1;
                    self.i += 1;
                    continue;
                }
                b'}' | b']' => {
                    depth -= 1;
                    self.i += 1;
                }
                b',' | b':' => {
                    self.i += 1;
                    continue;
                }
                _ => {
                    while !matches!(
                        self.b.get(self.i),
                        None | Some(b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
                    ) {
                        self.i += 1;
                    }
                }
            }
            if depth == 0 {
                return;
            }
        }
    }

    /// The string at the cursor, unquoted as Go unquotes it.
    fn string(&mut self) -> String {
        let b = self.b;
        let mut out = String::new();
        let mut i = self.i + 1;
        loop {
            match b[i] {
                b'"' => break,
                b'\\' => {
                    let simple = match b[i + 1] {
                        b'b' => Some('\u{8}'),
                        b'f' => Some('\u{c}'),
                        b'n' => Some('\n'),
                        b'r' => Some('\r'),
                        b't' => Some('\t'),
                        b'u' => None,
                        c => Some(c as char),
                    };
                    if let Some(c) = simple {
                        out.push(c);
                        i += 2;
                        continue;
                    }
                    let r = hex4(b, i + 2).expect("validated escape");
                    i += 6;
                    if (0xd800..0xe000).contains(&r) {
                        let low = (b.get(i) == Some(&b'\\') && b.get(i + 1) == Some(&b'u'))
                            .then(|| hex4(b, i + 2))
                            .flatten();
                        match low {
                            Some(lo) if r < 0xdc00 && (0xdc00..0xe000).contains(&lo) => {
                                let c = 0x10000 + ((r - 0xd800) << 10) + (lo - 0xdc00);
                                out.push(char::from_u32(c).expect("valid surrogate pair"));
                                i += 6;
                            }
                            _ => out.push(char::REPLACEMENT_CHARACTER),
                        }
                    } else {
                        out.push(char::from_u32(r).expect("not a surrogate"));
                    }
                }
                c if c < 0x80 => {
                    out.push(c as char);
                    i += 1;
                }
                c => {
                    let width = match c {
                        0xc2..=0xdf => 2,
                        0xe0..=0xef => 3,
                        0xf0..=0xf4 => 4,
                        _ => 0,
                    };
                    match b.get(i..i + width).map(std::str::from_utf8) {
                        Some(Ok(s)) if width > 0 => {
                            out.push_str(s);
                            i += width;
                        }
                        _ => {
                            out.push(char::REPLACEMENT_CHARACTER);
                            i += 1;
                        }
                    }
                }
            }
        }
        self.i = i + 1;
        out
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Default, Deserialize, PartialEq)]
    struct Platform {
        architecture: String,
        os: String,
    }

    #[derive(Debug, Default, Deserialize, PartialEq)]
    struct Desc {
        #[serde(rename = "mediaType")]
        media_type: String,
        digest: String,
        #[serde(default)]
        annotations: HashMap<String, String>,
        platform: Option<Platform>,
    }

    #[derive(Debug, Deserialize)]
    struct Doc {
        config: Desc,
        layers: Vec<Desc>,
        manifests: bool,
    }

    const PLATFORM: Shape = Shape::Struct(&[("architecture", Shape::Str), ("os", Shape::Str)]);
    const DESC: Shape = Shape::Struct(&[
        ("mediaType", Shape::Str),
        ("digest", Shape::Str),
        ("annotations", Shape::StrMap),
        ("platform", Shape::Ptr(&PLATFORM)),
    ]);

    impl GoType for Doc {
        const SHAPE: Shape = Shape::Struct(&[
            ("config", DESC),
            ("layers", Shape::List(&DESC)),
            ("manifests", Shape::Raw),
        ]);
    }

    fn doc(json: &str) -> Doc {
        decode(json.as_bytes()).unwrap()
    }

    fn digests(d: &Doc) -> Vec<&str> {
        d.layers.iter().map(|l| l.digest.as_str()).collect()
    }

    /// Expected values are what Go 1.27's `json.Unmarshal` gives for the same input and
    /// the same field types.
    #[test]
    fn keys_match_exactly_or_under_case_folding() {
        assert_eq!(digests(&doc(r#"{"Layers":[{"DIGEST":"a"}]}"#)), ["a"]);
        assert_eq!(
            digests(&doc("{\"layer\u{17f}\":[{\"digest\":\"a\"}]}")),
            ["a"]
        );
        assert_eq!(
            digests(&doc("{\"layers\":[{\"\\u0064igest\":\"a\"}]}")),
            ["a"]
        );
        assert!(digests(&doc(r#"{"layerz":[{"digest":"a"}]}"#)).is_empty());
        assert_eq!(
            digests(&doc(
                r#"{"layers":[{"digest":"a"}],"LAYERS":[{"digest":"b"}]}"#
            )),
            ["b"]
        );
    }

    #[test]
    fn duplicate_objects_merge_into_structs_pointers_and_maps() {
        let d = doc(r#"{"config":{"digest":"a"},"config":{"mediaType":"x"}}"#);
        assert_eq!(
            (d.config.digest.as_str(), d.config.media_type.as_str()),
            ("a", "x")
        );
        let d = doc(
            r#"{"layers":[{"platform":{"os":"linux"},"platform":{"architecture":"arm64"},
               "annotations":{"a":"1"},"annotations":{"b":"2"}}]}"#,
        );
        let l = &d.layers[0];
        assert_eq!(
            l.platform,
            Some(Platform {
                architecture: "arm64".into(),
                os: "linux".into()
            })
        );
        assert_eq!(l.annotations.len(), 2);
    }

    #[test]
    fn a_later_array_decodes_into_the_earlier_elements() {
        let d = doc(
            r#"{"layers":[{"digest":"a","mediaType":"m"},{"digest":"z"}],"layers":[{"digest":"b"}]}"#,
        );
        assert_eq!(digests(&d), ["b"]);
        assert_eq!(d.layers[0].media_type, "m");
        // Truncated elements stay in the backing store and are reused.
        let d = doc(
            r#"{"layers":[{"digest":"a"},{"digest":"z","mediaType":"q"}],
               "layers":[{"digest":"b"}],"layers":[{"digest":"c"},{"digest":"d"}]}"#,
        );
        assert_eq!(digests(&d), ["c", "d"]);
        assert_eq!(d.layers[1].media_type, "q");
        // An empty array or null drops the backing store.
        for reset in ["[]", "null"] {
            let d = doc(&format!(
                r#"{{"layers":[{{"digest":"a","mediaType":"m"}}],"layers":{reset},"layers":[{{"digest":"b"}}]}}"#
            ));
            assert_eq!(d.layers[0].media_type, "", "{reset}");
        }
        let d = doc(r#"{"layers":[null,{"digest":"a"}]}"#);
        assert_eq!(digests(&d), ["", "a"]);
    }

    #[test]
    fn null_keeps_strings_and_structs_and_clears_the_rest() {
        let d = doc(
            r#"{"config":{"digest":"a","mediaType":"x"},"config":null,"config":{"digest":null}}"#,
        );
        assert_eq!(
            (d.config.digest.as_str(), d.config.media_type.as_str()),
            ("a", "x")
        );
        let d = doc(r#"{"layers":[{"digest":"a"}],"layers":null}"#);
        assert!(d.layers.is_empty());
        let d = doc(
            r#"{"layers":[{"platform":{"os":"linux"},"platform":null,"annotations":{"a":"1"},"annotations":null}]}"#,
        );
        assert_eq!(
            (d.layers[0].platform.as_ref(), d.layers[0].annotations.len()),
            (None, 0)
        );
        let d = doc(r#"{"layers":[{"annotations":{"a":null}}]}"#);
        assert_eq!(d.layers[0].annotations["a"], "");
        assert!(doc("null").layers.is_empty());
    }

    #[test]
    fn strings_replace_invalid_utf8_bytes_and_lone_surrogates() {
        let d = |raw: &[u8]| -> String {
            let json = [br#"{"layers":[{"digest":""#.as_slice(), raw, br#""}]}"#].concat();
            decode::<Doc>(&json).unwrap().layers.remove(0).digest
        };
        assert_eq!(d(br"\ud800"), "\u{fffd}");
        assert_eq!(d(br"\ud800A"), "\u{fffd}A");
        assert_eq!(d(br"\udc00\ud800"), "\u{fffd}\u{fffd}");
        assert_eq!(d(br"\ud83d\ude00"), "\u{1f600}");
        assert_eq!(
            d(b"a\xe2\x82b\xed\xa0\x80"),
            "a\u{fffd}\u{fffd}b\u{fffd}\u{fffd}\u{fffd}"
        );
        assert_eq!(d("\u{1f600}".as_bytes()), "\u{1f600}");
    }

    #[test]
    fn missing_fields_are_zero() {
        let d = doc(r#"{"layers":[{"mediaType":"x"}]}"#);
        assert_eq!(digests(&d), [""]);
        assert!(!d.manifests);
        assert_eq!(d.config, Desc::default());
    }

    #[test]
    fn raw_messages_record_presence_of_any_value() {
        for json in [
            r#"{"manifests":null}"#,
            r#"{"Manifests":[]}"#,
            r#"{"manifests":1e400}"#,
        ] {
            assert!(doc(json).manifests, "{json}");
        }
    }

    #[test]
    fn unknown_fields_are_skipped_up_to_gos_depth_limit() {
        let nested = |n: usize| {
            format!(
                r#"{{"x":{}{},"layers":[{{"digest":"a"}}],"y":1e400}}"#,
                "[".repeat(n),
                "]".repeat(n)
            )
        };
        assert_eq!(
            digests(&decode::<Doc>(nested(9_999).as_bytes()).unwrap()),
            ["a"]
        );
        assert!(decode::<Doc>(nested(10_000).as_bytes()).is_err());
    }

    #[test]
    fn wrong_types_and_bad_syntax_are_unparsable() {
        for json in [
            r#"{"layers":"x"}"#,
            r#"{"config":"x"}"#,
            r#"{"config":[]}"#,
            r#"{"layers":[{"annotations":{"a":1}}]}"#,
            r#"{"layers":[{"platform":"linux"}]}"#,
            r#"{"layers":[{"digest":1}]}"#,
            r#"{"layers":[]"#,
            r#"{"layers":[]} x"#,
            r#"{"layers":[01]}"#,
            "{\"x\":\"\u{1}\"}",
            r#"{"x":"\x"}"#,
            "\u{feff}{}",
            "",
        ] {
            assert!(decode::<Doc>(json.as_bytes()).is_err(), "{json}");
        }
    }
}
