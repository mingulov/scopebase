// SPDX-License-Identifier: Apache-2.0
//! Minimal strict JSON reader for scopebase-bpf test fixtures.
//!
//! Test support only: parses the exact shapes of the BP04/BP06 fixtures
//! (objects with unique string keys, arrays, unsigned integers, plain
//! strings, booleans, null). Rejects duplicate keys, trailing input,
//! negative/fractional/exponent numbers and unsupported escapes.
#![allow(dead_code)]

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(u64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Result<&Json, String> {
        match self {
            Json::Obj(entries) => entries
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .ok_or_else(|| format!("missing key {key:?}")),
            other => Err(format!("expected object for key {key:?}, found {other:?}")),
        }
    }

    pub fn as_u64(&self) -> Result<u64, String> {
        match self {
            Json::Num(value) => Ok(*value),
            other => Err(format!("expected number, found {other:?}")),
        }
    }

    pub fn as_usize(&self) -> Result<usize, String> {
        let value = self.as_u64()?;
        usize::try_from(value).map_err(|_| format!("number {value} exceeds usize"))
    }

    pub fn as_str(&self) -> Result<&str, String> {
        match self {
            Json::Str(value) => Ok(value),
            other => Err(format!("expected string, found {other:?}")),
        }
    }

    pub fn as_arr(&self) -> Result<&[Json], String> {
        match self {
            Json::Arr(items) => Ok(items),
            other => Err(format!("expected array, found {other:?}")),
        }
    }

    pub fn as_bool(&self) -> Result<bool, String> {
        match self {
            Json::Bool(value) => Ok(*value),
            other => Err(format!("expected bool, found {other:?}")),
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Result<u8, String> {
        self.bytes
            .get(self.pos)
            .copied()
            .ok_or_else(|| format!("unexpected end of input at byte {}", self.pos))
    }

    fn next(&mut self) -> Result<u8, String> {
        let byte = self.peek()?;
        self.pos += 1;
        Ok(byte)
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len()
            && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }

    fn expect(&mut self, want: u8) -> Result<(), String> {
        let got = self.next()?;
        if got == want {
            Ok(())
        } else {
            Err(format!(
                "expected {:?} at byte {}, found {:?}",
                want as char, self.pos, got as char
            ))
        }
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek()? {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => Ok(Json::Str(self.parse_string()?)),
            b'0'..=b'9' => Ok(Json::Num(self.parse_number()?)),
            b't' => self.parse_literal("true", Json::Bool(true)),
            b'f' => self.parse_literal("false", Json::Bool(false)),
            b'n' => self.parse_literal("null", Json::Null),
            other => Err(format!(
                "unexpected {:?} at byte {}",
                other as char, self.pos
            )),
        }
    }

    fn parse_literal(&mut self, word: &str, value: Json) -> Result<Json, String> {
        let end = self.pos + word.len();
        if self.bytes.get(self.pos..end) == Some(word.as_bytes()) {
            self.pos = end;
            Ok(value)
        } else {
            Err(format!("invalid literal at byte {}", self.pos))
        }
    }

    fn parse_object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut entries = Vec::new();
        self.skip_ws();
        if self.peek()? == b'}' {
            self.pos += 1;
            return Ok(Json::Obj(entries));
        }
        loop {
            self.skip_ws();
            if self.peek()? != b'"' {
                return Err(format!("expected string key at byte {}", self.pos));
            }
            let key = self.parse_string()?;
            if entries.iter().any(|(k, _)| *k == key) {
                return Err(format!("duplicate key {key:?}"));
            }
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value()?;
            entries.push((key, value));
            self.skip_ws();
            match self.next()? {
                b',' => continue,
                b'}' => break,
                other => {
                    return Err(format!(
                        "expected ',' or '}}' at byte {}, found {:?}",
                        self.pos, other as char
                    ));
                }
            }
        }
        Ok(Json::Obj(entries))
    }

    fn parse_array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek()? == b']' {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.next()? {
                b',' => continue,
                b']' => break,
                other => {
                    return Err(format!(
                        "expected ',' or ']' at byte {}, found {:?}",
                        self.pos, other as char
                    ));
                }
            }
        }
        Ok(Json::Arr(items))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = Vec::new();
        loop {
            match self.next()? {
                b'"' => break,
                b'\\' => match self.next()? {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    other => {
                        return Err(format!(
                            "unsupported escape {:?} at byte {}",
                            other as char, self.pos
                        ));
                    }
                },
                byte @ 0x20..=0x7e => out.push(byte),
                byte => {
                    return Err(format!(
                        "unsupported string byte 0x{byte:02x} at byte {}",
                        self.pos
                    ));
                }
            }
        }
        String::from_utf8(out).map_err(|error| format!("invalid string bytes: {error}"))
    }

    fn parse_number(&mut self) -> Result<u64, String> {
        let start = self.pos;
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        let text = &self.bytes[start..self.pos];
        if text.len() > 1 && text[0] == b'0' {
            return Err(format!("leading zero at byte {start}"));
        }
        std::str::from_utf8(text)
            .map_err(|error| format!("invalid number bytes: {error}"))?
            .parse::<u64>()
            .map_err(|_| format!("number out of u64 range at byte {start}"))
    }
}

/// Parse one complete JSON value; trailing bytes are an error.
pub fn parse(text: &str) -> Result<Json, String> {
    let mut cursor = Cursor::new(text);
    let value = cursor.parse_value()?;
    cursor.skip_ws();
    if cursor.pos != cursor.bytes.len() {
        return Err(format!("trailing input at byte {}", cursor.pos));
    }
    Ok(value)
}
