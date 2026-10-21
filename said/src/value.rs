//! A JSON value whose maps keep their fields in the order they were given.
//!
//! A SAID covers the bytes of a message, so a map nested anywhere inside it
//! must come out in the order it went in. `serde_json::Value` only does that
//! with serde_json's `preserve_order` feature, and a library turning that on
//! re-orders the JSON of every other crate in the same build. [`Value`]
//! keeps the order by itself.

use core::fmt;

use indexmap::IndexMap;
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
    Deserialize, Deserializer, Serialize, Serializer,
};

/// The key serde_json uses for a number when its `arbitrary_precision`
/// feature is on: the number then arrives as a one-entry map holding its
/// text under this key.
const ARBITRARY_PRECISION_NUMBER: &str = "$serde_json::private::Number";

/// A JSON value. Maps keep their fields in the order they were given.
#[derive(Clone, Debug, PartialEq, Default)]
pub enum Value {
    /// `null`.
    #[default]
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, as serde_json holds it.
    Number(serde_json::Number),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// A map, in the order its fields were given.
    Object(IndexMap<String, Value>),
}

impl Value {
    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The map, if this is one.
    pub fn as_object(&self) -> Option<&IndexMap<String, Value>> {
        match self {
            Value::Object(map) => Some(map),
            _ => None,
        }
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_string())
    }
}

impl PartialEq<str> for Value {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == Some(other)
    }
}

impl PartialEq<&str> for Value {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == Some(*other)
    }
}

impl PartialEq<String> for Value {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == Some(other.as_str())
    }
}

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(b) => serializer.serialize_bool(*b),
            Value::Number(n) => n.serialize(serializer),
            Value::String(s) => serializer.serialize_str(s),
            Value::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Value::Object(map) => {
                let mut out = serializer.serialize_map(Some(map.len()))?;
                for (k, v) in map {
                    out.serialize_entry(k, v)?;
                }
                out.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ValueVisitor)
    }
}

/// How much to reserve for a sequence or map from the length it declares.
/// CBOR and MessagePack state lengths up front, and a message is not
/// trusted to state its own truthfully, so the reservation is capped and
/// anything longer grows as its items actually arrive.
fn cautious(hint: Option<usize>) -> usize {
    hint.unwrap_or(0).min(4096)
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, b: bool) -> Result<Value, E> {
        Ok(Value::Bool(b))
    }

    fn visit_i64<E>(self, n: i64) -> Result<Value, E> {
        Ok(Value::Number(n.into()))
    }

    fn visit_u64<E>(self, n: u64) -> Result<Value, E> {
        Ok(Value::Number(n.into()))
    }

    fn visit_f64<E: de::Error>(self, n: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(n)
            .map(Value::Number)
            .ok_or_else(|| E::custom("a number JSON cannot hold"))
    }

    fn visit_str<E>(self, s: &str) -> Result<Value, E> {
        Ok(Value::String(s.to_string()))
    }

    fn visit_string<E>(self, s: String) -> Result<Value, E> {
        Ok(Value::String(s))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        Value::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::with_capacity(cautious(seq.size_hint()));
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut map = IndexMap::with_capacity(cautious(access.size_hint()));
        let Some(first) = access.next_key::<String>()? else {
            return Ok(Value::Object(map));
        };
        if first == ARBITRARY_PRECISION_NUMBER {
            let text: String = access.next_value()?;
            return text.parse().map(Value::Number).map_err(de::Error::custom);
        }
        map.insert(first, access.next_value()?);
        while let Some((k, v)) = access.next_entry()? {
            map.insert(k, v);
        }
        Ok(Value::Object(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trips_byte_for_byte() {
        let text = r#"{"z":[1,-2,3.5,"s",null,true],"a":{"y":{},"b":[]}}"#;
        let value: Value = serde_json::from_str(text).unwrap();
        assert_eq!(serde_json::to_string(&value).unwrap(), text);
    }

    #[test]
    fn large_integers_are_kept_exactly() {
        let text = r#"{"u":18446744073709551615,"i":-9223372036854775808}"#;
        let value: Value = serde_json::from_str(text).unwrap();
        assert_eq!(serde_json::to_string(&value).unwrap(), text);
    }
}
