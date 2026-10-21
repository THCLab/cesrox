//! Serializations of non-native messages.

use std::str::FromStr;

use rmp_serde as serde_mgpk;
use serde::{Deserialize, Serialize};

use super::error::Error;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy)]
#[non_exhaustive]
/// Serialization of a non-native message.
pub enum SerializationFormats {
    /// JSON.
    JSON,
    /// MessagePack.
    MGPK,
    /// CBOR.
    CBOR,
    /// Native CESR. said reads it in version strings but cannot serialize
    /// to it.
    CESR,
}

impl SerializationFormats {
    /// Serializes `message`; structs become maps with field names.
    pub fn encode<T: Serialize>(&self, message: &T) -> Result<Vec<u8>, Error> {
        match self {
            Self::JSON => serde_json::to_vec(message).map_err(|_| Error::JsonDeserError),
            Self::CBOR => encode_cbor(message),
            // structs as maps with field names, as in JSON and CBOR
            Self::MGPK => serde_mgpk::to_vec_named(message).map_err(|_| Error::MsgPackDeserError),
            Self::CESR => Err(Error::SerializationError(
                "native CESR serialization is not supported".into(),
            )),
        }
    }

    /// The four-letter kind in a version string, such as `JSON`.
    pub fn to_str(&self) -> String {
        match self {
            Self::JSON => "JSON",
            Self::CBOR => "CBOR",
            Self::MGPK => "MGPK",
            Self::CESR => "CESR",
        }
        .to_string()
    }
}

/// CBOR with every map and array of definite length, as keripy writes it.
/// serde_cbor writes a struct with flattened fields as an indefinite-length
/// map, which encodes the same data with other bytes, so digests and
/// signatures over it would not match. Going through a value that keeps the
/// field order gives every map its length.
fn encode_cbor<T: Serialize>(message: &T) -> Result<Vec<u8>, Error> {
    let value = ciborium::Value::serialized(message).map_err(|_| Error::CborDeserError)?;
    let mut out = vec![];
    ciborium::into_writer(&value, &mut out).map_err(|_| Error::CborDeserError)?;
    Ok(out)
}

impl FromStr for SerializationFormats {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "JSON" => Ok(SerializationFormats::JSON),
            "MGPK" => Ok(SerializationFormats::MGPK),
            "CBOR" => Ok(SerializationFormats::CBOR),
            "CESR" => Ok(SerializationFormats::CESR),
            _ => Err(Error::DeserializeError("Unknown format".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::SerializationFormats;

    #[derive(Serialize)]
    struct Flattened {
        v: String,
        #[serde(flatten)]
        rest: Rest,
    }

    #[derive(Serialize)]
    struct Rest {
        t: String,
        k: Vec<String>,
    }

    #[derive(Serialize)]
    struct Plain {
        v: String,
        t: String,
        k: Vec<String>,
    }

    #[test]
    fn cbor_maps_have_definite_length() {
        let flattened = Flattened {
            v: "KERI10CBOR000000_".into(),
            rest: Rest {
                t: "icp".into(),
                k: vec!["DA".into()],
            },
        };
        let plain = Plain {
            v: "KERI10CBOR000000_".into(),
            t: "icp".into(),
            k: vec!["DA".into()],
        };
        let encoded = SerializationFormats::CBOR.encode(&flattened).unwrap();
        // a map of three entries, not 0xbf (indefinite length)
        assert_eq!(encoded[0], 0xa3);
        assert_eq!(encoded, serde_cbor::to_vec(&plain).unwrap());
    }
}
