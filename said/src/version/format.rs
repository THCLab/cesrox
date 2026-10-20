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
            Self::CBOR => serde_cbor::to_vec(message).map_err(|_| Error::CborDeserError),
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
