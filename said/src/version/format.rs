use std::str::FromStr;

use rmp_serde as serde_mgpk;
use serde::{Deserialize, Serialize};

use super::error::Error;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy)]
pub enum SerializationFormats {
    JSON,
    MGPK,
    CBOR,
}

impl SerializationFormats {
    pub fn encode<T: Serialize>(&self, message: &T) -> Result<Vec<u8>, Error> {
        match self {
            Self::JSON => serde_json::to_vec(message).map_err(|_| Error::JsonDeserError),
            Self::CBOR => serde_cbor::to_vec(message).map_err(|_| Error::CborDeserError),
            Self::MGPK => serde_mgpk::to_vec(message).map_err(|_| Error::MsgPackDeserError),
        }
    }

    pub fn to_str(&self) -> String {
        match self {
            Self::JSON => "JSON",
            Self::CBOR => "CBOR",
            Self::MGPK => "MGPK",
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
            _ => Err(Error::DeserializeError("Unknown format".into())),
        }
    }
}
