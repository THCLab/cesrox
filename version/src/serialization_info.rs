use crate::error::Error;
use core::str::FromStr;
use rmp_serde as serde_mgpk;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

#[derive(Debug, Clone, PartialEq)]
pub struct SerializationInfo {
    pub protocol_code: String,
    pub major_version: u8,
    pub minor_version: u8,
    pub size: usize,
    pub kind: SerializationFormats,
}

impl SerializationInfo {
    pub fn new(protocol: String, kind: SerializationFormats, size: usize) -> Self {
        Self {
            protocol_code: protocol,
            major_version: 1,
            minor_version: 0,
            size,
            kind,
        }
    }

    pub fn new_empty(protocol: String, kind: SerializationFormats) -> Self {
        Self {
            protocol_code: protocol,
            major_version: 1,
            minor_version: 0,
            size: 0,
            kind,
        }
    }

    pub fn serialize<T: Serialize>(&self, t: &T) -> Result<Vec<u8>, Error> {
        self.kind.encode(t)
    }

    pub fn to_str(&self) -> String {
        format!(
            "{}{:x}{:x}{}{:06x}_",
            self.protocol_code,
            self.major_version,
            self.minor_version,
            self.kind.to_str(),
            self.size
        )
    }
}

impl FromStr for SerializationInfo {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            protocol_code: s[..4].to_string(),
            major_version: u8::from_str_radix(&s[4..5], 16)?,
            minor_version: u8::from_str_radix(&s[5..6], 16)?,
            kind: SerializationFormats::from_str(&s[6..10])?,
            size: u16::from_str_radix(&s[10..16], 16)? as usize,
        })
    }
}

/// Serde compatible Serialize
impl Serialize for SerializationInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for SerializationInfo {
    fn deserialize<D>(deserializer: D) -> Result<SerializationInfo, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        SerializationInfo::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Default for SerializationInfo {
    fn default() -> Self {
        Self {
            protocol_code: "KERI".to_string(),
            major_version: 1,
            minor_version: 0,
            size: 0,
            kind: SerializationFormats::JSON,
        }
    }
}

#[test]
fn test_version_from_str() {
    let json = r#"KERI10JSON00014b_"#;
    let json_result = json.parse::<SerializationInfo>();
    assert!(json_result.is_ok());
    assert_eq!(&json, &json_result.unwrap().to_str());
}
