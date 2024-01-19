use self::{error::Error, format::SerializationFormats};
use core::str::FromStr;
use crate::derivation::HashFunctionCode;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub mod error;
pub mod format;
// pub mod parse;

#[derive(Debug, Clone, PartialEq)]
pub struct SerializationInfo {
    pub protocol_code: String,
    pub major_version: u8,
    pub minor_version: u8,
    pub size: usize,
    pub kind: SerializationFormats,
}

impl SerializationInfo {
    pub fn new(
        protocol: String,
        major_version: u8,
        minor_version: u8,
        kind: SerializationFormats,
        size: usize,
    ) -> Self {
        Self {
            protocol_code: protocol,
            major_version,
            minor_version,
            size,
            kind,
        }
    }

    pub fn new_empty(
        protocol: String,
        major_version: u8,
        minor_version: u8,
        kind: SerializationFormats,
    ) -> Self {
        Self {
            protocol_code: protocol,
            major_version,
            minor_version,
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

pub trait Encode {
    fn encode(&self, code: &HashFunctionCode, serialization_format: &SerializationFormats) -> Result<Vec<u8>, Error>;
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::version::{error::Error, format::SerializationFormats, SerializationInfo};

    #[test]
    fn test_version_from_str() {
        let json = r#"KERI10JSON00014b_"#;
        let json_result = json.parse::<SerializationInfo>();
        assert!(json_result.is_ok());
        assert_eq!(&json, &json_result.unwrap().to_str());
    }

    #[test]
    fn test_serialization_info_to_str() -> Result<(), Error> {
        let si = SerializationInfo::new("KERI".to_string(), 1, 0, SerializationFormats::JSON, 100);

        let version_string = si.to_str();
        assert_eq!("KERI10JSON000064_", &version_string);
        Ok(())
    }

    #[test]
    fn test_serialization_info_from_str() -> Result<(), Error> {
        let si = SerializationInfo::from_str("KERIa4CBOR000123_")?;

        assert_eq!(si.protocol_code, "KERI".to_string());
        assert_eq!(si.kind, SerializationFormats::CBOR);
        assert_eq!(si.major_version, 10);
        assert_eq!(si.minor_version, 4);
        assert_eq!(si.size, 291);
        Ok(())
    }
}
