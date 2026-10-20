//! Version strings of non-native messages: protocol, version, kind and
//! size.

use self::{error::Error, format::SerializationFormats};
use crate::derivation::HashFunctionCode;
use cesrox::conversion::{b64_to_num, num_to_b64};
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
pub mod error;
pub mod format;

/// The version string at the start of a non-native message (`v` field):
/// protocol, protocol version, serialization kind and size in bytes.
///
/// Protocol version 1 uses the 17-character form `PPPPvvKKKKllllll_` with
/// hexadecimal numbers; version 2 and later the 19-character form
/// `PPPPMmmGggKKKKBBBB.` with Base64 numbers and the version of the CESR
/// code table (genus) the message uses.
#[derive(Debug, Clone, PartialEq)]
pub struct SerializationInfo {
    /// Four-letter protocol code, such as `KERI` or `ACDC`.
    pub protocol_code: String,
    /// Major version of the protocol.
    pub major_version: u8,
    /// Minor version of the protocol.
    pub minor_version: u16,
    /// Major and minor version of the CESR code table; only in the V2 form,
    /// where it defaults to 2.0.
    pub genus_version: Option<(u8, u16)>,
    /// Size of the whole serialized message in bytes.
    pub size: usize,
    /// How the message is serialized.
    pub kind: SerializationFormats,
}

/// Genus version written when none is set.
const DEFAULT_GENUS: (u8, u16) = (2, 0);

impl SerializationInfo {
    /// A version string for `protocol` with the given versions, kind and
    /// size.
    pub fn new(
        protocol: String,
        major_version: u8,
        minor_version: u16,
        kind: SerializationFormats,
        size: usize,
    ) -> Self {
        Self {
            protocol_code: protocol,
            major_version,
            minor_version,
            genus_version: None,
            size,
            kind,
        }
    }

    /// A version string with size 0, to be filled in once the message is
    /// serialized.
    pub fn new_empty(
        protocol: String,
        major_version: u8,
        minor_version: u16,
        kind: SerializationFormats,
    ) -> Self {
        Self::new(protocol, major_version, minor_version, kind, 0)
    }

    /// Serializes `t` in this version string's kind.
    pub fn serialize<T: Serialize>(&self, t: &T) -> Result<Vec<u8>, Error> {
        self.kind.encode(t)
    }

    /// Whether the version string uses the V2 form.
    pub fn is_v2(&self) -> bool {
        self.major_version >= 2
    }

    /// Text of the version string. Values must fit the form: in V1 versions
    /// up to 15 and sizes up to 16,777,215 bytes; in V2 major versions up to
    /// 63, minor versions up to 4095 and the same sizes.
    pub fn to_str(&self) -> String {
        if self.is_v2() {
            let (genus_major, genus_minor) = self.genus_version.unwrap_or(DEFAULT_GENUS);
            format!(
                "{}{}{}{}{}{}{}.",
                self.protocol_code,
                b64(self.major_version, 1),
                b64(self.minor_version, 2),
                b64(genus_major, 1),
                b64(genus_minor, 2),
                self.kind.to_str(),
                b64(self.size as u64, 4),
            )
        } else {
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
}

fn b64(value: impl Into<u64>, width: usize) -> String {
    format!("{:A>width$}", num_to_b64(value))
}

fn invalid(s: &str) -> Error {
    Error::DeserializeError(format!("invalid version string {s:?}"))
}

impl FromStr for SerializationInfo {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let protocol = s
            .get(0..4)
            .filter(|p| p.bytes().all(|b| b.is_ascii_uppercase()));
        let protocol_code = protocol.ok_or_else(|| invalid(s))?.to_string();
        match (s.len(), s.as_bytes().last()) {
            // PPPPvvKKKKllllll_
            (17, Some(b'_')) => {
                let hex = |range: std::ops::Range<usize>| {
                    s.get(range)
                        .filter(|t| t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
                        .ok_or_else(|| invalid(s))
                };
                Ok(Self {
                    protocol_code,
                    major_version: u8::from_str_radix(hex(4..5)?, 16)?,
                    minor_version: u16::from_str_radix(hex(5..6)?, 16)?,
                    genus_version: None,
                    kind: SerializationFormats::from_str(&s[6..10])?,
                    size: usize::from_str_radix(hex(10..16)?, 16)?,
                })
            }
            // PPPPMmmGggKKKKBBBB.
            (19, Some(b'.')) => {
                let num = |range: std::ops::Range<usize>| -> Result<u64, Error> {
                    s.get(range)
                        .and_then(|t| b64_to_num::<u64>(t).ok())
                        .ok_or_else(|| invalid(s))
                };
                let major_version = num(4..5)? as u8;
                let genus_major = num(7..8)? as u8;
                // the V2 form is for protocol version 2 and CESR V2 code tables
                if major_version < 2 || genus_major < 2 {
                    return Err(invalid(s));
                }
                Ok(Self {
                    protocol_code,
                    major_version,
                    minor_version: num(5..7)? as u16,
                    genus_version: Some((genus_major, num(8..10)? as u16)),
                    kind: SerializationFormats::from_str(s.get(10..14).ok_or_else(|| invalid(s))?)?,
                    size: num(14..18)? as usize,
                })
            }
            _ => Err(invalid(s)),
        }
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
        Self::new("KERI".to_string(), 1, 0, SerializationFormats::JSON, 0)
    }
}

/// Types that serialize as a complete message with a version string.
pub trait Encode {
    /// The message serialized as `serialization_format`, with the size in
    /// its version string.
    fn encode(
        &self,
        code: &HashFunctionCode,
        serialization_format: &SerializationFormats,
    ) -> Result<Vec<u8>, Error>;
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
    fn v2_version_strings() -> Result<(), Error> {
        let si = SerializationInfo::from_str("KERICAACAAJSONAABk.")?;
        assert_eq!((si.major_version, si.minor_version), (2, 0));
        assert_eq!(si.genus_version, Some((2, 0)));
        assert_eq!(si.size, 100);
        assert_eq!(si.to_str(), "KERICAACAAJSONAABk.");

        let si = SerializationInfo::new("ACDC".into(), 2, 0, SerializationFormats::CESR, 0);
        assert_eq!(si.to_str(), "ACDCCAACAACESRAAAA.");
        Ok(())
    }

    #[test]
    fn malformed_version_strings_are_rejected() {
        for s in [
            "KERI10JSON00014bXYZ",
            "keri10JSON00014b_",
            "KERI10JSON+0014b_",
            "KERI10JSON00014B_",
            "KERIBAACAAJSONAABk.",
            "KERICAACAAJSONAABk",
            "KERICAACAAXXXXAABk.",
        ] {
            assert!(SerializationInfo::from_str(s).is_err(), "{s}");
        }
        // sizes beyond 16 bits
        assert_eq!(
            SerializationInfo::from_str("KERI10JSON010000_")
                .unwrap()
                .size,
            0x10000
        );
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
