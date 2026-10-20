//! Self-addressing identifiers (SAIDs): digests of data that are embedded
//! in that data, as used by KERI and ACDC.
//!
//! [`saidify`] computes the SAID of a map serialized as JSON, CBOR or
//! MessagePack and writes it into the map's SAID fields, filling in a
//! version string if there is one. [`saidify_value`] does the same for any
//! type that serializes as a map, and [`verify`] checks the SAID of a
//! received message.
//!
//! ```
//! use said::{derivation::HashFunctionCode, sad::SerializationFormats, saidify, Sad};
//!
//! let mut sad: Sad = serde_json::from_str(
//!     r#"{"v":"KERI10JSON000000_","d":"","text":"Hello world"}"#,
//! )
//! .unwrap();
//! let (said, json) = saidify(
//!     &mut sad,
//!     HashFunctionCode::Blake3_256,
//!     SerializationFormats::JSON,
//!     &["d"],
//! )
//! .unwrap();
//!
//! // `d` holds the SAID, and the version string the message size
//! assert_eq!(sad["d"], said.to_string());
//! let version: said::version::SerializationInfo = sad["v"].as_str().unwrap().parse().unwrap();
//! assert_eq!(version.size, json.len());
//! ```

#![warn(missing_docs)]

pub mod cesr_adapter;
pub mod derivation;
pub mod error;
pub mod sad;
pub mod version;

use core::{fmt, str::FromStr};

use cesrox::{derivation_code::DerivationCode, primitives::CesrPrimitive};
use indexmap::IndexMap;
use sad::SerializationFormats;
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
use version::{error::Error, SerializationInfo};

use self::derivation::HashFunction;
use crate::derivation::HashFunctionCode;

/// Self Addressing Identifier
///
/// Self-addressing is a digest/hash of data.
#[derive(PartialEq, Clone, Hash, Eq, Default)]
pub struct SelfAddressingIdentifier {
    /// Hash algorithm used for computing digest
    pub derivation: HashFunction,
    /// Computed digest
    pub digest: Vec<u8>,
}

impl fmt::Debug for SelfAddressingIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_str())
    }
}

impl SelfAddressingIdentifier {
    /// A SAID from its hash function and digest bytes.
    pub fn new(code: HashFunction, digest: Vec<u8>) -> Self {
        Self {
            derivation: code,
            digest,
        }
    }

    /// Whether this is the SAID of `sed`, the serialized data with `#`
    /// placeholders in its SAID fields.
    pub fn verify_binding(&self, sed: &[u8]) -> bool {
        self.derivation.digest(sed) == self.digest
    }
}

impl fmt::Display for SelfAddressingIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

/// Serde compatible Serialize
impl Serialize for SelfAddressingIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for SelfAddressingIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<SelfAddressingIdentifier, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        SelfAddressingIdentifier::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Protocol and version written into a version string by [`make_me_sad`].
pub struct ProtocolVersion {
    pub(crate) prefix: String,
    pub(crate) major: u8,
    pub(crate) minor: u16,
}

impl ProtocolVersion {
    /// A protocol version; `prefix` is the four-letter protocol code, such
    /// as `KERI`.
    pub fn new(prefix: &str, major: u8, minor: u16) -> Result<Self, Error> {
        if prefix.len() == 4 {
            Ok(Self {
                prefix: prefix.to_string(),
                major,
                minor,
            })
        } else {
            Err(Error::VersionStringLength(prefix.to_string()))
        }
    }
}

/// A self-addressing data map. Field order is kept as given, because the
/// serialization the SAID is computed over depends on it.
pub type Sad = IndexMap<String, serde_json::Value>;

/// Computes the SAID of `sad` serialized as `format` and puts it into each
/// field named in `labels`: usually `d`, or `d` and `i` when an identifier
/// is its own SAID. While the digest is computed, those fields hold `#`
/// placeholders of the SAID's length. If `sad` has a version string in
/// `v`, its kind is set to `format` and its size to the length of the
/// serialization. Returns the SAID and the serialized SAD.
pub fn saidify(
    sad: &mut Sad,
    code: HashFunctionCode,
    format: SerializationFormats,
    labels: &[&str],
) -> Result<(SelfAddressingIdentifier, Vec<u8>), Error> {
    if labels.is_empty() {
        return Err(Error::MissingField("no SAID field given".into()));
    }
    let placeholder = serde_json::Value::String("#".repeat(code.full_size()));
    for label in labels {
        let field = sad
            .get_mut(*label)
            .ok_or_else(|| Error::MissingField((*label).into()))?;
        *field = placeholder.clone();
    }

    if let Some(version) = sad.get("v") {
        let mut info: SerializationInfo = version
            .as_str()
            .ok_or_else(|| Error::DeserializeError("v is not a version string".into()))?
            .parse()?;
        // the size field has a fixed width, so the length is the same after
        // it is filled in
        info.kind = format;
        info.size = 0;
        sad.insert("v".into(), info.to_str().into());
        info.size = format.encode(sad)?.len();
        sad.insert("v".into(), info.to_str().into());
    }

    let said = HashFunction::from(code).derive(&format.encode(sad)?);
    for label in labels {
        sad.insert((*label).into(), said.to_string().into());
    }
    let serialized = format.encode(sad)?;
    Ok((said, serialized))
}

/// [`saidify`] for any type that serializes as a map: `value` is serialized,
/// its SAID computed into the fields named in `labels` and read back into
/// `value`. Field names are those of the serialization, so serde renames
/// apply. SAID fields must be serialized even while they are empty, for
/// example as an `Option` without `skip_serializing_if`; a version string
/// is a [`SerializationInfo`] field named `v`. Returns the SAID and the
/// serialized message.
///
/// ```
/// use said::{derivation::HashFunctionCode, sad::SerializationFormats, saidify_value};
/// use said::{version::SerializationInfo, SelfAddressingIdentifier};
///
/// #[derive(serde::Serialize, serde::Deserialize)]
/// struct Event {
///     v: SerializationInfo,
///     d: Option<SelfAddressingIdentifier>,
///     text: String,
/// }
///
/// let format = SerializationFormats::JSON;
/// let mut event = Event {
///     v: SerializationInfo::new_empty("KERI".into(), 2, 0, format),
///     d: None,
///     text: "Hello".into(),
/// };
/// let (said, message) =
///     saidify_value(&mut event, HashFunctionCode::Blake3_256, format, &["d"]).unwrap();
/// assert_eq!(event.d, Some(said));
/// assert_eq!(event.v.size, message.len());
/// ```
pub fn saidify_value<T: Serialize + DeserializeOwned>(
    value: &mut T,
    code: HashFunctionCode,
    format: SerializationFormats,
    labels: &[&str],
) -> Result<(SelfAddressingIdentifier, Vec<u8>), Error> {
    let mut sad: Sad = match serde_json::to_value(&*value) {
        Ok(serde_json::Value::Object(map)) => map.into_iter().collect(),
        Ok(_) => return Err(Error::SerializationError("not a map".into())),
        Err(e) => return Err(Error::SerializationError(e.to_string())),
    };
    let (said, serialized) = saidify(&mut sad, code, format, labels)?;
    *value = serde_json::to_value(&sad)
        .and_then(serde_json::from_value)
        .map_err(|e| Error::DeserializeError(e.to_string()))?;
    Ok((said, serialized))
}

/// Checks a message received as `format`: every field named in `labels`
/// holds the same SAID, and it is the SAID of the message as received. The
/// message must be in the form its SAID is computed over: compact JSON, or
/// CBOR and MessagePack as said writes them, and the size and kind of a
/// version string in `v` must match. Returns the SAID.
///
/// ```
/// use said::{derivation::HashFunctionCode, sad::SerializationFormats, saidify, verify, Sad};
///
/// let format = SerializationFormats::JSON;
/// let mut sad: Sad = serde_json::from_str(r#"{"d":"","text":"Hello"}"#).unwrap();
/// let (said, message) = saidify(&mut sad, HashFunctionCode::Blake3_256, format, &["d"]).unwrap();
///
/// assert_eq!(verify(&message, format, &["d"]).unwrap(), said);
/// let forged = String::from_utf8(message).unwrap().replace("Hello", "Hallo");
/// assert!(verify(forged.as_bytes(), format, &["d"]).is_err());
/// ```
pub fn verify(
    message: &[u8],
    format: SerializationFormats,
    labels: &[&str],
) -> Result<SelfAddressingIdentifier, Error> {
    let mut sad: Sad = match format {
        SerializationFormats::JSON => {
            serde_json::from_slice(message).map_err(|_| Error::JsonDeserError)
        }
        SerializationFormats::CBOR => {
            serde_cbor::from_slice(message).map_err(|_| Error::CborDeserError)
        }
        SerializationFormats::MGPK => {
            rmp_serde::from_slice(message).map_err(|_| Error::MsgPackDeserError)
        }
        _ => Err(Error::DeserializeError(
            "native CESR messages are not supported".into(),
        )),
    }?;
    // the SAID is computed over this exact serialization, so another
    // encoding of the same map, such as JSON with whitespace, is rejected
    // rather than verified against bytes that were never sent
    if format.encode(&sad)? != message {
        return Err(Error::InvalidSaid(
            "not in its canonical serialization".into(),
        ));
    }
    if let Some(version) = sad.get("v") {
        let info: SerializationInfo = version
            .as_str()
            .ok_or_else(|| Error::DeserializeError("v is not a version string".into()))?
            .parse()?;
        if info.kind != format || info.size != message.len() {
            return Err(Error::InvalidSaid(format!(
                "version string {} does not describe this message",
                info.to_str()
            )));
        }
    }

    let mut said: Option<SelfAddressingIdentifier> = None;
    for label in labels {
        let field = sad
            .get_mut(*label)
            .ok_or_else(|| Error::MissingField((*label).into()))?;
        let value: SelfAddressingIdentifier = field
            .as_str()
            .ok_or_else(|| Error::InvalidSaid(format!("{label} is not a SAID")))?
            .parse()
            .map_err(|_| Error::InvalidSaid(format!("{label} is not a SAID")))?;
        *field = serde_json::Value::String(
            "#".repeat(HashFunctionCode::from(&value.derivation).full_size()),
        );
        match &said {
            Some(said) if *said != value => {
                return Err(Error::InvalidSaid(format!("{label} holds another SAID")))
            }
            _ => said = Some(value),
        }
    }
    let said = said.ok_or_else(|| Error::MissingField("no SAID field given".into()))?;
    if said.verify_binding(&format.encode(&sad)?) {
        Ok(said)
    } else {
        Err(Error::InvalidSaid("digest does not match".into()))
    }
}

/// Computes the SAID of a JSON map and puts it into `field_name`, `d` by
/// default. Fails if the field is missing.
pub fn make_me_happy(
    input: &str,
    derivation: HashFunctionCode,
    field_name: Option<&str>,
) -> Result<String, Error> {
    let mut sad: Sad =
        serde_json::from_str(input).map_err(|e| Error::DeserializeError(e.to_string()))?;
    let (_, out) = saidify(
        &mut sad,
        derivation,
        SerializationFormats::JSON,
        &[field_name.unwrap_or("d")],
    )?;
    String::from_utf8(out).map_err(|e| Error::SerializationError(e.to_string()))
}

/// Puts a version string for `version_str` as the first field `v` of a
/// JSON map, replacing any `v` it has, then computes its SAID into
/// `field_name`, `d` by default.
pub fn make_me_sad(
    input: &str,
    derivation: HashFunctionCode,
    version_str: ProtocolVersion,
    field_name: Option<&str>,
) -> Result<String, Error> {
    let mut data: Sad =
        serde_json::from_str(input).map_err(|e| Error::DeserializeError(e.to_string()))?;
    data.shift_remove("v");
    let version = SerializationInfo::new(
        version_str.prefix.to_string(),
        version_str.major,
        version_str.minor,
        sad::SerializationFormats::JSON,
        0,
    );
    let mut sad: Sad = [("v".to_string(), version.to_str().into())]
        .into_iter()
        .collect();
    sad.extend(data);
    let (_, out) = saidify(
        &mut sad,
        derivation,
        SerializationFormats::JSON,
        &[field_name.unwrap_or("d")],
    )?;
    String::from_utf8(out).map_err(|e| Error::SerializationError(e.to_string()))
}

#[test]
fn test_add_version() {
    let input_str = r#"{"v":"","hi":"there","d":"","blah":"blah"}"#;
    let protocol_version = ProtocolVersion::new("DKMS", 0, 0).unwrap();
    let json_with_version = make_me_sad(
        input_str,
        HashFunctionCode::Blake3_256,
        protocol_version,
        None,
    )
    .unwrap();
    assert_eq!(
        json_with_version,
        r#"{"v":"DKMS00JSON000067_","hi":"there","d":"EEjVw3gkdhqfHoLypHgpKtxWvK9II8B91g6EAP5Scdtb","blah":"blah"}"#
    );

    let mut map: IndexMap<String, String> = serde_json::from_str(&json_with_version).unwrap();
    // Check size
    let version: SerializationInfo = map.get("v").unwrap().parse().unwrap();
    assert_eq!(version.size, json_with_version.len());

    // Check digest
    let digest: SelfAddressingIdentifier = map.get("d").unwrap().parse().unwrap();
    let placeholder = "#".repeat(HashFunctionCode::Blake3_256.full_size());
    map.insert("d".to_string(), placeholder);
    let der_data = serde_json::to_vec(&map).unwrap();
    assert!(digest.verify_binding(&der_data));
}
