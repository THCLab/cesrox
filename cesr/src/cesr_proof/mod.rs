use base64::prelude::*;
use serde::Deserialize;

use crate::{
    conversion::from_bytes_to_text,
    variable_length::{
        LeadBytes, SmallVariableLengthCode, VariableLengthCode, VariableLengthPrimitive,
    },
};

use super::error::Error;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(try_from = "UncheckedMaterialPath")]
pub struct MaterialPath {
    lead_bytes: usize,
    // base64 representation of path string
    base: String,
}

/// Deserialized form of [`MaterialPath`], checked before it is accepted.
#[derive(Deserialize)]
struct UncheckedMaterialPath {
    lead_bytes: usize,
    base: String,
}

impl TryFrom<UncheckedMaterialPath> for MaterialPath {
    type Error = Error;

    fn try_from(path: UncheckedMaterialPath) -> Result<Self, Self::Error> {
        if path.lead_bytes > 2 {
            return Err(Error::IncorrectLength(format!(
                "{} lead bytes",
                path.lead_bytes
            )));
        }
        if !path.base.len().is_multiple_of(4) {
            return Err(Error::IncorrectLength(path.base));
        }
        BASE64_URL_SAFE_NO_PAD.decode(&path.base)?;
        Ok(MaterialPath {
            lead_bytes: path.lead_bytes,
            base: path.base,
        })
    }
}

impl MaterialPath {
    pub fn new(lb: LeadBytes, path: String) -> Self {
        let lead_bytes = match lb {
            LeadBytes::Zero => 0,
            LeadBytes::One => 1,
            LeadBytes::Two => 2,
        };
        MaterialPath {
            lead_bytes,
            base: path,
        }
    }

    fn lead_bytes(&self) -> LeadBytes {
        match self.lead_bytes {
            0 => LeadBytes::Zero,
            1 => LeadBytes::One,
            // constructors and deserialization only allow 0 to 2
            _ => LeadBytes::Two,
        }
    }

    pub fn create_from_str(path: String) -> Self {
        let primitive =
            VariableLengthPrimitive::create_from_str(SmallVariableLengthCode::Base64String, &path);

        Self {
            base: from_bytes_to_text(primitive.value()),
            lead_bytes: primitive.code().lead_bytes() as usize,
        }
    }

    pub fn to_cesr(&self) -> String {
        let size = self.base.len() / 4;
        let code = VariableLengthCode::Small {
            lb: self.lead_bytes(),
            code: SmallVariableLengthCode::Base64String,
            length: size as u16,
        };
        [code.to_cesr(), self.base.clone()].join("")
    }

    pub fn to_raw(&self) -> Result<Vec<u8>, Error> {
        let decoded_base = BASE64_URL_SAFE_NO_PAD.decode(&self.base)?;
        let raw = decoded_base
            .get(self.lead_bytes..)
            .ok_or_else(|| Error::IncorrectLength(self.base.clone()))?;
        Ok(raw.to_vec())
    }
}

#[test]
pub fn test_path_to_cesr() -> Result<(), Error> {
    assert_eq!(
        MaterialPath::create_from_str("-".into()).to_cesr(),
        "6AABAAA-"
    );
    assert_eq!(
        MaterialPath::create_from_str("-A".into()).to_cesr(),
        "5AABAA-A"
    );
    assert_eq!(
        MaterialPath::create_from_str("-A-".into()).to_cesr(),
        "4AABA-A-"
    );
    assert_eq!(
        MaterialPath::create_from_str("-A-B".into()).to_cesr(),
        "4AAB-A-B"
    );
    assert_eq!(
        MaterialPath::create_from_str("-a-b-c".into()).to_cesr(),
        "5AACAA-a-b-c"
    );

    assert_eq!(
        MaterialPath::create_from_str("-field0".into()).to_cesr(),
        "4AACA-field0"
    );

    assert_eq!(
        MaterialPath::create_from_str("-field0-field1-field3".into()).to_cesr(),
        "6AAGAAA-field0-field1-field3"
    );

    Ok(())
}
