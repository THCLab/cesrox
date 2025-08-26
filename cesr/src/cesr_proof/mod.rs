use base64::URL_SAFE;
use serde::Deserialize;

use crate::{
    conversion::from_bytes_to_text,
    variable_length::{
        LeadBytes, SmallVariableLengthCode, VariableLengthCode, VariableLengthPrimitive,
    },
};

use super::error::Error;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MaterialPath {
    lead_bytes: usize,
    // base64 representation of path string
    base: String,
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
            2 => LeadBytes::Two,
            _ => panic!("Invalid lead bytes"),
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
        let decoded_base = base64::decode_config(&self.base, URL_SAFE).unwrap();

        let size = decoded_base.len() / 3;
        let code = VariableLengthCode::Small {
            lb: self.lead_bytes(),
            code: SmallVariableLengthCode::Base64String,
            length: size as u16,
        };
        [code.to_cesr(), self.base.clone()].join("")
    }

    pub fn to_raw(&self) -> Result<Vec<u8>, Error> {
        let decoded_base = base64::decode_config(&self.base, URL_SAFE)?;
        let raw = &decoded_base[self.lead_bytes..];
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
