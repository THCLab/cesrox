use std::str::FromStr;

use crate::{conversion::from_bytes_to_text, derivation_code::DerivationCode, error::Error};

#[derive(PartialEq, Eq, Debug)]
pub struct SerialNumberCode;

impl DerivationCode for SerialNumberCode {
    fn hard_size(&self) -> usize {
        2
    }

    fn soft_size(&self) -> usize {
        0
    }

    fn value_size(&self) -> usize {
        22
    }

    fn to_str(&self) -> String {
        "0A".into()
    }
}

impl FromStr for SerialNumberCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = s.get(..2).ok_or(Error::EmptyCodeError)?;

        match code {
            "0A" => Ok(SerialNumberCode),
            _ => Err(Error::UnknownCodeError),
        }
    }
}

pub fn pack_sn(sn: u64) -> String {
    let payload_type = SerialNumberCode;
    let sn_raw: Vec<u8> = sn.to_be_bytes().into();

    // Calculate how many zeros are missing to achieve expected base64 string
    // length. Master code size is expected padding size.
    let missing_zeros = payload_type.full_size() / 4 * 3 - payload_type.code_size() - sn_raw.len();
    let sn_vec: Vec<u8> = std::iter::repeat(0)
        .take(missing_zeros)
        .chain(sn_raw)
        .collect();
    [
        payload_type.to_str(),
        from_bytes_to_text(&sn_vec)[2..].to_string(),
    ]
    .join("")
}

#[test]
pub fn test_pack_sn() -> Result<(), Error> {
    assert_eq!(pack_sn(1), "0AAAAAAAAAAAAAAAAAAAAAAB");
    assert_eq!(pack_sn(64), "0AAAAAAAAAAAAAAAAAAAAABA");
    assert_eq!(pack_sn(1000), "0AAAAAAAAAAAAAAAAAAAAAPo");

    Ok(())
}
