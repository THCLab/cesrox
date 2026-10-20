//! Fixed-size primitives without a family of their own: cipher material,
//! salts and short labels, and the special values that carry no data.

use std::str::FromStr;

use crate::{derivation_code::DerivationCode, error::Error};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MaterialCode {
    /// `O`, X25519 private decryption key.
    X25519Private,
    /// `P`, X25519 sealed box cipher of a 44-character seed.
    X25519CipherSeed,
    /// `a`, 256-bit salt, nonce or blinding factor.
    Salt256,
    /// `1AAH`, X25519 sealed box cipher of a 24-character salt.
    X25519CipherSalt,
    /// `V`, one-byte label.
    Label1,
    /// `W`, two-byte label.
    Label2,
}

const MATERIAL: [(MaterialCode, &str, usize); 6] = [
    (MaterialCode::X25519Private, "O", 44),
    (MaterialCode::X25519CipherSeed, "P", 124),
    (MaterialCode::Salt256, "a", 44),
    (MaterialCode::X25519CipherSalt, "1AAH", 100),
    (MaterialCode::Label1, "V", 4),
    (MaterialCode::Label2, "W", 4),
];

impl MaterialCode {
    fn entry(&self) -> (&'static str, usize) {
        MATERIAL
            .iter()
            .find(|(code, _, _)| code == self)
            .map(|(_, text, full)| (*text, *full))
            .unwrap_or(("", 0))
    }
}

impl DerivationCode for MaterialCode {
    fn hard_size(&self) -> usize {
        self.entry().0.len()
    }

    fn soft_size(&self) -> usize {
        0
    }

    fn value_size(&self) -> usize {
        self.entry().1 - self.hard_size()
    }

    fn to_str(&self) -> String {
        self.entry().0.into()
    }

    fn lead_size(&self) -> usize {
        match self {
            MaterialCode::Label1 => 1,
            _ => 0,
        }
    }
}

impl FromStr for MaterialCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hard = match s.get(..1).ok_or(Error::Truncated)? {
            "1" => s.get(..4).ok_or(Error::Truncated)?,
            one => one,
        };
        MATERIAL
            .iter()
            .find(|(_, text, _)| *text == hard)
            .map(|(code, _, _)| *code)
            .ok_or(Error::UnknownCode)
    }
}

/// Values that are only a code: null, booleans, an escape and empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SpecialCode {
    /// `1AAK`
    Null,
    /// `1AAL`
    No,
    /// `1AAM`
    Yes,
    /// `1AAO`
    Escape,
    /// `1AAP`
    Empty,
}

impl DerivationCode for SpecialCode {
    fn hard_size(&self) -> usize {
        4
    }

    fn soft_size(&self) -> usize {
        0
    }

    fn value_size(&self) -> usize {
        0
    }

    fn to_str(&self) -> String {
        match self {
            SpecialCode::Null => "1AAK",
            SpecialCode::No => "1AAL",
            SpecialCode::Yes => "1AAM",
            SpecialCode::Escape => "1AAO",
            SpecialCode::Empty => "1AAP",
        }
        .into()
    }
}

impl FromStr for SpecialCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.get(..4).ok_or(Error::Truncated)? {
            "1AAK" => Ok(SpecialCode::Null),
            "1AAL" => Ok(SpecialCode::No),
            "1AAM" => Ok(SpecialCode::Yes),
            "1AAO" => Ok(SpecialCode::Escape),
            "1AAP" => Ok(SpecialCode::Empty),
            _ => Err(Error::UnknownCode),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{parse_primitive, CesrPrimitive, Primitive};

    #[test]
    fn labels_match_keripy() {
        // encodings produced by keripy's Matter
        for (code, raw, text) in [
            (MaterialCode::Label1, vec![0x41], "VABB"),
            (MaterialCode::Label1, vec![0xff], "VAD_"),
            (MaterialCode::Label2, vec![0x41, 0x42], "WEFC"),
        ] {
            let (parsed, rest) = parse_primitive::<MaterialCode>(text.as_bytes()).unwrap();
            assert!(rest.is_empty());
            assert_eq!(parsed, Primitive::new(code, raw.clone()));
            let primitive: Primitive<crate::primitives::codes::PrimitiveCode> =
                Primitive::new(crate::primitives::codes::PrimitiveCode::Material(code), raw);
            assert_eq!(primitive.to_str(), text);
        }
        // the lead byte of a one-byte label must be zero
        assert!(parse_primitive::<MaterialCode>(b"V_AB").is_err());
    }
}
