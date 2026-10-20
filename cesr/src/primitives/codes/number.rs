//! Number primitives: unsigned integers such as sequence numbers, written in
//! the smallest code that holds them.

use std::str::FromStr;

use crate::{conversion::from_bytes_to_text, derivation_code::DerivationCode, error::Error};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NumberCode {
    /// `M`, 2 bytes.
    Short,
    /// `0H`, 4 bytes.
    Long,
    /// `R`, 5 bytes.
    Tall,
    /// `N`, 8 bytes.
    Big,
    /// `S`, 11 bytes.
    Large,
    /// `T`, 14 bytes.
    Great,
    /// `U`, 17 bytes.
    Vast,
}

/// Codes chosen when writing, smallest first. Long is left out: it is as
/// long as Tall but holds a byte less, and keripy never writes it either.
const WRITTEN: [NumberCode; 6] = [
    NumberCode::Short,
    NumberCode::Tall,
    NumberCode::Big,
    NumberCode::Large,
    NumberCode::Great,
    NumberCode::Vast,
];

impl NumberCode {
    /// Size of the number in bytes.
    pub fn raw_size(&self) -> usize {
        match self {
            NumberCode::Short => 2,
            NumberCode::Long => 4,
            NumberCode::Tall => 5,
            NumberCode::Big => 8,
            NumberCode::Large => 11,
            NumberCode::Great => 14,
            NumberCode::Vast => 17,
        }
    }

    /// The smallest code that holds `value`.
    pub fn for_value(value: u128) -> NumberCode {
        let needed = 16 - value.leading_zeros() as usize / 8;
        WRITTEN
            .into_iter()
            .find(|code| code.raw_size() >= needed)
            .unwrap_or(NumberCode::Vast)
    }
}

impl DerivationCode for NumberCode {
    fn hard_size(&self) -> usize {
        self.to_str().len()
    }

    fn soft_size(&self) -> usize {
        0
    }

    fn value_size(&self) -> usize {
        // the raw bytes fill whole quadlets together with the code
        (self.raw_size() + self.hard_size()).div_ceil(3) * 4 - self.hard_size()
    }

    fn to_str(&self) -> String {
        match self {
            NumberCode::Short => "M",
            NumberCode::Long => "0H",
            NumberCode::Tall => "R",
            NumberCode::Big => "N",
            NumberCode::Large => "S",
            NumberCode::Great => "T",
            NumberCode::Vast => "U",
        }
        .into()
    }
}

impl FromStr for NumberCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.get(..1).ok_or(Error::Truncated)? {
            "M" => Ok(NumberCode::Short),
            "R" => Ok(NumberCode::Tall),
            "N" => Ok(NumberCode::Big),
            "S" => Ok(NumberCode::Large),
            "T" => Ok(NumberCode::Great),
            "U" => Ok(NumberCode::Vast),
            "0" => match s.get(1..2).ok_or(Error::Truncated)? {
                "H" => Ok(NumberCode::Long),
                _ => Err(Error::UnknownCode),
            },
            _ => Err(Error::UnknownCode),
        }
    }
}

/// Text of `value` as a Number primitive.
pub fn pack_number(value: u128) -> String {
    let code = NumberCode::for_value(value);
    let bytes = value.to_be_bytes();
    let raw = if code.raw_size() <= 16 {
        bytes[16 - code.raw_size()..].to_vec()
    } else {
        // Vast is one byte wider than u128
        [&[0u8][..], &bytes[..]].concat()
    };
    let text = from_bytes_to_text(&raw);
    // the code replaces the lead characters of the raw text
    [code.to_str(), text[code.hard_size() % 4..].to_string()].concat()
}

/// The value of a Number's raw bytes. Fails if it does not fit in 128 bits.
pub fn number_value(raw: &[u8]) -> Result<u128, Error> {
    let start = raw.len().saturating_sub(16);
    if raw[..start].iter().any(|b| *b != 0) {
        return Err(Error::Invalid("number larger than 128 bits".into()));
    }
    Ok(raw[start..]
        .iter()
        .fold(0u128, |n, b| (n << 8) | u128::from(*b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_the_code_table() {
        // full sizes from the CESR V2 table
        for (code, full) in [
            ("M", 4),
            ("0H", 8),
            ("R", 8),
            ("N", 12),
            ("S", 16),
            ("T", 20),
            ("U", 24),
        ] {
            let parsed: NumberCode = code.parse().unwrap();
            assert_eq!(parsed.full_size(), full, "{code}");
        }
    }

    #[test]
    fn smallest_code_is_used() {
        assert_eq!(pack_number(0), "MAAA");
        assert_eq!(pack_number(1), "MAAB");
        assert_eq!(NumberCode::for_value(0xffff), NumberCode::Short);
        // matches keripy: Tall, not Long, for values over two bytes
        assert_eq!(NumberCode::for_value(0x1_0000), NumberCode::Tall);
        assert_eq!(pack_number(70_000), "RAAAARFw");
        assert_eq!(NumberCode::for_value(0xff_ffff_ffff), NumberCode::Tall);
        assert_eq!(NumberCode::for_value(u64::MAX as u128), NumberCode::Big);
        assert_eq!(NumberCode::for_value(u128::MAX), NumberCode::Vast);
        assert_eq!(pack_number(u128::MAX).len(), 24);
    }

    #[test]
    fn value_round_trip() {
        for value in [0, 1, 255, 65_535, 65_536, u64::MAX as u128, u128::MAX] {
            let code = NumberCode::for_value(value);
            let bytes = value.to_be_bytes();
            let raw = &bytes[16usize.saturating_sub(code.raw_size())..];
            assert_eq!(number_value(raw).unwrap(), value);
        }
        assert!(number_value(&[1; 17]).is_err());
    }
}
