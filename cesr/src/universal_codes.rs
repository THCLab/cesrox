use std::{fmt::Display, str::FromStr};

use nom::bytes::complete::take;

use crate::{
    conversion::{adjust_with_num, b64_to_num, num_to_b64},
    derivation_code::DerivationCode,
    error::Error,
    parsing::{ascii, code_error, error, PResult},
    value::Value,
};

/// The universal groups every CESR genus has, `-A` to `-J`.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[non_exhaustive]
pub enum UniversalCode {
    /// `-A`, any values.
    GenericGroup,
    /// `-B`, a message body followed by its attachments.
    BodyWithAttachments,
    /// `-C`, the attachments of a message.
    Attachments,
    /// `-D`, a segment of a datagram stream.
    DatagramSegment,
    /// `-E`, an ESSR wrapper.
    EssrWrapper,
    /// `-F`, a native message body as fixed fields in order.
    FixBody,
    /// `-G`, a native message body as a field map: label, value, label, ...
    MapBody,
    /// `-H`, a non-native (JSON, CBOR, MessagePack) message body, enclosed
    /// as one Bytes primitive.
    NonNativeBody,
    /// `-I`, a generic field map: label, value, label, ...
    GenericMap,
    /// `-J`, a generic list.
    GenericList,
}

const LETTERS: [(UniversalCode, char); 10] = [
    (UniversalCode::GenericGroup, 'A'),
    (UniversalCode::BodyWithAttachments, 'B'),
    (UniversalCode::Attachments, 'C'),
    (UniversalCode::DatagramSegment, 'D'),
    (UniversalCode::EssrWrapper, 'E'),
    (UniversalCode::FixBody, 'F'),
    (UniversalCode::MapBody, 'G'),
    (UniversalCode::NonNativeBody, 'H'),
    (UniversalCode::GenericMap, 'I'),
    (UniversalCode::GenericList, 'J'),
];

impl UniversalCode {
    pub fn letter(&self) -> char {
        LETTERS
            .iter()
            .find(|(code, _)| code == self)
            .map(|(_, letter)| *letter)
            .unwrap_or('A')
    }

    pub fn from_letter(letter: char) -> Option<Self> {
        LETTERS
            .iter()
            .find(|(_, l)| *l == letter)
            .map(|(code, _)| *code)
    }

    /// Whether a genus/version code inside the group may switch the code
    /// table, as the spec allows for `-A`, `-B` and `-C`.
    pub fn allows_override(&self) -> bool {
        matches!(
            self,
            UniversalCode::GenericGroup
                | UniversalCode::BodyWithAttachments
                | UniversalCode::Attachments
        )
    }
}

#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum UniversalGroupCode {
    /// Universal Genus Version Codes
    Genus(GenusCountCode),
    /// A universal group occupying `quadlets` quadlets.
    Group { code: UniversalCode, quadlets: u32 },
}

/// A generic group (`-A`) holding `values`.
pub fn generic_pipeline(values: Vec<Value>) -> Value {
    let data_len: usize = values.iter().map(|v| v.to_cesr().len()).sum();
    let universal_group_code = UniversalGroupCode::Group {
        code: UniversalCode::GenericGroup,
        quadlets: (data_len / 4) as u32,
    };

    Value::UniversalGroup(universal_group_code, values)
}

impl FromStr for UniversalGroupCode {
    type Err = Error;

    /// Parses the code without its leading `-`: `A##`, or `-A#####` for
    /// the big form.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (s, count_size) = match s.strip_prefix('-') {
            Some(big) => (big, 5),
            None => (s, 2),
        };
        let letter = s.chars().next().ok_or(Error::Truncated)?;
        if letter == '_' {
            let genus_code = s.get(1..3).ok_or(Error::Truncated)?;
            return Ok(Self::Genus(GenusCountCode::from_str(genus_code)?));
        }
        let code = UniversalCode::from_letter(letter).ok_or(Error::UnknownCode)?;
        let length = s.get(1..1 + count_size).ok_or(Error::Truncated)?;
        Ok(Self::Group {
            code,
            quadlets: b64_to_num(length)?,
        })
    }
}

/// Largest count of a small code; bigger counts use the big form.
const SMALL_MAX: u32 = 4095;

/// The code without its leading `-`, as [`FromStr`] reads it.
impl Display for UniversalGroupCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UniversalGroupCode::Genus(genus_count_code) => write!(f, "{}", genus_count_code),
            UniversalGroupCode::Group { code, quadlets } if *quadlets > SMALL_MAX => {
                write!(f, "-{}{}", code.letter(), adjust_with_num(*quadlets, 5))
            }
            UniversalGroupCode::Group { code, quadlets } => {
                write!(f, "{}{}", code.letter(), adjust_with_num(*quadlets, 2))
            }
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
#[non_exhaustive]
pub enum GenusCountCode {
    Keri { minor: u16, major: u16 },
}

impl FromStr for GenusCountCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = s.get(..4).ok_or(Error::Truncated)?;
        let minor_version = s.get(5..).ok_or(Error::Truncated)?;
        let major_version = s.get(4..5).ok_or(Error::Truncated)?;
        match code {
            "_AAA" => {
                let major = b64_to_num(major_version)?;
                let minor = b64_to_num(minor_version)?;
                Ok(Self::Keri { minor, major })
            }
            _ => Err(Error::UnknownCode),
        }
    }
}
impl Display for GenusCountCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenusCountCode::Keri { minor, major } => {
                write!(
                    f,
                    "_AAA{}{}",
                    num_to_b64(*major),
                    adjust_with_num(*minor, 2)
                )
            }
        }
    }
}

/// Parses a genus/version code; `s` starts after the leading `-`.
pub(crate) fn genus_code(s: &[u8]) -> PResult<'_, GenusCountCode> {
    let (rest, version_genus) = take(7u8)(s)?;
    match GenusCountCode::from_str(ascii(version_genus)) {
        Ok(code) => Ok((rest, code)),
        Err(e) => error(s, code_error(version_genus, e)),
    }
}

/// Parses a universal group code; `s` starts after the leading `-`.
pub(crate) fn universal_group_code(s: &[u8]) -> PResult<'_, UniversalGroupCode> {
    let size: usize = if s.first() == Some(&b'-') { 7 } else { 3 };
    let (rest, payload_type) = take(size)(s)?;
    match UniversalGroupCode::from_str(ascii(payload_type)) {
        Ok(code) => Ok((rest, code)),
        Err(e) => error(s, code_error(payload_type, e)),
    }
}

impl DerivationCode for UniversalGroupCode {
    fn hard_size(&self) -> usize {
        match self {
            UniversalGroupCode::Genus(_) => 8,
            _ if self.value_size() as u32 > SMALL_MAX => 3,
            _ => 2,
        }
    }

    fn soft_size(&self) -> usize {
        match self {
            UniversalGroupCode::Genus(_) => 0,
            _ if self.value_size() as u32 > SMALL_MAX => 5,
            _ => 2,
        }
    }

    /// Size of the group's content in quadlets.
    fn value_size(&self) -> usize {
        match self {
            UniversalGroupCode::Genus(_) => 0,
            UniversalGroupCode::Group { quadlets, .. } => *quadlets as usize,
        }
    }

    fn to_str(&self) -> String {
        self.to_string()
    }
}

#[test]
fn every_universal_code_round_trips() -> Result<(), Error> {
    for (code, letter) in LETTERS {
        for quadlets in [0, 1, 4095, 4096, 1_073_741_823] {
            let group = UniversalGroupCode::Group { code, quadlets };
            let text = group.to_string();
            assert_eq!(text.parse::<UniversalGroupCode>()?, group);
            assert!(text.trim_start_matches('-').starts_with(letter));
        }
    }
    assert!("KAB".parse::<UniversalGroupCode>().is_err());
    Ok(())
}
