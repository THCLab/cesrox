use std::{fmt::Display, str::FromStr};

use nom::bytes::complete::take;

use crate::{
    conversion::{adjust_with_num, b64_to_num, num_to_b64},
    derivation_code::DerivationCode,
    error::Error,
    parsing::{ascii, code_error, error, PResult},
    value::Value,
};

#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum UniversalGroupCode {
    /// Universal Genus Version Codes
    Genus(GenusCountCode),
    /// Universal Count Codes that allow genus/version override
    OverrideAllowed {
        code: CustomizableCode,
        quadlets: u16,
    },
    /// Universal Count Codes that do not allow genus/version override
    OverrideNotAllowed { code: FixedCode, quadlets: u16 },
}

pub fn generic_pipeline(values: Vec<Value>) -> Value {
    let data_len: usize = values.iter().map(|v| v.to_string().len()).sum();
    let universal_group_code = UniversalGroupCode::OverrideAllowed {
        code: CustomizableCode::GenericPipeline,
        quadlets: (data_len / 4) as u16,
    };

    Value::UniversalGroup(universal_group_code, values)
}

impl FromStr for UniversalGroupCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = s.chars().next().ok_or(Error::Truncated)?;
        match code {
            '_' => {
                let genus_code = s.get(1..3).ok_or(Error::Truncated)?;
                let group_code = GenusCountCode::from_str(genus_code)?;
                Ok(Self::Genus(group_code))
            }
            'A' | 'B' | 'C' => {
                let length = s.get(1..3).ok_or(Error::Truncated)?;
                let quadlets = b64_to_num(length)?;
                let special_code = CustomizableCode::from_str(&code.to_string())?;
                Ok(Self::OverrideAllowed {
                    code: special_code,
                    quadlets,
                })
            }
            x if x.is_alphabetic() => {
                let length = s.get(1..3).ok_or(Error::Truncated)?;
                let quadlets = b64_to_num(length)?;
                let special_code = FixedCode::from_str(&code.to_string())?;
                Ok(Self::OverrideNotAllowed {
                    code: special_code,
                    quadlets,
                })
            }
            _ => Err(Error::UnknownCode),
        }
    }
}

impl Display for UniversalGroupCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UniversalGroupCode::Genus(genus_count_code) => write!(f, "{}", genus_count_code),
            UniversalGroupCode::OverrideAllowed { code, quadlets } => {
                write!(f, "{}{}", code, adjust_with_num(*quadlets, 2))
            }
            UniversalGroupCode::OverrideNotAllowed { code, quadlets } => {
                write!(f, "{}{}", code, adjust_with_num(*quadlets, 2))
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
pub(crate) fn short_universal_group_code(s: &[u8]) -> PResult<'_, UniversalGroupCode> {
    let (rest, payload_type) = take(3u8)(s)?;
    match UniversalGroupCode::from_str(ascii(payload_type)) {
        Ok(code) => Ok((rest, code)),
        Err(e) => error(s, code_error(payload_type, e)),
    }
}

#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum CustomizableCode {
    /// Generic pipeline group up to 4,095 quadlets/triplets
    GenericPipeline,
    /// Attachments only group up to 4,095 quadlets/triplets
    Attachments,
}

impl FromStr for CustomizableCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = s.get(..1).ok_or(Error::Truncated)?;
        match code {
            "A" => Ok(Self::GenericPipeline),
            "C" => Ok(Self::Attachments),
            _ => Err(Error::UnknownCode),
        }
    }
}

impl Display for CustomizableCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CustomizableCode::GenericPipeline => write!(f, "A"),
            CustomizableCode::Attachments => write!(f, "C"),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
#[non_exhaustive]
pub enum FixedCode {
    /// ESSR wrapper signable up to 4,095 quadlets/triplets
    Essr,
}

impl FromStr for FixedCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = s.get(..1).ok_or(Error::Truncated)?;
        match code {
            "E" => Ok(Self::Essr),
            _ => Err(Error::UnknownCode),
        }
    }
}

impl Display for FixedCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FixedCode::Essr => write!(f, "E"),
        }
    }
}

impl DerivationCode for UniversalGroupCode {
    fn hard_size(&self) -> usize {
        match self {
            UniversalGroupCode::Genus(_genus_count_code) => 8,
            UniversalGroupCode::OverrideAllowed { code, quadlets: _ } => match code {
                CustomizableCode::GenericPipeline => 2,
                CustomizableCode::Attachments => 2,
            },
            UniversalGroupCode::OverrideNotAllowed { .. } => 2,
        }
    }

    fn soft_size(&self) -> usize {
        match self {
            UniversalGroupCode::Genus(_genus_count_code) => 0,
            UniversalGroupCode::OverrideAllowed { .. } => 2,
            UniversalGroupCode::OverrideNotAllowed { .. } => 2,
        }
    }

    fn value_size(&self) -> usize {
        match self {
            UniversalGroupCode::Genus(_) => 0,
            UniversalGroupCode::OverrideAllowed { quadlets, .. } => *quadlets as usize,
            UniversalGroupCode::OverrideNotAllowed { quadlets, .. } => *quadlets as usize,
        }
    }

    fn to_str(&self) -> String {
        match self {
            UniversalGroupCode::Genus(genus_count_code) => genus_count_code.to_string(),
            UniversalGroupCode::OverrideAllowed { code, quadlets } => {
                format!("{}{}", code, adjust_with_num(*quadlets, 2))
            }
            UniversalGroupCode::OverrideNotAllowed { code, quadlets } => {
                format!("{}{}", code, adjust_with_num(*quadlets, 2))
            }
        }
    }
}
