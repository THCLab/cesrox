use std::{fmt::Display, str::FromStr};

use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
};

use crate::{
    conversion::{adjust_with_num, b64_to_num, num_to_b64},
    derivation_code::DerivationCode,
    error::Error,
    value::Value,
};

#[derive(Debug, PartialEq, Clone)]
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
        let code = s.chars().next().ok_or(Error::EmptyCodeError)?;
        match code {
            '_' => {
                let genus_code = s.get(1..3).ok_or(Error::EmptyCodeError)?;
                let group_code = GenusCountCode::from_str(genus_code)?;
                Ok(Self::Genus(group_code))
            }
            'A' | 'B' | 'C' => {
                let length = s.get(1..3).ok_or(Error::EmptyCodeError)?;
                let quadlets = b64_to_num(length)?;
                let special_code = CustomizableCode::from_str(&code.to_string())?;
                Ok(Self::OverrideAllowed {
                    code: special_code,
                    quadlets,
                })
            },
            x if x.is_alphabetic() => {
                let length = s.get(1..3).ok_or(Error::EmptyCodeError)?;
                let quadlets = b64_to_num(length)?;
                let special_code = FixedCode::from_str(&code.to_string())?;
                Ok(Self::OverrideNotAllowed {
                    code: special_code,
                    quadlets,
                })
            },
            _ => Err(Error::UnknownCodeError),
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
pub enum GenusCountCode {
    Keri { minor: u16, major: u16 },
}

impl FromStr for GenusCountCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = s.get(..4).ok_or(Error::EmptyCodeError)?;
        let minor_version = s.get(5..).ok_or(Error::EmptyCodeError)?;
        let major_version = s.get(4..5).ok_or(Error::EmptyCodeError)?;
        match code {
            "_AAA" => {
                let major = b64_to_num(major_version)?;
                let minor = b64_to_num(minor_version)?;
                Ok(Self::Keri { minor, major })
            }
            _ => Err(Error::UnknownCodeError),
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

pub fn genus_code(s: &str) -> nom::IResult<&str, GenusCountCode> {
    let (rest, version_genus) = take(7u8)(s)?;
    let Ok(group_code) = GenusCountCode::from_str(version_genus) else {
        return Err(nom::Err::Error(make_error(s, ErrorKind::IsNot)));
    };
    Ok((rest, group_code))
}

pub fn short_universal_group_code(s: &str) -> nom::IResult<&str, UniversalGroupCode> {
    let (rest, payload_type) = take(3u8)(s)?;
    let Ok(group_code) = UniversalGroupCode::from_str(payload_type) else {
        return Err(nom::Err::Error(make_error(s, ErrorKind::IsNot)));
    };
    Ok((rest, group_code))
}

#[derive(Debug, PartialEq, Clone)]
pub enum CustomizableCode {
    /// Generic pipeline group up to 4,095 quadlets/triplets
    GenericPipeline,
    /// Attachments only group up to 4,095 quadlets/triplets
    Attachments,
}

impl FromStr for CustomizableCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = s.get(..1).ok_or(Error::EmptyCodeError)?;
        match code {
            "A" => Ok(Self::GenericPipeline),
            "C" => Ok(Self::Attachments),
            _ => Err(Error::UnknownCodeError),
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
pub enum FixedCode {
    /// ESSR wrapper signable up to 4,095 quadlets/triplets
    Essr,
}

impl FromStr for FixedCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = s.get(..1).ok_or(Error::EmptyCodeError)?;
        match code {
            "E" => Ok(Self::Essr),
            _ => Err(Error::UnknownCodeError),
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
            UniversalGroupCode::OverrideNotAllowed { code, quadlets } => 2,
        }
    }

    fn soft_size(&self) -> usize {
        match self {
            UniversalGroupCode::Genus(_genus_count_code) => 0,
            UniversalGroupCode::OverrideAllowed {
                code: _,
                quadlets: _,
            } => 2,
            UniversalGroupCode::OverrideNotAllowed { code, quadlets } => 2,
        }
    }

    fn value_size(&self) -> usize {
        match self {
            UniversalGroupCode::Genus(_) => 0,
            UniversalGroupCode::OverrideAllowed { quadlets, .. } => *quadlets as usize,
            UniversalGroupCode::OverrideNotAllowed { code, quadlets } => *quadlets as usize,
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

// pub fn parse_primitive(stream: &str) ->  IResult<&str, PrimitiveCode>{
// 	let (rest, first) = anychar(stream)?;
// 	match first {
// 		x if x.is_alphabetic() => {
// 			// Basic one character code
// 			todo!()
// 		}
// 		'0' | '1' => {
// 			todo!()
// 		}
// 		'4' => {
// 			// Variable raw size code
// 			// Lead size 0
// 			todo!();
// 		},
// 		'5' => {
// 			// Variable raw size code
// 			// Lead size 1
// 			todo!()
// 		}
// 		'6' => {
// 			// Variable raw size code
// 			// Lead size 2
// 			todo!()
// 		}
// 		_ => todo!(),
// 	}
// }
