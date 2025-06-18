use std::str::FromStr;

use nom::{
    bytes::complete::take,
    character::complete::anychar,
    error::{make_error, ErrorKind},
    IResult,
};

use crate::{
    conversion::{adjust_with_num, b64_to_num, num_to_b64},
    derivation_code::DerivationCode,
    error::Error,
    primitives::codes::PrimitiveCode,
};

#[derive(Debug, PartialEq)]
pub enum UniversalGroupCode {
    /// Universal Genus Version Codes
    Genus(GenusCountCode),
    /// Universal Count Codes that allow genus/version override
    Special {
        code: SpecialCountCode,
        quadlets: u16,
    },
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
            x if x.is_alphabetic() => {
                let length = s.get(1..3).ok_or(Error::EmptyCodeError)?;
                let length = b64_to_num(length.as_bytes())?;
                let special_code = SpecialCountCode::from_str(&code.to_string())?;
                Ok(Self::Special {
                    code: special_code,
                    quadlets: length.into(),
                })
            }
            _ => Err(Error::UnknownCodeError),
        }
    }
}

#[derive(PartialEq, Debug)]
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
                let major = b64_to_num(major_version.as_bytes())?;
                let minor = b64_to_num(minor_version.as_bytes())?;
                Ok(Self::Keri { minor, major })
            }
            _ => Err(Error::UnknownCodeError),
        }
    }
}

impl ToString for GenusCountCode {
    fn to_string(&self) -> String {
        match self {
            GenusCountCode::Keri { minor, major } => {
                format!("_AAA{}{}", num_to_b64(*major), adjust_with_num(*minor, 2))
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

#[derive(Debug, PartialEq)]
pub enum SpecialCountCode {
    /// Generic pipeline group up to 4,095 quadlets/triplets
    GenericPipeline,
    /// Attachments only group up to 4,095 quadlets/triplets
    Attachments,
}

impl FromStr for SpecialCountCode {
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

impl ToString for SpecialCountCode {
    fn to_string(&self) -> String {
        match self {
            SpecialCountCode::GenericPipeline => "A".to_string(),
            SpecialCountCode::Attachments => "C".to_string(),
        }
    }
}

impl DerivationCode for UniversalGroupCode {
    fn hard_size(&self) -> usize {
        match self {
            UniversalGroupCode::Genus(_genus_count_code) => 8,
            UniversalGroupCode::Special { code, quadlets: _ } => match code {
                SpecialCountCode::GenericPipeline => 2,
                SpecialCountCode::Attachments => 2,
            },
        }
    }

    fn soft_size(&self) -> usize {
        match self {
            UniversalGroupCode::Genus(_genus_count_code) => 0,
            UniversalGroupCode::Special {
                code: _,
                quadlets: _,
            } => 2,
        }
    }

    fn value_size(&self) -> usize {
        match self {
            UniversalGroupCode::Genus(_) => 0,
            UniversalGroupCode::Special { code, quadlets } => (*quadlets as usize).clone(),
        }
    }

    fn to_str(&self) -> String {
        match self {
            UniversalGroupCode::Genus(genus_count_code) => genus_count_code.to_string(),
            UniversalGroupCode::Special { code, quadlets } => format!(
                "{}{}",
                code.to_string(),
                adjust_with_num(quadlets.clone(), 2)
            ),
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
