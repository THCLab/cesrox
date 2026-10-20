use std::{fmt::Display, str::FromStr};

use nom::bytes::complete::take;

use crate::{
    conversion::{adjust_with_num, b64_to_num, from_bytes_to_text, from_text_to_bytes},
    error::Error,
    parsing::{ascii, error, PResult},
};

#[cfg(test)]
use crate::parsing::on_text;

#[allow(clippy::enum_variant_names)]
pub enum VariableCodeSelector {
    ShortZeroLeadBytes,
    ShortOneLeadBytes,
    ShortTwoLeadBytes,
    LongZeroLeadBytes,
    LongOneLeadBytes,
    LongTwoLeadBytes,
}

impl VariableCodeSelector {
    pub fn type_len(&self) -> u8 {
        match self {
            VariableCodeSelector::ShortZeroLeadBytes
            | VariableCodeSelector::ShortOneLeadBytes
            | VariableCodeSelector::ShortTwoLeadBytes => 1,
            VariableCodeSelector::LongZeroLeadBytes
            | VariableCodeSelector::LongOneLeadBytes
            | VariableCodeSelector::LongTwoLeadBytes => 3,
        }
    }

    pub fn counter_len(&self) -> u8 {
        match self {
            VariableCodeSelector::ShortZeroLeadBytes
            | VariableCodeSelector::ShortOneLeadBytes
            | VariableCodeSelector::ShortTwoLeadBytes => 2,
            VariableCodeSelector::LongZeroLeadBytes
            | VariableCodeSelector::LongOneLeadBytes
            | VariableCodeSelector::LongTwoLeadBytes => 4,
        }
    }

    pub fn lead_bytes(&self) -> LeadBytes {
        match self {
            VariableCodeSelector::ShortZeroLeadBytes | VariableCodeSelector::LongZeroLeadBytes => {
                LeadBytes::Zero
            }
            VariableCodeSelector::ShortOneLeadBytes | VariableCodeSelector::LongOneLeadBytes => {
                LeadBytes::One
            }
            VariableCodeSelector::ShortTwoLeadBytes | VariableCodeSelector::LongTwoLeadBytes => {
                LeadBytes::Two
            }
        }
    }
}
impl Display for VariableCodeSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            VariableCodeSelector::ShortZeroLeadBytes => "4",
            VariableCodeSelector::ShortOneLeadBytes => "5",
            VariableCodeSelector::ShortTwoLeadBytes => "6",
            VariableCodeSelector::LongZeroLeadBytes => "7",
            VariableCodeSelector::LongOneLeadBytes => "8",
            VariableCodeSelector::LongTwoLeadBytes => "9",
        })
    }
}

impl FromStr for VariableCodeSelector {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "4" => Ok(VariableCodeSelector::ShortZeroLeadBytes),
            "5" => Ok(VariableCodeSelector::ShortOneLeadBytes),
            "6" => Ok(VariableCodeSelector::ShortTwoLeadBytes),
            "7" => Ok(VariableCodeSelector::LongZeroLeadBytes),
            "8" => Ok(VariableCodeSelector::LongOneLeadBytes),
            "9" => Ok(VariableCodeSelector::LongTwoLeadBytes),
            _ => Err(Error::UnknownCode),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq)]
pub enum LeadBytes {
    Zero,
    One,
    Two,
}

/// What a variable-length primitive holds; the last character of its code.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[non_exhaustive]
pub enum VariableLengthType {
    /// `A`, text of Base64 characters only.
    Base64String,
    /// `B`, arbitrary bytes.
    Bytes,
    /// `C`, X25519 sealed box cipher of arbitrary bytes.
    X25519Cipher,
    /// `D`, X25519 sealed box cipher of a text-domain primitive.
    X25519CipherQb64,
    /// `E`, X25519 sealed box cipher of a binary-domain primitive.
    X25519CipherQb2,
    /// `F`, HPKE base mode cipher.
    HpkeBaseCipher,
    /// `H`, decimal number as text.
    Decimal,
}

const TYPES: [(VariableLengthType, &str); 7] = [
    (VariableLengthType::Base64String, "A"),
    (VariableLengthType::Bytes, "B"),
    (VariableLengthType::X25519Cipher, "C"),
    (VariableLengthType::X25519CipherQb64, "D"),
    (VariableLengthType::X25519CipherQb2, "E"),
    (VariableLengthType::HpkeBaseCipher, "F"),
    (VariableLengthType::Decimal, "H"),
];

impl Display for VariableLengthType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = TYPES
            .iter()
            .find(|(code, _)| code == self)
            .map(|(_, text)| *text)
            .unwrap_or_default();
        f.write_str(text)
    }
}

impl FromStr for VariableLengthType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        TYPES
            .iter()
            .find(|(_, text)| *text == s)
            .map(|(code, _)| *code)
            .ok_or(Error::UnknownCode)
    }
}

/// Most quadlets a small code can count; larger values use a big code.
const SMALL_MAX: u32 = 4095;
/// Most quadlets a big code can count.
pub const MAX_QUADLETS: u32 = 16_777_215;

#[derive(Debug, PartialEq, Clone)]
pub struct VariableLengthPrimitive {
    code: VariableLengthCode,
    value: Vec<u8>,
}

impl VariableLengthPrimitive {
    pub fn new(code: VariableLengthCode, value: Vec<u8>) -> Self {
        VariableLengthPrimitive { code, value }
    }
    /// Builds a primitive from base64 text, e.g. a path such as `-a-b`.
    /// Fails if `encoded_value` is not base64.
    pub fn create_from_str(
        code: VariableLengthType,
        encoded_value: &str,
    ) -> Result<VariableLengthPrimitive, Error> {
        let len_modulo = encoded_value.len() % 4;
        let leading_bytes = (3 - (len_modulo % 3)) % 3;
        let bytes = from_text_to_bytes(encoded_value)?;
        let lb = match leading_bytes {
            0 => LeadBytes::Zero,
            1 => LeadBytes::One,
            _ => LeadBytes::Two,
        };
        let value = bytes
            .get(leading_bytes..)
            .ok_or_else(|| Error::IncorrectLength(encoded_value.to_string()))?
            .to_vec();

        let quadlets = if len_modulo == 0 {
            encoded_value.len() / 4
        } else {
            (encoded_value.len() + 4 - len_modulo) / 4
        };

        Ok(VariableLengthPrimitive {
            code: VariableLengthCode::sized(lb, code, quadlets)?,
            value,
        })
    }

    /// Builds a primitive holding `value`, choosing a big code when the
    /// value needs more than 4095 quadlets. Fails above 16,777,215.
    pub fn create_from_bytes(
        code: VariableLengthType,
        value: Vec<u8>,
    ) -> Result<VariableLengthPrimitive, Error> {
        let lead_bytes = (3 - (value.len() % 3)) % 3;
        let lb = match lead_bytes {
            0 => LeadBytes::Zero,
            1 => LeadBytes::One,
            _ => LeadBytes::Two,
        };
        let triplets = (value.len() + lead_bytes) / 3;

        Ok(VariableLengthPrimitive {
            code: VariableLengthCode::sized(lb, code, triplets)?,
            value,
        })
    }

    pub fn code(&self) -> &VariableLengthCode {
        &self.code
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn to_cesr(&self) -> String {
        let encoded_value = from_bytes_to_text(&self.value);
        format!("{}{}", self.code.to_cesr(), encoded_value)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum VariableLengthCode {
    /// Up to 4095 quadlets: selector, type and a 2-character length.
    Small {
        lb: LeadBytes,
        code: VariableLengthType,
        length: u16,
    },
    /// Up to 16,777,215 quadlets: selector, `AA`, type and a 4-character
    /// length.
    Large {
        lb: LeadBytes,
        code: VariableLengthType,
        length: u32,
    },
}
impl VariableLengthCode {
    /// The smallest code for `quadlets` quadlets of value.
    fn sized(lb: LeadBytes, code: VariableLengthType, quadlets: usize) -> Result<Self, Error> {
        match u32::try_from(quadlets) {
            Ok(length) if length <= SMALL_MAX => Ok(VariableLengthCode::Small {
                lb,
                code,
                length: length as u16,
            }),
            Ok(length) if length <= MAX_QUADLETS => {
                Ok(VariableLengthCode::Large { lb, code, length })
            }
            _ => Err(Error::IncorrectLength(format!(
                "{quadlets} quadlets, at most {MAX_QUADLETS}"
            ))),
        }
    }

    pub fn quadlets(&self) -> u32 {
        match self {
            VariableLengthCode::Small { length, .. } => *length as u32,
            VariableLengthCode::Large { length, .. } => *length,
        }
    }

    pub fn lead_bytes(&self) -> LeadBytes {
        match self {
            VariableLengthCode::Small { lb, .. } => lb.clone(),
            VariableLengthCode::Large { lb, .. } => lb.clone(),
        }
    }

    pub fn to_cesr(&self) -> String {
        match self {
            VariableLengthCode::Small { lb, code, length } => {
                let selector = match lb {
                    LeadBytes::Zero => VariableCodeSelector::ShortZeroLeadBytes,
                    LeadBytes::One => VariableCodeSelector::ShortOneLeadBytes,
                    LeadBytes::Two => VariableCodeSelector::ShortTwoLeadBytes,
                };
                let quadlets = adjust_with_num(*length, 2);
                format!("{}{}{}", selector, code, quadlets)
            }
            VariableLengthCode::Large { lb, code, length } => {
                let selector = match lb {
                    LeadBytes::Zero => VariableCodeSelector::LongZeroLeadBytes,
                    LeadBytes::One => VariableCodeSelector::LongOneLeadBytes,
                    LeadBytes::Two => VariableCodeSelector::LongTwoLeadBytes,
                };
                let quadlets = adjust_with_num(*length, 4);
                format!("{}AA{}{}", selector, code, quadlets)
            }
        }
    }
}

pub(crate) fn variable_length_code(s: &[u8]) -> PResult<'_, VariableLengthCode> {
    let (more, selector) = take(1u8)(s)?;
    let Ok(selector) = ascii(selector).parse::<VariableCodeSelector>() else {
        return error(s, Error::UnknownCode);
    };

    let (more, code_type) = take(selector.type_len())(more)?;
    let (more, data_len) = take(selector.counter_len())(more)?;
    // big codes are written selector, `AA`, type
    let type_text = ascii(code_type);
    let type_char = match type_text.as_bytes() {
        [b'A', b'A', _] | [_] if type_text.len() == code_type.len() => {
            &type_text[type_text.len() - 1..]
        }
        _ => return error(s, Error::UnknownCode),
    };
    let Ok(code) = type_char.parse::<VariableLengthType>() else {
        return error(s, Error::UnknownCode);
    };
    let Ok(length) = b64_to_num::<u32>(ascii(data_len)) else {
        return error(s, Error::InvalidBase64);
    };

    let lb = selector.lead_bytes();
    Ok((
        more,
        match selector {
            VariableCodeSelector::ShortZeroLeadBytes
            | VariableCodeSelector::ShortOneLeadBytes
            | VariableCodeSelector::ShortTwoLeadBytes => VariableLengthCode::Small {
                lb,
                code,
                length: length as u16,
            },
            VariableCodeSelector::LongZeroLeadBytes
            | VariableCodeSelector::LongOneLeadBytes
            | VariableCodeSelector::LongTwoLeadBytes => {
                VariableLengthCode::Large { lb, code, length }
            }
        },
    ))
}

pub(crate) fn variable_length_value(input: &[u8]) -> PResult<'_, VariableLengthPrimitive> {
    let (rest, code) = variable_length_code(input)?;
    let (rest, value) = take(code.quadlets() * 4)(rest)?;
    let text = ascii(value);
    if text.len() != value.len() {
        return error(input, Error::InvalidBase64);
    }
    let Ok(bytes) = from_text_to_bytes(text) else {
        return error(input, Error::InvalidBase64);
    };
    let lb = match code.lead_bytes() {
        LeadBytes::Zero => 0,
        LeadBytes::One => 1,
        LeadBytes::Two => 2,
    };
    let value = match bytes.split_at_checked(lb) {
        // lead bytes must be zero, or one value has several encodings
        Some((lead, value)) if lead.iter().all(|b| *b == 0) => value.to_vec(),
        Some(_) => return error(input, Error::Invalid("non-zero lead bytes".into())),
        None => return error(input, Error::IncorrectLength(code.to_cesr())),
    };
    Ok((rest, VariableLengthPrimitive::new(code, value)))
}

#[test]
pub fn test_variable_length_code_to_str() -> Result<(), Error> {
    let code = VariableLengthCode::Small {
        lb: LeadBytes::Zero,
        code: VariableLengthType::Bytes,
        length: 5,
    };
    assert_eq!(code.to_cesr(), "4BAF".to_string());

    let code = VariableLengthCode::Small {
        lb: LeadBytes::One,
        code: VariableLengthType::HpkeBaseCipher,
        length: 100,
    };
    assert_eq!(code.to_cesr(), "5FBk".to_string());

    let code = VariableLengthCode::Large {
        lb: LeadBytes::One,
        code: VariableLengthType::HpkeBaseCipher,
        length: 100,
    };
    assert_eq!(code.to_cesr(), "8AAFAABk".to_string());

    let code = VariableLengthCode::Small {
        lb: LeadBytes::Two,
        code: VariableLengthType::Base64String,
        length: 64,
    };
    assert_eq!(code.to_cesr(), "6ABA".to_string());

    Ok(())
}

#[test]
pub fn test_variable_length_code_from_str() -> Result<(), Error> {
    let expected_code = VariableLengthCode::Small {
        lb: LeadBytes::Zero,
        code: VariableLengthType::Bytes,
        length: 5,
    };
    let (rest, parsed_code) = on_text("4BAF", variable_length_code).unwrap();
    assert!(rest.is_empty());
    assert_eq!(expected_code, parsed_code);

    let expected_code = VariableLengthCode::Large {
        lb: LeadBytes::One,
        code: VariableLengthType::HpkeBaseCipher,
        length: 100,
    };
    let (rest, parsed_code) = on_text("8AAFAABk", variable_length_code).unwrap();
    assert!(rest.is_empty());
    assert_eq!(expected_code, parsed_code);

    let expected_code = VariableLengthCode::Small {
        lb: LeadBytes::Zero,
        code: VariableLengthType::Base64String,
        length: 1,
    };
    let (rest, parsed_code) = on_text("4AAB", variable_length_code).unwrap();
    assert!(rest.is_empty());
    assert_eq!(expected_code, parsed_code);

    let expected_code = VariableLengthCode::Small {
        lb: LeadBytes::One,
        code: VariableLengthType::Base64String,
        length: 100,
    };
    let (rest, parsed_code) = on_text("5ABk", variable_length_code).unwrap();
    assert!(rest.is_empty());
    assert_eq!(expected_code, parsed_code);

    let expected_code = VariableLengthCode::Small {
        lb: LeadBytes::Two,
        code: VariableLengthType::Base64String,
        length: 64,
    };
    let (rest, parsed_code) = on_text("6ABA", variable_length_code).unwrap();
    assert!(rest.is_empty());
    assert_eq!(expected_code, parsed_code);

    Ok(())
}

#[test]
pub fn test_to_value() -> Result<(), Error> {
    let ciphertext = vec![
        87, 7, 172, 172, 139, 223, 116, 19, 131, 73, 42, 152, 33, 41, 238, 159, 231, 233, 148, 237,
        32, 92, 218, 168, 166, 237, 197, 201, 19, 214, 0, 210, 168, 225, 71, 226, 229, 202,
    ];
    let variable_len_value: VariableLengthPrimitive =
        VariableLengthPrimitive::create_from_bytes(VariableLengthType::Bytes, ciphertext.clone())?;
    let variable_str = variable_len_value.to_cesr();

    let (rest, parsed_value) = on_text(&variable_str, variable_length_value).unwrap();
    assert_eq!(parsed_value, variable_len_value);
    assert_eq!(parsed_value.value(), &ciphertext);
    assert!(rest.is_empty());

    Ok(())
}

#[test]
fn test_base64_string() {
    use crate::value::{parse_value_at, Value};

    let variable_length_primitive =
        VariableLengthPrimitive::create_from_str(VariableLengthType::Base64String, "-").unwrap();
    let expected_cesr = "6AABAAA-";
    assert_eq!(variable_length_primitive.to_cesr(), expected_cesr);

    let (_, parsed_primitive) = on_text(expected_cesr, |i| {
        parse_value_at(i, crate::parsing::Ctx::new(crate::Counting::Quadlets))
    })
    .unwrap();
    if let Value::VariableLengthRaw(v) = parsed_primitive {
        assert_eq!(v, variable_length_primitive);
    } else {
        unreachable!();
    };

    assert_eq!(
        VariableLengthPrimitive::create_from_str(VariableLengthType::Base64String, "-A")
            .unwrap()
            .to_cesr(),
        "5AABAA-A"
    );
    assert_eq!(
        VariableLengthPrimitive::create_from_str(VariableLengthType::Base64String, "-A-")
            .unwrap()
            .to_cesr(),
        "4AABA-A-"
    );
    assert_eq!(
        VariableLengthPrimitive::create_from_str(VariableLengthType::Base64String, "-A-B")
            .unwrap()
            .to_cesr(),
        "4AAB-A-B"
    );
    assert_eq!(
        VariableLengthPrimitive::create_from_str(VariableLengthType::Base64String, "-a-b-c")
            .unwrap()
            .to_cesr(),
        "5AACAA-a-b-c"
    );
    assert_eq!(
        VariableLengthPrimitive::create_from_str(VariableLengthType::Base64String, "-field0")
            .unwrap()
            .to_cesr(),
        "4AACA-field0"
    );
    assert_eq!(
        VariableLengthPrimitive::create_from_str(
            VariableLengthType::Base64String,
            "-field0-field1-field3"
        )
        .unwrap()
        .to_cesr(),
        "6AAGAAA-field0-field1-field3"
    );
}

#[test]
fn big_values_use_big_codes() -> Result<(), Error> {
    // 5000 quadlets need a big code; one lead byte gives selector 8
    let value = vec![7u8; 5000 * 3 - 1];
    let primitive = VariableLengthPrimitive::create_from_bytes(VariableLengthType::Bytes, value)?;
    let text = primitive.to_cesr();
    assert!(text.starts_with("8AABABOI"), "{}", &text[..8]);
    let (rest, parsed) = on_text(&text, variable_length_value)?;
    assert!(rest.is_empty());
    assert_eq!(parsed, primitive);

    // selector 9: two lead bytes
    let value = vec![1u8; 5000 * 3 - 2];
    let text =
        VariableLengthPrimitive::create_from_bytes(VariableLengthType::Decimal, value)?.to_cesr();
    assert!(text.starts_with("9AAH"));
    assert!(on_text(&text, variable_length_value).is_ok());

    // more than 16,777,215 quadlets cannot be encoded
    let too_big = vec![0u8; MAX_QUADLETS as usize * 3 + 3];
    assert!(
        VariableLengthPrimitive::create_from_bytes(VariableLengthType::Bytes, too_big).is_err()
    );
    Ok(())
}
