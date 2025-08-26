use std::str::FromStr;

use nom::bytes::complete::take;

use crate::{
    conversion::{adjust_with_num, b64_to_num, from_bytes_to_text, from_text_to_bytes},
    error::Error,
};

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
impl ToString for VariableCodeSelector {
    fn to_string(&self) -> String {
        match self {
            VariableCodeSelector::ShortZeroLeadBytes => "4".to_string(),
            VariableCodeSelector::ShortOneLeadBytes => "5".to_string(),
            VariableCodeSelector::ShortTwoLeadBytes => "6".to_string(),
            VariableCodeSelector::LongZeroLeadBytes => "7".to_string(),
            VariableCodeSelector::LongOneLeadBytes => "8".to_string(),
            VariableCodeSelector::LongTwoLeadBytes => "9".to_string(),
        }
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
            _ => todo!("Unknown variable code selector: {}", s),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq)]
pub enum LeadBytes {
    Zero,
    One,
    Two,
}

#[derive(Debug, PartialEq, Clone)]
pub enum SmallVariableLengthCode {
    HPKEBaseCipher,
    HPKEAuthCipher,
    // String Base64 Only
    Base64String,
}

impl ToString for SmallVariableLengthCode {
    fn to_string(&self) -> String {
        match self {
            SmallVariableLengthCode::Base64String => "A".to_string(),
            SmallVariableLengthCode::HPKEBaseCipher => "F".to_string(),
            SmallVariableLengthCode::HPKEAuthCipher => "G".to_string(),
        }
    }
}

impl FromStr for SmallVariableLengthCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "A" => Ok(SmallVariableLengthCode::Base64String),
            "F" => Ok(SmallVariableLengthCode::HPKEBaseCipher),
            "G" => Ok(SmallVariableLengthCode::HPKEAuthCipher),
            _ => Err(Error::UnknownCodeError),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum LargeVariableLengthCode {
    HPKEBaseCipher,
    HPKEAuthCipher,
}

impl ToString for LargeVariableLengthCode {
    fn to_string(&self) -> String {
        match self {
            LargeVariableLengthCode::HPKEBaseCipher => "AAF".to_string(),
            LargeVariableLengthCode::HPKEAuthCipher => "AAG".to_string(),
        }
    }
}

impl FromStr for LargeVariableLengthCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "AAF" => Ok(LargeVariableLengthCode::HPKEBaseCipher),
            "AAG" => Ok(LargeVariableLengthCode::HPKEAuthCipher),
            _ => Err(Error::UnknownCodeError),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct VariableLengthPrimitive {
    code: VariableLengthCode,
    value: Vec<u8>,
}

impl VariableLengthPrimitive {
    pub fn new(code: VariableLengthCode, value: Vec<u8>) -> Self {
        VariableLengthPrimitive { code, value }
    }
    pub fn create_from_str(
        code: SmallVariableLengthCode,
        encoded_value: &str,
    ) -> VariableLengthPrimitive {
        let len_modulo = encoded_value.len() % 4;
        let leading_bytes = (3 - (len_modulo % 3)) % 3;
        let (lb, value) = match leading_bytes {
            0 => (LeadBytes::Zero, from_text_to_bytes(encoded_value).unwrap()),
            1 => (
                LeadBytes::One,
                (&from_text_to_bytes(encoded_value).unwrap()[1..]).to_vec(),
            ),
            2 => (
                LeadBytes::Two,
                (&from_text_to_bytes(encoded_value).unwrap()[2..]).to_vec(),
            ),
            _ => panic!("Invalid leading bytes length"),
        };

        let quadlets = if len_modulo == 0 {
            encoded_value.len() / 4
        } else {
            (encoded_value.len() + 4 - len_modulo) / 4
        };

        VariableLengthPrimitive {
            code: VariableLengthCode::Small {
                lb,
                code,
                length: quadlets as u16,
            },
            value,
        }
    }
    pub fn create_from_bytes(
        code: SmallVariableLengthCode,
        value: Vec<u8>,
    ) -> VariableLengthPrimitive {
        let lead_bytes = 3 - (value.len() % 3);
        let lb = match lead_bytes {
            0 => LeadBytes::Zero,
            1 => LeadBytes::One,
            2 => LeadBytes::Two,
            _ => todo!(),
        };
        let triplets = (value.len() + lead_bytes) / 3;

        let code = VariableLengthCode::Small {
            lb,
            code,
            length: triplets as u16,
        };

        VariableLengthPrimitive { code, value }
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
    Small {
        lb: LeadBytes,
        code: SmallVariableLengthCode,
        length: u16,
    },
    Large {
        lb: LeadBytes,
        code: LargeVariableLengthCode,
        length: u32,
    },
}
impl VariableLengthCode {
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
                format!("{}{}{}", selector.to_string(), code.to_string(), quadlets)
            }
            VariableLengthCode::Large { lb, code, length } => {
                let selector = match lb {
                    LeadBytes::Zero => VariableCodeSelector::LongZeroLeadBytes,
                    LeadBytes::One => VariableCodeSelector::LongOneLeadBytes,
                    LeadBytes::Two => VariableCodeSelector::LongTwoLeadBytes,
                };
                let quadlets = adjust_with_num(*length as u16, 4);
                format!("{}{}{}", selector.to_string(), code.to_string(), quadlets)
            }
        }
    }
}

pub fn variable_length_code(s: &str) -> nom::IResult<&str, VariableLengthCode> {
    let (more, selector) = take(1u8)(s)?;
    let selector: VariableCodeSelector = selector.parse().unwrap();

    let (more, code_type) = take(selector.type_len())(more)?;
    let (more, data_len) = take(selector.counter_len())(more)?;
    let len = b64_to_num(data_len).unwrap();

    match selector {
        VariableCodeSelector::ShortZeroLeadBytes
        | VariableCodeSelector::ShortOneLeadBytes
        | VariableCodeSelector::ShortTwoLeadBytes => {
            let code: SmallVariableLengthCode = code_type.parse().unwrap();
            Ok((
                more,
                VariableLengthCode::Small {
                    lb: selector.lead_bytes(),
                    code,
                    length: len as u16,
                },
            ))
        }
        VariableCodeSelector::LongZeroLeadBytes
        | VariableCodeSelector::LongOneLeadBytes
        | VariableCodeSelector::LongTwoLeadBytes => {
            let code: LargeVariableLengthCode = code_type.parse().unwrap();
            Ok((
                more,
                VariableLengthCode::Large {
                    lb: selector.lead_bytes(),
                    code,
                    length: len as u32,
                },
            ))
        }
    }
}

pub fn variable_length_value(input: &str) -> nom::IResult<&str, VariableLengthPrimitive> {
    let (rest, code) = variable_length_code(input)?;
    let (rest, value) = take(code.quadlets() * 4)(rest)?;
    let bytes = from_text_to_bytes(value).unwrap();
    let lb = match code.lead_bytes() {
        LeadBytes::Zero => 0,
        LeadBytes::One => 1,
        LeadBytes::Two => 2,
    };
    let value = bytes[lb..].to_vec();
    Ok((rest, VariableLengthPrimitive::new(code, value)))
}

#[test]
pub fn test_variable_length_code_to_str() -> Result<(), Error> {
    let code = VariableLengthCode::Small {
        lb: LeadBytes::Zero,
        code: SmallVariableLengthCode::HPKEAuthCipher,
        length: 5,
    };
    assert_eq!(code.to_cesr(), "4GAF".to_string());

    let code = VariableLengthCode::Small {
        lb: LeadBytes::One,
        code: SmallVariableLengthCode::HPKEBaseCipher,
        length: 100,
    };
    assert_eq!(code.to_cesr(), "5FBk".to_string());

    let code = VariableLengthCode::Large {
        lb: LeadBytes::One,
        code: LargeVariableLengthCode::HPKEBaseCipher,
        length: 100,
    };
    assert_eq!(code.to_cesr(), "8AAFAABk".to_string());

    let code = VariableLengthCode::Small {
        lb: LeadBytes::Two,
        code: SmallVariableLengthCode::Base64String,
        length: 64,
    };
    assert_eq!(code.to_cesr(), "6ABA".to_string());

    Ok(())
}

#[test]
pub fn test_variable_length_code_from_str() -> Result<(), Error> {
    let expected_code = VariableLengthCode::Small {
        lb: LeadBytes::Zero,
        code: SmallVariableLengthCode::HPKEAuthCipher,
        length: 5,
    };
    let (rest, parsed_code) = variable_length_code("4GAF").unwrap();
    assert!(rest.is_empty());
    assert_eq!(expected_code, parsed_code);

    let expected_code = VariableLengthCode::Large {
        lb: LeadBytes::One,
        code: LargeVariableLengthCode::HPKEBaseCipher,
        length: 100,
    };
    let (rest, parsed_code) = variable_length_code("8AAFAABk").unwrap();
    assert!(rest.is_empty());
    assert_eq!(expected_code, parsed_code);

    let expected_code = VariableLengthCode::Small {
        lb: LeadBytes::Zero,
        code: SmallVariableLengthCode::Base64String,
        length: 1,
    };
    let (rest, parsed_code) = variable_length_code("4AAB").unwrap();
    assert!(rest.is_empty());
    assert_eq!(expected_code, parsed_code);

    let expected_code = VariableLengthCode::Small {
        lb: LeadBytes::One,
        code: SmallVariableLengthCode::Base64String,
        length: 100,
    };
    let (rest, parsed_code) = variable_length_code("5ABk").unwrap();
    assert!(rest.is_empty());
    assert_eq!(expected_code, parsed_code);

    let expected_code = VariableLengthCode::Small {
        lb: LeadBytes::Two,
        code: SmallVariableLengthCode::Base64String,
        length: 64,
    };
    let (rest, parsed_code) = variable_length_code("6ABA").unwrap();
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
    let variable_len_value: VariableLengthPrimitive = VariableLengthPrimitive::create_from_bytes(
        SmallVariableLengthCode::HPKEAuthCipher,
        ciphertext.clone(),
    );
    let variable_str = variable_len_value.to_cesr();

    let (rest, parsed_value) = variable_length_value(&variable_str).unwrap();
    assert_eq!(parsed_value, variable_len_value);
    assert_eq!(parsed_value.value(), &ciphertext);
    assert!(rest.is_empty());

    Ok(())
}

#[test]
fn test_base64_string() {
    use crate::value::{parse_value, Value};

    let variable_length_primitive =
        VariableLengthPrimitive::create_from_str(SmallVariableLengthCode::Base64String, "-");
    let expected_cesr = "6AABAAA-";
    assert_eq!(variable_length_primitive.to_cesr(), expected_cesr);

    let (_, parsed_primitive) = parse_value(expected_cesr).unwrap();
    if let Value::VariableLengthRaw(v) = parsed_primitive {
        assert_eq!(v, variable_length_primitive);
    } else {
        unreachable!();
    };

    assert_eq!(
        VariableLengthPrimitive::create_from_str(SmallVariableLengthCode::Base64String, "-A")
            .to_cesr(),
        "5AABAA-A"
    );
    assert_eq!(
        VariableLengthPrimitive::create_from_str(SmallVariableLengthCode::Base64String, "-A-")
            .to_cesr(),
        "4AABA-A-"
    );
    assert_eq!(
        VariableLengthPrimitive::create_from_str(SmallVariableLengthCode::Base64String, "-A-B")
            .to_cesr(),
        "4AAB-A-B"
    );
    assert_eq!(
        VariableLengthPrimitive::create_from_str(SmallVariableLengthCode::Base64String, "-a-b-c")
            .to_cesr(),
        "5AACAA-a-b-c"
    );
    assert_eq!(
        VariableLengthPrimitive::create_from_str(SmallVariableLengthCode::Base64String, "-field0")
            .to_cesr(),
        "4AACA-field0"
    );
    assert_eq!(
        VariableLengthPrimitive::create_from_str(
            SmallVariableLengthCode::Base64String,
            "-field0-field1-field3"
        )
        .to_cesr(),
        "6AAGAAA-field0-field1-field3"
    );
}
