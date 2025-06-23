use std::str::FromStr;

use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
};

use super::{codes::MaterialPathCode, MaterialPath};
pub fn material_path(s: &str) -> nom::IResult<&str, MaterialPath> {
    let (more, type_c) = take(4u8)(s)?;

    let Ok(payload_type) = MaterialPathCode::from_str(type_c) else {
        return Err(nom::Err::Error(make_error(s, ErrorKind::IsNot)));
    };
    // parse amount of quadruplets
    let full_size = payload_type.size() * 4;
    // parse full path
    let (more, base) = take(full_size)(more)?;

    let path = MaterialPath::new(payload_type, base.to_string());

    Ok((more, path))
}
