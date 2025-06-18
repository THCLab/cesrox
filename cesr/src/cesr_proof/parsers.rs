use std::str::FromStr;

use nom::{
    bytes::complete::take,
    error::{make_error, ErrorKind},
};

use super::{codes::MaterialPathCode, MaterialPath};
pub fn material_path(s: &[u8]) -> nom::IResult<&[u8], MaterialPath> {
    let (more, type_c) = take(4u8)(s)?;

    let Ok(payload_type) = MaterialPathCode::from_str(std::str::from_utf8(type_c).unwrap()) else {
        return Err(nom::Err::Error(make_error(s, ErrorKind::IsNot)));
    };
    // parse amount of quadruplets
    let full_size = payload_type.size() * 4;
    // parse full path
    let (more, base) = take(full_size)(more)?;

    let path = MaterialPath::new(
        payload_type,
        String::from_utf8(base.to_vec()).unwrap_or_default(),
    );

    Ok((more, path))
}
