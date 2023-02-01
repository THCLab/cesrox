use nom::{error::{make_error, ErrorKind}, branch::alt};
use rmp_serde as serde_mgpk;
use crate::serialization_info::SerializationInfo;

// TESTED: OK
fn json_version(data: &[u8]) -> nom::IResult<&[u8], SerializationInfo> {
    match serde_json::from_slice(data) {
        Ok(vi) => Ok((data, vi)),
        _ => Err(nom::Err::Error(make_error(data, ErrorKind::IsNot))),
    }
}

// TODO: Requires testing
fn cbor_version(data: &[u8]) -> nom::IResult<&[u8], SerializationInfo> {
    match serde_cbor::from_slice(data) {
        Ok(vi) => Ok((data, vi)),
        _ => Err(nom::Err::Error(make_error(data, ErrorKind::IsNot))),
    }
}

// TODO: Requires testing
fn mgpk_version(data: &[u8]) -> nom::IResult<&[u8], SerializationInfo> {
    match serde_mgpk::from_slice(data) {
        Ok(vi) => Ok((data, vi)),
        _ => Err(nom::Err::Error(make_error(data, ErrorKind::IsNot))),
    }
}

pub(crate) fn version(data: &[u8]) -> nom::IResult<&[u8], SerializationInfo> {
    alt((json_version, cbor_version, mgpk_version))(data).map(|d| (d.0, d.1))
}

#[test]
fn test_version_parse() {
    let json = br#""KERI10JSON00014b_""#;
    let json_result = version(json);
    assert!(json_result.is_ok());
    assert_eq!(&json[1..18], json_result.unwrap().1.to_str().as_bytes());
}