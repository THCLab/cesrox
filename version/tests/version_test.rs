use std::str::FromStr;

use version::{
    error::Error,
    serialization_info::{SerializationFormats, SerializationInfo},
};

#[test]
fn test_serialization_info_to_str() -> Result<(), Error> {
    let si = SerializationInfo::new("KERI".to_string(), SerializationFormats::JSON, 100);

    let version_string = si.to_str();
    assert_eq!("KERI10JSON000064_", &version_string);
    Ok(())
}

#[test]
fn test_serialization_info_from_str() -> Result<(), Error> {
    let si = SerializationInfo::from_str("KERIa4CBOR000123_")?;

    assert_eq!(si.protocol_code, "KERI".to_string());
    assert_eq!(si.kind, SerializationFormats::CBOR);
    assert_eq!(si.major_version, 10);
    assert_eq!(si.minor_version, 4);
    assert_eq!(si.size, 291);
    Ok(())
}
