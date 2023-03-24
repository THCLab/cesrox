use sai::derivation::SelfAddressingCode;

#[test]
fn test_derive() {
    let data = "hello there";
    // let code: SelfAddressingCode = SelfAddressing::Blake3_256.into();
    let code: SelfAddressingCode = "E".parse().unwrap();
    let sai = code.derive(data.as_bytes());

    assert_eq!(
        format!("{}", sai),
        "ENmwqnqVxonf_bNZ0hMipOJJY25dxlC8eSY5BbyMCfLJ"
    );
    assert!(sai.verify_binding(data.as_bytes()));
    assert!(!sai.verify_binding("wrong data".as_bytes()));
}
