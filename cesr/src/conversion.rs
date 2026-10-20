use base64::prelude::*;

use super::error::Error;

pub fn from_text_to_bytes(text: &str) -> Result<Vec<u8>, Error> {
    let lead_size = (4 - (text.len() % 4)) % 4;
    let full_derivative = [&"A".repeat(lead_size), text].concat();

    // CESR never uses `=` padding; the lead `A`s above already align the text.
    Ok(BASE64_URL_SAFE_NO_PAD.decode(full_derivative)?.to_vec())
}

/// The binary domain (qb2) form of text-domain CESR (qb64): its Base64
/// decoding. Fails unless `text` is whole Base64 quadlets.
pub fn qb64_to_qb2(text: &[u8]) -> Result<Vec<u8>, Error> {
    if !text.len().is_multiple_of(4) {
        return Err(Error::Invalid("not whole Base64 quadlets".into()));
    }
    Ok(BASE64_URL_SAFE_NO_PAD.decode(text)?)
}

/// The text domain (qb64) form of binary-domain CESR (qb2).
pub fn qb2_to_qb64(binary: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(binary)
}

pub fn from_bytes_to_text(bytes: &[u8]) -> String {
    let lead_size = (3 - (bytes.len() % 3)) % 3;
    let full_derivative: Vec<_> = std::iter::repeat_n(0, lead_size)
        .chain(bytes.iter().copied())
        .collect();

    BASE64_URL_SAFE.encode(full_derivative)
}

const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Parses the number from radix 64 using digits from url-safe base64 (`A` = 0, `_` = 63).
/// Fails on other characters and on values that do not fit in `T`.
pub fn b64_to_num<T: TryFrom<u64>>(b64: &str) -> Result<T, Error> {
    let mut num: u64 = 0;
    for c in b64.bytes() {
        let digit = DIGITS
            .iter()
            .position(|d| *d == c)
            .ok_or(Error::InvalidBase64)? as u64;
        num = num
            .checked_mul(64)
            .and_then(|n| n.checked_add(digit))
            .ok_or_else(|| Error::Invalid(format!("number {b64} is too large")))?;
    }
    T::try_from(num).map_err(|_| Error::Invalid(format!("number {b64} is too large")))
}

/// Formats the number in radix 64 using digits from url-safe base64 (`A` = 0, `_` = 63)
pub fn num_to_b64(num: impl Into<u64>) -> String {
    let mut num = num.into();
    let mut digits = vec![];
    loop {
        digits.push(DIGITS[(num % 64) as usize]);
        num /= 64;
        if num == 0 {
            break;
        }
    }
    digits.reverse();
    String::from_utf8(digits).unwrap_or_default()
}

/// `num` in radix 64, left-padded with `A` to `expected_length` digits.
pub(crate) fn adjust_with_num(num: impl Into<u64>, expected_length: usize) -> String {
    if expected_length == 0 {
        return String::new();
    }
    format!("{:A>expected_length$}", num_to_b64(num))
}

pub(crate) fn check_first_three_bits(byte: &u8) -> u8 {
    (byte >> 5) & 0b111 // Shift right by 5 and mask the first 3 bits
}

#[test]
fn num_to_b64_test() {
    assert_eq!("A", num_to_b64(0u32));
    assert_eq!("BAA", num_to_b64(4096u32));
    assert_eq!("P__", num_to_b64(u16::MAX));
    assert_eq!("____", num_to_b64(16_777_215u32));
    assert_eq!("B", num_to_b64(1u32));
    assert_eq!("C", num_to_b64(2u32));
    assert_eq!("D", num_to_b64(3u32));
    assert_eq!("b", num_to_b64(27u32));
    assert_eq!("BQ", num_to_b64(80u32));
    assert_eq!("__", num_to_b64(4095u32));
}

#[test]
fn b64_to_num_test() {
    assert_eq!(b64_to_num::<u32>("AAAA").unwrap(), 0);
    assert_eq!(b64_to_num::<u32>("A").unwrap(), 0);
    assert_eq!(b64_to_num::<u32>("B").unwrap(), 1);
    assert_eq!(b64_to_num::<u32>("C").unwrap(), 2);
    assert_eq!(b64_to_num::<u32>("D").unwrap(), 3);
    assert_eq!(b64_to_num::<u32>("b").unwrap(), 27);
    assert_eq!(b64_to_num::<u32>("BQ").unwrap(), 80);
    assert_eq!(b64_to_num::<u32>("__").unwrap(), 4095);
    assert_eq!(b64_to_num::<u32>("____").unwrap(), 16_777_215);
    assert!(b64_to_num::<u16>("BAAA").is_err());
    assert!(b64_to_num::<u16>("A=").is_err());
}

#[test]
fn test_from_text_to_bytes() {
    assert_eq!(hex::encode(from_text_to_bytes("MP__").unwrap()), "30ffff");
    assert_eq!(hex::encode(from_text_to_bytes("MAAA").unwrap()), "300000");
    assert_eq!(hex::encode(from_text_to_bytes("MAAB").unwrap()), "300001");
}

#[test]
fn test_from_bytes_to_text() {
    let b_bytes = from_text_to_bytes("B").unwrap();
    assert_eq!("AAAB", from_bytes_to_text(&b_bytes));

    assert_eq!(
        from_bytes_to_text(&hex::decode("300000").unwrap()),
        "MAAA".to_string()
    );
    assert_eq!(
        from_bytes_to_text(&hex::decode("300001").unwrap()),
        "MAAB".to_string()
    );
    assert_eq!(
        from_bytes_to_text(&hex::decode("30ffff").unwrap()),
        "MP__".to_string()
    );
}

#[test]
fn test_adjust_with_num() {
    assert_eq!(adjust_with_num(2u32, 4), "AAAC");
    assert_eq!(adjust_with_num(27u32, 6), "AAAAAb");
}
