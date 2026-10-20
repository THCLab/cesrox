//! Tag primitives: 1 to 11 Base64 characters carried in the soft part of
//! the code, e.g. message types such as `icp`.

use std::str::FromStr;

use crate::{derivation_code::DerivationCode, error::Error};

/// A tag of 1 to 11 URL-safe Base64 characters.
#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub struct TagCode {
    tag: String,
}

/// Code for each tag length; odd lengths of two-character codes are
/// padded with one `_` in front.
const CODES: [&str; 11] = [
    "0J", "0K", "X", "1AAF", "0L", "0M", "Y", "1AAN", "0N", "0O", "Z",
];

fn is_base64(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

impl TagCode {
    pub fn new(tag: &str) -> Result<Self, Error> {
        if tag.is_empty() || tag.len() > CODES.len() || !tag.chars().all(is_base64) {
            return Err(Error::Invalid(format!("tag {tag:?}")));
        }
        Ok(TagCode { tag: tag.into() })
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    fn code(&self) -> &'static str {
        CODES[self.tag.len() - 1]
    }

    /// Characters of `_` padding in front of the tag.
    fn pad(&self) -> usize {
        // the code and the soft part fill whole quadlets
        (4 - (self.code().len() + self.tag.len()) % 4) % 4
    }
}

impl DerivationCode for TagCode {
    fn hard_size(&self) -> usize {
        self.code().len()
    }

    fn soft_size(&self) -> usize {
        self.pad() + self.tag.len()
    }

    fn value_size(&self) -> usize {
        0
    }

    fn to_str(&self) -> String {
        [self.code(), &"_".repeat(self.pad()), &self.tag].concat()
    }
}

impl FromStr for TagCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hard = match s.get(..1).ok_or(Error::Truncated)? {
            "0" => s.get(..2).ok_or(Error::Truncated)?,
            "1" => s.get(..4).ok_or(Error::Truncated)?,
            one => one,
        };
        let length = CODES
            .iter()
            .position(|code| *code == hard)
            .ok_or(Error::UnknownCode)?
            + 1;
        let pad = (4 - (hard.len() + length) % 4) % 4;
        let soft = s
            .get(hard.len()..hard.len() + pad + length)
            .ok_or(Error::Truncated)?;
        let (padding, tag) = soft.split_at_checked(pad).ok_or(Error::UnknownCode)?;
        if padding.chars().any(|c| c != '_') {
            return Err(Error::Invalid(format!("{hard}: tag padding {padding:?}")));
        }
        TagCode::new(tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_length_round_trips() {
        let alphabet = "AbCdEfGhIjK";
        for length in 1..=11 {
            let tag = TagCode::new(&alphabet[..length]).unwrap();
            let text = tag.to_str();
            assert_eq!(text.len() % 4, 0, "{text}");
            assert_eq!(text.parse::<TagCode>().unwrap(), tag);
        }
        assert_eq!(TagCode::new("A").unwrap().to_str(), "0J_A");
        assert_eq!(TagCode::new("icp").unwrap().to_str(), "Xicp");
    }

    #[test]
    fn invalid_tags_are_rejected() {
        assert!(TagCode::new("").is_err());
        assert!(TagCode::new("AbCdEfGhIjKl").is_err());
        assert!(TagCode::new("a b").is_err());
        assert!("0JAA".parse::<TagCode>().is_err());
    }
}
