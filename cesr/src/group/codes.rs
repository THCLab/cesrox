use std::str::FromStr;

use crate::{
    conversion::{adjust_with_num, b64_to_num},
    derivation_code::DerivationCode,
    error::Error,
};

/// Counter codes of attachment and seal groups. The number is the group's
/// count: quadlets in CESR V2, items in the format of cesrox before 2.0.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum GroupCode {
    /// `-K`
    IndexedControllerSignatures(u32),
    /// `-L`
    IndexedWitnessSignatures(u32),
    /// `-M`
    NontransferableReceiptCouples(u32),
    /// `-O`
    FirstSeenReplayCouples(u32),
    /// `-Q`
    DigestSeals(u32),
    /// `-R`
    MerkleRootSeals(u32),
    /// `-S`: sequence number and digest of the delegator's or issuer's
    /// anchoring event.
    SealSourceCouples(u32),
    /// `-T`
    AnchoringEventSeals(u32),
    /// `-U`
    LastEventSeals(u32),
    /// `-V`
    BackerSeals(u32),
    /// `-W`
    TypedDigestSeals(u32),
    /// `-X`: transferable signer's prefix, sequence number and event digest
    /// with its indexed signatures.
    TransIdxSigGroups(u32),
    /// `-Y`: transferable signer's prefix with indexed signatures verified
    /// against its latest establishment event.
    TransLastIdxSigGroups(u32),
    /// `-a`
    BlindedStates(u32),
    /// `-b`
    BoundStates(u32),
    /// `-c`
    TypedMedia(u32),
    #[cfg(feature = "cesr-proof")]
    /// `-P`
    PathedMaterialQuadruple(u32),
    /// `-Z`
    TSPPayload(u32),
}

/// Largest count of a small code (`-X##`); bigger counts use `--X#####`.
const SMALL_MAX: u32 = 4095;

impl GroupCode {
    fn parts(&self) -> (char, u32) {
        match *self {
            GroupCode::IndexedControllerSignatures(n) => ('K', n),
            GroupCode::IndexedWitnessSignatures(n) => ('L', n),
            GroupCode::NontransferableReceiptCouples(n) => ('M', n),
            GroupCode::FirstSeenReplayCouples(n) => ('O', n),
            GroupCode::DigestSeals(n) => ('Q', n),
            GroupCode::MerkleRootSeals(n) => ('R', n),
            GroupCode::SealSourceCouples(n) => ('S', n),
            GroupCode::AnchoringEventSeals(n) => ('T', n),
            GroupCode::LastEventSeals(n) => ('U', n),
            GroupCode::BackerSeals(n) => ('V', n),
            GroupCode::TypedDigestSeals(n) => ('W', n),
            GroupCode::TransIdxSigGroups(n) => ('X', n),
            GroupCode::TransLastIdxSigGroups(n) => ('Y', n),
            GroupCode::BlindedStates(n) => ('a', n),
            GroupCode::BoundStates(n) => ('b', n),
            GroupCode::TypedMedia(n) => ('c', n),
            #[cfg(feature = "cesr-proof")]
            GroupCode::PathedMaterialQuadruple(n) => ('P', n),
            GroupCode::TSPPayload(n) => ('Z', n),
        }
    }

    fn from_parts(letter: char, n: u32) -> Result<Self, Error> {
        Ok(match letter {
            'K' => GroupCode::IndexedControllerSignatures(n),
            'L' => GroupCode::IndexedWitnessSignatures(n),
            'M' => GroupCode::NontransferableReceiptCouples(n),
            'O' => GroupCode::FirstSeenReplayCouples(n),
            'Q' => GroupCode::DigestSeals(n),
            'R' => GroupCode::MerkleRootSeals(n),
            'S' => GroupCode::SealSourceCouples(n),
            'T' => GroupCode::AnchoringEventSeals(n),
            'U' => GroupCode::LastEventSeals(n),
            'V' => GroupCode::BackerSeals(n),
            'W' => GroupCode::TypedDigestSeals(n),
            'X' => GroupCode::TransIdxSigGroups(n),
            'Y' => GroupCode::TransLastIdxSigGroups(n),
            'a' => GroupCode::BlindedStates(n),
            'b' => GroupCode::BoundStates(n),
            'c' => GroupCode::TypedMedia(n),
            #[cfg(feature = "cesr-proof")]
            'P' => GroupCode::PathedMaterialQuadruple(n),
            'Z' => GroupCode::TSPPayload(n),
            'N' => {
                return Err(Error::Invalid(
                    "-N: the CESR spec (receipt quadruples) and keripy (nonce seals) disagree on its meaning".into(),
                ))
            }
            _ => return Err(Error::UnknownCode),
        })
    }

    /// The group's count.
    pub fn count(&self) -> u32 {
        self.parts().1
    }

    fn is_big(&self) -> bool {
        self.count() > SMALL_MAX
    }
}

impl DerivationCode for GroupCode {
    fn value_size(&self) -> usize {
        0
    }

    fn soft_size(&self) -> usize {
        if self.is_big() {
            5
        } else {
            2
        }
    }

    fn hard_size(&self) -> usize {
        if self.is_big() {
            3
        } else {
            2
        }
    }

    /// Counts above 1,073,741,823 do not fit in a counter and must not be
    /// used.
    fn to_str(&self) -> String {
        let (letter, count) = self.parts();
        let dashes = if self.is_big() { "--" } else { "-" };
        format!(
            "{dashes}{letter}{}",
            adjust_with_num(count, self.soft_size())
        )
    }
}

impl FromStr for GroupCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (letter, count) = match s.get(..2).ok_or(Error::Truncated)? {
            "--" => (s.get(2..3), s.get(3..8)),
            code if code.starts_with('-') => (s.get(1..2), s.get(2..4)),
            _ => return Err(Error::UnknownCode),
        };
        let letter = letter.ok_or(Error::Truncated)?;
        let count = b64_to_num(count.ok_or(Error::Truncated)?)?;
        let letter = letter.chars().next().ok_or(Error::Truncated)?;
        GroupCode::from_parts(letter, count)
    }
}

#[test]
pub fn test_group_codes_to_str() -> Result<(), Error> {
    assert_eq!(GroupCode::IndexedControllerSignatures(3).to_str(), "-KAD");
    assert_eq!(GroupCode::IndexedWitnessSignatures(30).to_str(), "-LAe");
    assert_eq!(
        GroupCode::NontransferableReceiptCouples(100).to_str(),
        "-MBk"
    );
    assert_eq!(GroupCode::FirstSeenReplayCouples(127).to_str(), "-OB_");
    assert_eq!(GroupCode::SealSourceCouples(0).to_str(), "-SAA");
    assert_eq!(GroupCode::AnchoringEventSeals(4095).to_str(), "-T__");
    Ok(())
}

#[test]
pub fn test_group_codes_from_str() -> Result<(), Error> {
    assert_eq!(GroupCode::IndexedControllerSignatures(3), "-KAD".parse()?);
    assert_eq!(GroupCode::IndexedWitnessSignatures(30), "-LAe".parse()?);
    assert_eq!(
        GroupCode::NontransferableReceiptCouples(100),
        "-MBk".parse()?
    );
    assert_eq!(GroupCode::SealSourceCouples(0), "-SAA".parse()?);
    assert_eq!(GroupCode::FirstSeenReplayCouples(127), "-OB_".parse()?);
    assert_eq!(GroupCode::AnchoringEventSeals(4095), "-T__".parse()?);
    Ok(())
}

#[test]
fn big_counts_use_big_codes() -> Result<(), Error> {
    let big = GroupCode::IndexedControllerSignatures(4096);
    assert_eq!(big.to_str(), "--KAABAA");
    assert_eq!(big.code_size(), 8);
    assert_eq!(big, "--KAABAA".parse()?);
    assert_eq!(GroupCode::TypedMedia(1_073_741_823).to_str(), "--c_____");
    assert!("-NAB".parse::<GroupCode>().is_err());
    assert!("--K".parse::<GroupCode>().is_err());
    Ok(())
}
