use std::str::FromStr;

use crate::{
    conversion::{adjust_with_num, b64_to_num},
    derivation_code::DerivationCode,
    error::Error,
};

#[derive(Debug, PartialEq, Eq)]
pub enum GroupCode {
    IndexedControllerSignatures(u16),
    IndexedWitnessSignatures(u16),
    NontransferableReceiptCouples(u16),
    FirstSeenReplyCouples(u16),
    // Composed Base64 couple, snu+dig of given delegators or issuers event
    SealSourceCouples(u16),
    AnchoringEventSeals(u16),
    #[cfg(feature = "cesr-proof")]
    PathedMaterialQuadruple(u16),
    TSPPayload(u16),
}

impl DerivationCode for GroupCode {
    fn value_size(&self) -> usize {
        0
    }

    fn soft_size(&self) -> usize {
        2
    }

    fn hard_size(&self) -> usize {
        2
    }

    fn to_str(&self) -> String {
        let (code, count) = match self {
            GroupCode::IndexedControllerSignatures(count) => ("-J", count),
            GroupCode::IndexedWitnessSignatures(count) => ("-K", count),
            GroupCode::NontransferableReceiptCouples(count) => ("-L", count),
            GroupCode::FirstSeenReplyCouples(count) => ("-N", count),
            GroupCode::SealSourceCouples(count) => ("-Q", count),
            GroupCode::AnchoringEventSeals(count) => ("-R", count),
            #[cfg(feature = "cesr-proof")]
            GroupCode::PathedMaterialQuadruple(len) => ("-S", len),
            GroupCode::TSPPayload(len) => ("-Z", len),
        };
        [code, &adjust_with_num(count.to_owned(), self.soft_size())].join("")
    }
}

impl FromStr for GroupCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = s.get(..2).ok_or(Error::EmptyCodeError)?;
        let count_part = s.get(2..4).ok_or(Error::EmptyCodeError)?;
        let count = b64_to_num(count_part)?;
        match code {
            "-J" => Ok(Self::IndexedControllerSignatures(count)),
            "-K" => Ok(Self::IndexedWitnessSignatures(count)),
            "-L" => Ok(Self::NontransferableReceiptCouples(count)),
            "-N" => Ok(Self::FirstSeenReplyCouples(count)),
            "-Q" => Ok(Self::SealSourceCouples(count)),
            "-R" => Ok(Self::AnchoringEventSeals(count)),
            #[cfg(feature = "cesr-proof")]
            "-S" => Ok(Self::PathedMaterialQuadruple(count)),
            "-Z" => Ok(Self::TSPPayload(count)),
            _ => Err(Error::UnknownCodeError),
        }
    }
}

#[test]
pub fn test_group_codes_to_str() -> Result<(), Error> {
    assert_eq!(GroupCode::IndexedControllerSignatures(3).to_str(), "-JAD");
    assert_eq!(GroupCode::IndexedWitnessSignatures(30).to_str(), "-KAe");
    assert_eq!(
        GroupCode::NontransferableReceiptCouples(100).to_str(),
        "-LBk"
    );
    assert_eq!(GroupCode::FirstSeenReplyCouples(127).to_str(), "-NB_");
    assert_eq!(GroupCode::AnchoringEventSeals(4095).to_str(), "-R__");
    assert_eq!(GroupCode::SealSourceCouples(0).to_str(), "-QAA");
    Ok(())
}

#[test]
pub fn test_group_codes_from_str() -> Result<(), Error> {
    assert_eq!(GroupCode::IndexedControllerSignatures(3), "-JAD".parse()?);
    assert_eq!(GroupCode::IndexedWitnessSignatures(30), "-KAe".parse()?);
    assert_eq!(
        GroupCode::NontransferableReceiptCouples(100),
        "-LBk".parse()?
    );
    assert_eq!(GroupCode::AnchoringEventSeals(4095), "-R__".parse()?);
    assert_eq!(GroupCode::FirstSeenReplyCouples(127), "-NB_".parse()?);
    assert_eq!(GroupCode::SealSourceCouples(0), "-QAA".parse()?);
    Ok(())
}
