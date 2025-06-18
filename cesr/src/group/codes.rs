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
            GroupCode::IndexedControllerSignatures(count) => ("-K", count),
            GroupCode::IndexedWitnessSignatures(count) => ("-L", count),
            GroupCode::NontransferableReceiptCouples(count) => ("-M", count),
            GroupCode::FirstSeenReplyCouples(count) => ("-O", count),
            GroupCode::AnchoringEventSeals(count) => ("-S", count),
            GroupCode::SealSourceCouples(count) => ("-T", count),
            #[cfg(feature = "cesr-proof")]
            GroupCode::PathedMaterialQuadruple(len) => ("-P", len),
        };
        [code, &adjust_with_num(count.to_owned(), self.soft_size())].join("")
    }
}

impl FromStr for GroupCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = s.get(..2).ok_or(Error::EmptyCodeError)?;
        let count_part = s.get(2..4).ok_or(Error::EmptyCodeError)?;
        let count = b64_to_num(count_part.as_bytes())?;
        match code {
            "-K" => Ok(Self::IndexedControllerSignatures(count)),
            "-L" => Ok(Self::IndexedWitnessSignatures(count)),
            "-M" => Ok(Self::NontransferableReceiptCouples(count)),
            "-N" => todo!(),
            "-O" => Ok(Self::FirstSeenReplyCouples(count)),
            #[cfg(feature = "cesr-proof")]
            "-P" => Ok(Self::PathedMaterialQuadruple(count)),
            "-R" => todo!(),
            "-S" => Ok(Self::AnchoringEventSeals(count)),
            "-T" => Ok(Self::SealSourceCouples(count)),
            "-U" => todo!(),
            "-V" => todo!(),
            "-W" => todo!(),
            "-X" => todo!(),
            "-Y" => todo!(),
            "-Z" => todo!(),
            _ => Err(Error::UnknownCodeError),
        }
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
    assert_eq!(GroupCode::FirstSeenReplyCouples(127).to_str(), "-OB_");
    assert_eq!(GroupCode::AnchoringEventSeals(4095).to_str(), "-S__");
    assert_eq!(GroupCode::SealSourceCouples(0).to_str(), "-TAA");
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
    assert_eq!(GroupCode::AnchoringEventSeals(4095), "-S__".parse()?);
    assert_eq!(GroupCode::FirstSeenReplyCouples(127), "-OB_".parse()?);
    assert_eq!(GroupCode::SealSourceCouples(0), "-TAA".parse()?);
    Ok(())
}
