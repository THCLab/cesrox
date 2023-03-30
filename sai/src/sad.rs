use crate::error::Error;

use super::SelfAddressingIdentifier;

/// Self Addressing Data
pub trait SAD {
    fn get_digest(&self) -> SelfAddressingIdentifier;
    fn dummy_event(&self) -> Result<Vec<u8>, Error>;
    fn check_digest(&self) -> Result<(), Error> {
        let dummy: Vec<u8> = self.dummy_event()?;
        self.get_digest()
            .verify_binding(&dummy)
            .then_some(())
            .ok_or(Error::IncorrectDigestError)
    }
}
