use crate::derivation::HashFunctionCode;

pub trait SAD {
    fn compute_digest(&self, code: HashFunctionCode) -> Self;
}
