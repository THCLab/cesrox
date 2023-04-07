use sad_macros::SAD;
use said::sad::SAD;
use said::{SelfAddressingIdentifier, derivation::{HashFunctionCode}};
use serde::Serialize;

#[derive(SAD, Debug, Serialize)]
struct Pancakes {
    #[said]
    i: Option<SelfAddressingIdentifier>,
    something: AdditionalThings,
    #[said]
    d: Option<SelfAddressingIdentifier>,
}
 impl Pancakes {
    pub fn new(something: AdditionalThings) -> Self {
        Self {something, i: None, d: None}
    }
 }

#[derive(Serialize, Debug, Clone)]
struct AdditionalThings;

fn main() {
    let pancakes = Pancakes::new(AdditionalThings);
    dbg!(&pancakes);
    let hash_code = HashFunctionCode::Blake3_256;
    let saided_pancake = pancakes.compute_digest(hash_code);

    dbg!(&saided_pancake);
}
