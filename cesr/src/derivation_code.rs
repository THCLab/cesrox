//! Sizes of CESR codes and the parts of an encoded item.

/// A CESR code: its parts and the size of the item it prefixes, in
/// text-domain characters.
pub trait DerivationCode {
    /// hard (fixed) part of code size in chars
    fn hard_size(&self) -> usize;
    /// soft (variable) part of code size in chars
    fn soft_size(&self) -> usize;
    /// value size in chars
    fn value_size(&self) -> usize;

    /// Size of the whole code in chars, hard and soft parts together.
    fn code_size(&self) -> usize {
        self.hard_size() + self.soft_size()
    }
    /// full size in chars of code prefixed to data
    fn full_size(&self) -> usize {
        self.code_size() + self.value_size()
    }
    /// The code in the text domain.
    fn to_str(&self) -> String;
    /// Zero bytes in front of the raw value, part of the value text but not
    /// of the raw bytes.
    fn lead_size(&self) -> usize {
        0
    }
}
