use crate::{
    conversion::{adjust_with_num, b64_to_num},
    derivation_code::DerivationCode,
    error::Error,
    primitives::codes::self_signing::SelfSigning,
};
use core::str::FromStr;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Index {
    BothSame(u16),
    Dual(u16, u16),
    BigDual(u16, u16),
    CurrentOnly(u16),
    BigCurrentOnly(u16),
}
impl Index {
    pub fn current(&self) -> u16 {
        match self {
            Index::BothSame(i)
            | Index::Dual(i, _)
            | Index::BigDual(i, _)
            | Index::CurrentOnly(i)
            | Index::BigCurrentOnly(i) => *i,
        }
    }
    pub fn prev_next(&self) -> Option<u16> {
        match self {
            Index::BothSame(i) | Index::Dual(_, i) | Index::BigDual(_, i) => Some(*i),
            _ => None,
        }
    }
}
/// Attached Signature Derivation Codes
///
/// A self signing prefix derivation outputs a signature as its derivative (2.3.5)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AttachedSignatureCode {
    pub index: Index,
    pub code: SelfSigning,
}

impl AttachedSignatureCode {
    pub fn new(code: SelfSigning, index: Index) -> Self {
        Self { index, code }
    }

    pub fn new_from_ints(code: SelfSigning, current: u16, prev_next: Option<u16>) -> Self {
        let index = match prev_next {
            Some(i) => {
                if i == current {
                    Index::BothSame(i)
                } else {
                    Index::BigDual(current, i)
                }
            }
            None => Index::CurrentOnly(current),
        };
        Self { code, index }
    }
}

/// One family of indexed signature codes in the CESR V2 table, e.g. `A`,
/// `B`, `2A`, `2B` for Ed25519.
struct Family {
    /// Index in both key lists, small and big.
    both: (&'static str, &'static str),
    /// Index in the current key list only, small and big.
    current: (&'static str, &'static str),
    /// Characters for the index and the other index (ondex), small codes.
    small: (usize, usize),
    /// The same for big codes.
    big: (usize, usize),
}

impl Family {
    fn of(code: SelfSigning) -> Family {
        match code {
            SelfSigning::Ed25519Sha512 => Family {
                both: ("A", "2A"),
                current: ("B", "2B"),
                small: (1, 0),
                big: (2, 2),
            },
            SelfSigning::ECDSAsecp256k1Sha256 => Family {
                both: ("C", "2C"),
                current: ("D", "2D"),
                small: (1, 0),
                big: (2, 2),
            },
            // not in the V2 spec table yet; see the review of 2026-10-20
            SelfSigning::ECDSA256r1Sha256 => Family {
                both: ("Q", "2Q"),
                current: ("R", "2R"),
                small: (1, 0),
                big: (2, 2),
            },
            SelfSigning::Ed448 => Family {
                both: ("0A", "3A"),
                current: ("0B", "3B"),
                small: (1, 1),
                big: (3, 3),
            },
        }
    }
}

fn fits(value: u16, chars: usize) -> bool {
    (value as u32) < 64u32.pow(chars as u32)
}

/// How a code is written: the code itself, the index and ondex fields
/// with their widths. The smallest code that can hold the values is used.
struct Layout {
    code: &'static str,
    index: (u16, usize),
    ondex: (u16, usize),
}

impl AttachedSignatureCode {
    fn layout(&self) -> Layout {
        let family = Family::of(self.code);
        let (small_index, small_ondex) = family.small;
        let (big_index, big_ondex) = family.big;
        let both = |i: u16, o: u16, big: bool| {
            if !big
                && fits(i, small_index)
                && (small_ondex > 0 && fits(o, small_ondex) || o == i && small_ondex == 0)
            {
                Layout {
                    code: family.both.0,
                    index: (i, small_index),
                    ondex: (o, small_ondex),
                }
            } else {
                Layout {
                    code: family.both.1,
                    index: (i, big_index),
                    ondex: (o, big_ondex),
                }
            }
        };
        let current = |i: u16, big: bool| {
            if !big && fits(i, small_index) {
                Layout {
                    code: family.current.0,
                    index: (i, small_index),
                    ondex: (0, small_ondex),
                }
            } else {
                Layout {
                    code: family.current.1,
                    index: (i, big_index),
                    ondex: (0, big_ondex),
                }
            }
        };
        match self.index {
            Index::BothSame(i) => both(i, i, false),
            Index::Dual(i, o) => both(i, o, false),
            Index::BigDual(i, o) => both(i, o, true),
            Index::CurrentOnly(i) => current(i, false),
            Index::BigCurrentOnly(i) => current(i, true),
        }
    }

    /// Parses the code at the start of `s`. With `legacy`, current-only
    /// codes are read in the layout cesrox wrote before 2.0, which put the
    /// index into the ondex characters as well.
    pub(crate) fn parse(s: &str, legacy: bool) -> Result<Self, Error> {
        let part = |range: std::ops::Range<usize>| s.get(range).ok_or(Error::Truncated);
        let hard = match part(0..1)? {
            "0" | "2" | "3" => part(0..2)?,
            other => other,
        };
        let (code, family) = [
            SelfSigning::Ed25519Sha512,
            SelfSigning::ECDSAsecp256k1Sha256,
            SelfSigning::ECDSA256r1Sha256,
            SelfSigning::Ed448,
        ]
        .into_iter()
        .map(|code| (code, Family::of(code)))
        .find(|(_, f)| [f.both.0, f.both.1, f.current.0, f.current.1].contains(&hard))
        .ok_or(Error::UnknownCode)?;
        let big = hard == family.both.1 || hard == family.current.1;
        let (index_chars, ondex_chars) = if big { family.big } else { family.small };
        let start = hard.len();
        let index = b64_to_num(part(start..start + index_chars)?)?;
        let ondex_field = part(start + index_chars..start + index_chars + ondex_chars)?;

        let index = if hard == family.current.0 || hard == family.current.1 {
            if legacy && ondex_chars > 0 {
                // the old encoder wrote the index across both fields
                let index = b64_to_num(part(start..start + index_chars + ondex_chars)?)?;
                if big {
                    Index::BigCurrentOnly(index)
                } else {
                    Index::CurrentOnly(index)
                }
            } else if !ondex_field.is_empty() && b64_to_num::<u16>(ondex_field)? != 0 {
                return Err(Error::Invalid(format!(
                    "{hard}: current-only signature with an ondex"
                )));
            } else if big {
                Index::BigCurrentOnly(index)
            } else {
                Index::CurrentOnly(index)
            }
        } else if ondex_chars == 0 {
            Index::BothSame(index)
        } else if big {
            Index::BigDual(index, b64_to_num(ondex_field)?)
        } else {
            Index::Dual(index, b64_to_num(ondex_field)?)
        };
        Ok(Self::new(code, index))
    }
}

impl DerivationCode for AttachedSignatureCode {
    fn soft_size(&self) -> usize {
        let layout = self.layout();
        layout.index.1 + layout.ondex.1
    }

    fn hard_size(&self) -> usize {
        self.layout().code.len()
    }

    fn value_size(&self) -> usize {
        match self.code {
            SelfSigning::Ed25519Sha512 => 86,
            SelfSigning::ECDSAsecp256k1Sha256 => 86,
            SelfSigning::ECDSA256r1Sha256 => 86,
            SelfSigning::Ed448 => 152,
        }
    }

    /// Indexes beyond what the largest code of the family can hold (4095,
    /// or 65535 for Ed448) cannot be represented and must not be used.
    fn to_str(&self) -> String {
        let layout = self.layout();
        [
            layout.code.to_string(),
            adjust_with_num(layout.index.0, layout.index.1),
            adjust_with_num(layout.ondex.0, layout.ondex.1),
        ]
        .concat()
    }
}

impl FromStr for AttachedSignatureCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s, false)
    }
}

#[cfg(feature = "legacy-v2beta")]
impl AttachedSignatureCode {
    fn legacy_soft_size(&self) -> usize {
        match (self.code, self.index) {
            (SelfSigning::Ed448, Index::BigDual(..) | Index::BigCurrentOnly(_)) => 6,
            (SelfSigning::Ed448, _) => 2,
            (_, Index::BothSame(_) | Index::CurrentOnly(_)) => 1,
            (SelfSigning::Ed25519Sha512, Index::Dual(..)) => 4,
            (_, Index::Dual(..)) => 1,
            (_, Index::BigDual(..) | Index::BigCurrentOnly(_)) => 4,
        }
    }

    /// Text of the code as cesrox wrote it before 2.0, for writers that
    /// must still be read by older nodes.
    #[cfg(feature = "legacy-v2beta")]
    pub fn to_legacy_str(&self) -> String {
        let code = match (self.code, self.index) {
            (SelfSigning::Ed25519Sha512, Index::BothSame(_)) => "A",
            (SelfSigning::Ed25519Sha512, Index::Dual(_, _))
            | (SelfSigning::Ed25519Sha512, Index::BigDual(_, _)) => "2A",
            (SelfSigning::Ed25519Sha512, Index::CurrentOnly(_)) => "B",
            (SelfSigning::Ed25519Sha512, Index::BigCurrentOnly(_)) => "2B",
            (SelfSigning::ECDSAsecp256k1Sha256, Index::BothSame(_)) => "C",
            (SelfSigning::ECDSAsecp256k1Sha256, Index::Dual(_, _)) => "C",
            (SelfSigning::ECDSAsecp256k1Sha256, Index::BigDual(_, _)) => "2C",
            (SelfSigning::ECDSAsecp256k1Sha256, Index::CurrentOnly(_)) => "D",
            (SelfSigning::ECDSAsecp256k1Sha256, Index::BigCurrentOnly(_)) => "2D",
            (SelfSigning::Ed448, Index::BothSame(_)) => "0A",
            (SelfSigning::Ed448, Index::Dual(_, _)) => "0A",
            (SelfSigning::Ed448, Index::BigDual(_, _)) => "3A",
            (SelfSigning::Ed448, Index::CurrentOnly(_)) => "0B",
            (SelfSigning::Ed448, Index::BigCurrentOnly(_)) => "3B",
            (SelfSigning::ECDSA256r1Sha256, Index::BothSame(_)) => "Q",
            (SelfSigning::ECDSA256r1Sha256, Index::Dual(_, _)) => "Q",
            (SelfSigning::ECDSA256r1Sha256, Index::BigDual(_, _)) => "2Q",
            (SelfSigning::ECDSA256r1Sha256, Index::CurrentOnly(_)) => "R",
            (SelfSigning::ECDSA256r1Sha256, Index::BigCurrentOnly(_)) => "2R",
        };
        let indexes_str = match self.index {
            Index::BothSame(i) | Index::CurrentOnly(i) | Index::BigCurrentOnly(i) => {
                adjust_with_num(i, self.legacy_soft_size())
            }
            Index::Dual(i, pi) | Index::BigDual(i, pi) => [
                adjust_with_num(i, self.legacy_soft_size() / 2),
                adjust_with_num(pi, self.legacy_soft_size() / 2),
            ]
            .join(""),
        };
        [code, &indexes_str].join("")
    }
}

#[test]
pub fn test() {
    let code = "2AADAC";
    let c: AttachedSignatureCode = code.parse().unwrap();
    assert_eq!(code, c.to_str());

    let code = "2AAAAB";
    let c: AttachedSignatureCode = code.parse().unwrap();
    assert_eq!(code, c.to_str());
}

#[test]
pub fn test_ecdsa_256r1_indexed_sig_roundtrip() {
    for code in ["QA", "RB", "2QADAC", "2RADAA"] {
        let c: AttachedSignatureCode = code.parse().unwrap();
        assert_eq!(code, c.to_str(), "round-trip failed for {code}");
        assert_eq!(c.code, SelfSigning::ECDSA256r1Sha256);
    }
}
