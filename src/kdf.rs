//! Specifics for the Key Derivation function (KDF).
//!
//! Currently the KDF is just the blake3 hash function.
//! TODO need to find a better suited KDF implementation.

use primitive_types::H256;

pub struct KDF {
    hasher: blake3::Hasher,
}

// STENT TODO make this a raw [u8; 32] to save on copying work--we can instead just transfer ownership
pub struct Key {
    value: H256,
}

impl KDF {
    fn new() -> Self {
        KDF {
            hasher: blake3::Hasher::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(&self) -> Key {
        Key {
            value: H256(self.hasher.finalize().as_bytes().clone())
        }
    }
}

impl Key {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.value.into()
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.value.as_fixed_bytes()
    }
}

pub fn generate_key(value1: &[u8], value2: &[u8]) -> Key {
    let mut kdf = KDF::new();
    kdf.update(value1);
    kdf.update(value2);
    kdf.finalize()
}
