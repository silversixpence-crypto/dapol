use primitive_types::H256;

const DELIMITER: &[u8] = ";".as_bytes();

/// Abstraction of a hash function, allows easy switching of hash function.
///
/// The main purpose of the hash function is usage in the binary tree merge
/// function. The reason it has it's own file is so that we can create a
/// wrapper around the underlying hash function, allowing it to be easily
/// changed.
///
/// The current hash function used is blake3.
///
/// Example:
/// ```
/// use dapol::Hasher;
/// let mut hasher = Hasher::new();
/// hasher.update("leaf".as_bytes());
/// let hash = hasher.finalize();
/// ```
///
/// Note that a delimiter is used to add extra security:
/// ```
/// use dapol::Hasher;
/// let mut dapol_hasher = Hasher::new();
/// dapol_hasher.update("leaf".as_bytes());
/// dapol_hasher.update("node".as_bytes());
/// let dapol_hash = dapol_hasher.finalize();
///
/// let mut blake_hasher = blake3::Hasher::new();
/// blake_hasher.update("leaf".as_bytes());
/// blake_hasher.update(";".as_bytes());
/// blake_hasher.update("node".as_bytes());
/// blake_hasher.update(";".as_bytes());
/// let blake_hash = blake_hasher.finalize();
///
/// assert_eq!(dapol_hash.as_bytes(), blake_hash.as_bytes());
/// ```
pub struct Hasher(blake3::Hasher);

impl Hasher {
    pub fn new() -> Self {
        Hasher(blake3::Hasher::new())
    }

    pub fn update(&mut self, input: &[u8]) -> &mut Self {
        self.0.update(input);
        self.0.update(DELIMITER);
        self
    }

    pub fn finalize(&self) -> H256 {
        let bytes: [u8; 32] = self.0.finalize().into();
        H256(bytes)
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Hasher(blake3::Hasher::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ensures Blake 3 library produces correct hashed output.
    // Comparison hash derived through the following urls:
    // https://asecuritysite.com/hash/blake3
    // https://emn178.github.io/online-tools/blake3.html
    //
    // For https://connor4312.github.io/blake3/index.html do the following:
    // -> select utf-8 input option
    // -> paste in "dapol;PoR;"
    // -> see resulting hash is equal to b0424ae23fcce672aaff99e9f433286e27119939a280743539783ba7aade8294
    //
    // For https://toolkitbay.com/tkb/tool/BLAKE3 do the following:
    // -> select "text input" option
    // -> paste in "dapol;PoR;"
    // -> click "process from text"
    // -> see resulting hash is equal to b0424ae23fcce672aaff99e9f433286e27119939a280743539783ba7aade8294
    #[test]
    fn verify_hasher() {
        use std::str::FromStr;

        let mut hasher = Hasher::new();
        hasher.update("dapol".as_bytes());
        hasher.update("PoR".as_bytes());
        let hash = hasher.finalize();
        assert_eq!(
            hash,
            H256::from_str("b0424ae23fcce672aaff99e9f433286e27119939a280743539783ba7aade8294")
                .unwrap()
        );
    }
}
