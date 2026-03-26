use sha2::Digest;

pub fn compute_sha256(input: impl AsRef<[u8]>) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(input.as_ref());
    let hash_digest = hasher.finalize();
    hash_digest.to_vec()
}
