use serde_json::Value;

use crate::pkce::Sha256;

// §9.3 karar 1: OCSF 1.9.0'ın record_integrity profili tam olarak bu modelin
// wire formatı, dolayısıyla denetim çıktısı SIEM'lerin zaten anladığı bir
// şeydir, bize özgü bir şekil değil.
pub const CHAIN_UID_PREFIX: &str = "urn:argus:audit:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub chain_uid: String,
    pub fingerprint: [u8; 32],
    pub tree_size: u64,
    pub root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub tree_size: u64,
    pub root: [u8; 32],
    pub issued_at: i64,
}

// Bir olayın kanonik serileştirmesinin parmak izi. Kanonik, çünkü aynı olayın
// iki kodlaması iki farklı yaprak üretmemeli.
pub fn fingerprint<H: Sha256>(hasher: &H, canonical: &str) -> [u8; 32] {
    hasher.sha256(canonical.as_bytes())
}

#[must_use]
// §9.3 karar 1 yine: checkpoint kendi attestation'ı olarak yayınlanır, böylece
// her kayda `prev_event` gömmek gerekmez ve insert yolu düz bir append olarak
// kalır.
pub fn checkpoint_document(chain_uid: &str, checkpoint: &Checkpoint) -> Value {
    serde_json::json!({
        "chain_uid": chain_uid,
        "tree_size": checkpoint.tree_size,
        "root": crate::hex::encode(&checkpoint.root),
        "issued_at": checkpoint.issued_at,
    })
}

#[must_use]
pub fn inclusion_document(
    chain_uid: &str,
    fingerprint: &[u8; 32],
    index: u64,
    checkpoint: &Checkpoint,
    proof: &[[u8; 32]],
) -> Value {
    let path: Vec<String> = proof.iter().map(|h| crate::hex::encode(h)).collect();

    serde_json::json!({
        "chain_uid": chain_uid,
        "fingerprint": crate::hex::encode(fingerprint),
        "leaf_index": index,
        "tree_size": checkpoint.tree_size,
        "root": crate::hex::encode(&checkpoint.root),
        "path": path,
    })
}
