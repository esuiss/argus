#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use argus_core::audit::merkle::{
    consistency_proof, inclusion_proof, leaf_hash, root, verify_consistency, verify_inclusion,
};
use argus_core::pkce::Sha256;

struct TestHasher;

impl Sha256 for TestHasher {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        const K: [u32; 64] = [
            0x428a_2f98,
            0x7137_4491,
            0xb5c0_fbcf,
            0xe9b5_dba5,
            0x3956_c25b,
            0x59f1_11f1,
            0x923f_82a4,
            0xab1c_5ed5,
            0xd807_aa98,
            0x1283_5b01,
            0x2431_85be,
            0x550c_7dc3,
            0x72be_5d74,
            0x80de_b1fe,
            0x9bdc_06a7,
            0xc19b_f174,
            0xe49b_69c1,
            0xefbe_4786,
            0x0fc1_9dc6,
            0x240c_a1cc,
            0x2de9_2c6f,
            0x4a74_84aa,
            0x5cb0_a9dc,
            0x76f9_88da,
            0x983e_5152,
            0xa831_c66d,
            0xb003_27c8,
            0xbf59_7fc7,
            0xc6e0_0bf3,
            0xd5a7_9147,
            0x06ca_6351,
            0x1429_2967,
            0x27b7_0a85,
            0x2e1b_2138,
            0x4d2c_6dfc,
            0x5338_0d13,
            0x650a_7354,
            0x766a_0abb,
            0x81c2_c92e,
            0x9272_2c85,
            0xa2bf_e8a1,
            0xa81a_664b,
            0xc24b_8b70,
            0xc76c_51a3,
            0xd192_e819,
            0xd699_0624,
            0xf40e_3585,
            0x106a_a070,
            0x19a4_c116,
            0x1e37_6c08,
            0x2748_774c,
            0x34b0_bcb5,
            0x391c_0cb3,
            0x4ed8_aa4a,
            0x5b9c_ca4f,
            0x682e_6ff3,
            0x748f_82ee,
            0x78a5_636f,
            0x84c8_7814,
            0x8cc7_0208,
            0x90be_fffa,
            0xa450_6ceb,
            0xbef9_a3f7,
            0xc671_78f2,
        ];

        let mut h: [u32; 8] = [
            0x6a09_e667,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ];

        let mut message = input.to_vec();
        let bits = (input.len() as u64) * 8;
        message.push(0x80);
        while message.len() % 64 != 56 {
            message.push(0);
        }
        message.extend_from_slice(&bits.to_be_bytes());

        for chunk in message.chunks(64) {
            let mut w = [0_u32; 64];
            for (i, slot) in w.iter_mut().take(16).enumerate() {
                *slot = u32::from_be_bytes([
                    chunk[i * 4],
                    chunk[i * 4 + 1],
                    chunk[i * 4 + 2],
                    chunk[i * 4 + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            let mut v = h;
            for i in 0..64 {
                let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
                let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
                let t1 = v[7]
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
                let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                let t2 = s0.wrapping_add(maj);

                v[7] = v[6];
                v[6] = v[5];
                v[5] = v[4];
                v[4] = v[3].wrapping_add(t1);
                v[3] = v[2];
                v[2] = v[1];
                v[1] = v[0];
                v[0] = t1.wrapping_add(t2);
            }

            for (slot, value) in h.iter_mut().zip(v) {
                *slot = slot.wrapping_add(value);
            }
        }

        let mut out = [0_u8; 32];
        for (i, word) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

fn leaves(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| leaf_hash(&TestHasher, format!("event-{i}").as_bytes()))
        .collect()
}

#[test]
fn the_hasher_this_test_uses_is_the_real_one() {
    let digest = TestHasher.sha256(b"abc");
    assert_eq!(
        argus_core::hex::encode(&digest),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn a_leaf_and_an_interior_node_cannot_be_confused() {
    let left = TestHasher.sha256(b"l");
    let right = TestHasher.sha256(b"r");

    let mut concatenated = Vec::new();
    concatenated.extend_from_slice(&left);
    concatenated.extend_from_slice(&right);

    let as_leaf = leaf_hash(&TestHasher, &concatenated);
    let as_node = argus_core::audit::merkle::node_hash(&TestHasher, &left, &right);

    assert_ne!(as_leaf, as_node);
}

#[test]
fn every_leaf_of_every_tree_up_to_forty_proves_itself() {
    for size in 1..=40 {
        let tree = leaves(size);
        let expected = root(&TestHasher, &tree);

        for index in 0..size {
            let proof = inclusion_proof(&TestHasher, &tree, index).expect("proof");
            assert!(
                verify_inclusion(&TestHasher, &tree[index], index, size, &proof, &expected),
                "size {size} index {index} failed to verify"
            );

            assert!(
                proof.len() <= 6,
                "size {size} index {index} produced {} hashes",
                proof.len()
            );
        }
    }
}

#[test]
fn a_proof_for_the_wrong_leaf_is_refused() {
    let tree = leaves(17);
    let expected = root(&TestHasher, &tree);
    let proof = inclusion_proof(&TestHasher, &tree, 5).expect("proof");

    assert!(!verify_inclusion(
        &TestHasher,
        &tree[6],
        5,
        17,
        &proof,
        &expected
    ));
}

#[test]
fn a_proof_presented_at_the_wrong_index_is_refused() {
    let tree = leaves(17);
    let expected = root(&TestHasher, &tree);
    let proof = inclusion_proof(&TestHasher, &tree, 5).expect("proof");

    assert!(!verify_inclusion(
        &TestHasher,
        &tree[5],
        6,
        17,
        &proof,
        &expected
    ));
}

#[test]
fn a_tampered_sibling_is_refused() {
    let tree = leaves(11);
    let expected = root(&TestHasher, &tree);
    let mut proof = inclusion_proof(&TestHasher, &tree, 3).expect("proof");

    if let Some(first) = proof.first_mut() {
        first[0] ^= 0xff;
    }

    assert!(!verify_inclusion(
        &TestHasher,
        &tree[3],
        3,
        11,
        &proof,
        &expected
    ));
}

#[test]
fn a_proof_with_a_hash_left_over_is_refused() {
    let tree = leaves(8);
    let expected = root(&TestHasher, &tree);
    let mut proof = inclusion_proof(&TestHasher, &tree, 0).expect("proof");
    proof.push([0_u8; 32]);

    assert!(!verify_inclusion(
        &TestHasher,
        &tree[0],
        0,
        8,
        &proof,
        &expected
    ));
}

#[test]
fn an_index_past_the_end_has_no_proof() {
    let tree = leaves(4);
    assert!(inclusion_proof(&TestHasher, &tree, 4).is_none());
}

#[test]
fn a_log_that_only_grew_proves_it_for_every_pair_of_sizes() {
    for new_size in 1..=32 {
        let tree = leaves(new_size);
        let new_root = root(&TestHasher, &tree);

        for old_size in 1..=new_size {
            let old_root = root(&TestHasher, &tree[..old_size]);
            let proof = consistency_proof(&TestHasher, &tree, old_size).expect("proof");

            assert!(
                verify_consistency(
                    &TestHasher,
                    old_size,
                    &old_root,
                    new_size,
                    &new_root,
                    &proof
                ),
                "{old_size} -> {new_size} failed to verify"
            );
        }
    }
}

#[test]
fn a_log_that_was_rewritten_cannot_prove_consistency() {
    let honest = leaves(16);
    let old_size = 9;
    let old_root = root(&TestHasher, &honest[..old_size]);

    let mut rewritten = honest.clone();
    rewritten[4] = leaf_hash(&TestHasher, b"event-4-was-changed");
    let new_root = root(&TestHasher, &rewritten);
    let proof = consistency_proof(&TestHasher, &rewritten, old_size).expect("proof");

    assert!(
        !verify_consistency(&TestHasher, old_size, &old_root, 16, &new_root, &proof),
        "a rewritten prefix must not verify against the root it had before"
    );
}

#[test]
fn a_shrinking_log_is_refused() {
    let tree = leaves(8);
    let big = root(&TestHasher, &tree);
    let small = root(&TestHasher, &tree[..4]);

    assert!(!verify_consistency(&TestHasher, 8, &big, 4, &small, &[]));
}

#[test]
fn a_tree_that_did_not_change_needs_no_proof() {
    let tree = leaves(6);
    let here = root(&TestHasher, &tree);
    assert!(verify_consistency(&TestHasher, 6, &here, 6, &here, &[]));
    assert!(!verify_consistency(
        &TestHasher,
        6,
        &here,
        6,
        &here,
        &[[0_u8; 32]]
    ));
}
