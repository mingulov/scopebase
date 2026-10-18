// SPDX-License-Identifier: Apache-2.0
//! Test-only SHA-256 dependency/API admission; no TT02 verdict implementation.
#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    fn assert_digest(actual: &[u8], expected: &str) {
        assert_eq!(actual.len(), 32, "SHA256_OUTPUT_SIZE");
        let hex: String = actual.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, expected, "SHA256_DIGEST_MISMATCH");
    }

    #[test]
    fn fixed_one_shot_vectors() {
        for (bytes, expected) in [
            (
                &b""[..],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                &b"abc"[..],
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                &b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"[..],
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            let digest: [u8; 32] = Sha256::digest(bytes).into();
            assert_digest(&digest, expected);
        }
    }

    // Independent hashlib recipe and fixed digests: see reference_vectors.py.
    const BOUNDARIES: &[(usize, &str)] = &[
        (
            55,
            "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59",
        ),
        (
            56,
            "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562",
        ),
        (
            63,
            "29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488",
        ),
        (
            64,
            "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108",
        ),
        (
            65,
            "4bfd2c8b6f1eec7a2afeb48b934ee4b2694182027e6d0fc075074f2fabb31781",
        ),
        (
            127,
            "92ca0fa6651ee2f97b884b7246a562fa71250fedefe5ebf270d31c546bfea976",
        ),
        (
            128,
            "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5",
        ),
        (
            129,
            "5099c6a56203f9687f7d33f4bfdf576d31dc91f6b695ecea38b2770c87631135",
        ),
        (
            1024,
            "2bce1ba628720664be4b9fdd77aae0678e5f0f3f02fc6ff641ec879094f6a404",
        ),
    ];

    #[test]
    fn incremental_boundary_vectors() {
        let mut operations = 0;
        for &(size, expected) in BOUNDARIES {
            let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            assert_digest(&Sha256::digest(&bytes), expected);
            for chunk_size in [1, 7, 55, 56, 63, 64, 65, 127, 1024] {
                let mut hasher = Sha256::new();
                hasher.update([]); // Empty updates may appear between actual bytes.
                for chunk in bytes.chunks(chunk_size) {
                    hasher.update(chunk); // MUTATION_SITE: omit this actual update.
                    operations += 1;
                }
                let digest: [u8; 32] = hasher.finalize().into();
                assert_digest(&digest, expected);
            }
        }
        assert!(operations > 0, "nonempty update population");
    }

    #[test]
    fn omitted_update_control_and_restored_twin() {
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let mut mutant = Sha256::new();
        mutant.update(b"a");
        // The faulty adapter omits the required update(b"bc").
        let digest: [u8; 32] = mutant.finalize().into();
        assert_eq!(digest.len(), 32, "mutant setup succeeded");
        let failure = std::panic::catch_unwind(|| assert_digest(&digest, expected))
            .expect_err("omitted-update mutant must fail the digest assertion");
        let message = failure
            .downcast_ref::<String>()
            .expect("digest assertion panic");
        assert!(message.contains("SHA256_DIGEST_MISMATCH"));

        let mut restored = Sha256::new();
        restored.update(b"a");
        restored.update(b"bc");
        let digest: [u8; 32] = restored.finalize().into();
        assert_digest(&digest, expected);
    }
}
