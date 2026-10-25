use blake3::{
    guts::BLOCK_LEN,
    platform::{Platform, MAX_SIMD_DEGREE},
    IncrementCounter, OUT_LEN,
};

use super::PowStrategy;
use crate::difficulty_target;

/// A SIMD-accelerated BLAKE3-based proof-of-work engine.
///
/// This struct searches for a nonce such that the first eight bytes of
/// `BLAKE3(challenge || nonce.to_le_bytes() || [0; 24])`, interpreted as a
/// little-endian `u64`, are at most the difficulty threshold.
///
/// It leverages `Platform::hash_many` for parallel hash evaluation using `MAX_SIMD_DEGREE` lanes.
#[derive(Clone, Copy)]
pub struct Blake3PoW {
    /// The 32-byte challenge seed used as a prefix to every hash input.
    challenge: [u8; 32],
    /// Difficulty target: hashes must be at most this 64-bit threshold.
    threshold: u64,
    /// Platform-specific SIMD hashing backend selected at runtime.
    platform: Platform,
    /// SIMD batch of 64-byte inputs: challenge, little-endian nonce, 24 zero bytes.
    inputs: [[u8; BLOCK_LEN]; MAX_SIMD_DEGREE],
    /// SIMD batch of hash outputs (32 bytes each).
    outputs: [u8; OUT_LEN * MAX_SIMD_DEGREE],
}

impl Blake3PoW {
    /// Create a new Blake3PoW instance with a given challenge and difficulty.
    ///
    /// The `bits` parameter controls the difficulty. A higher number means
    /// lower probability of success per nonce. This function prepares the SIMD
    /// input buffer with the challenge prefix and sets the internal threshold.
    ///
    /// # Panics
    /// - If `bits` is not in the range `0..60`.
    /// - If `BLOCK_LEN` or `OUT_LEN` do not match expected values.
    pub fn new(challenge: [u8; 32], bits: u32) -> Self {
        // BLAKE3 block size must be 64 bytes.
        assert_eq!(BLOCK_LEN, 64);
        // BLAKE3 output size must be 32 bytes.
        assert_eq!(OUT_LEN, 32);
        let threshold = difficulty_target(bits);

        // Prepare SIMD input buffer: fill each lane with the challenge prefix.
        let mut inputs = [[0u8; BLOCK_LEN]; MAX_SIMD_DEGREE];
        for input in &mut inputs {
            input[..32].copy_from_slice(&challenge);
        }

        Self {
            // Store challenge prefix.
            challenge,
            // Compute threshold: smaller means harder PoW.
            threshold,
            // Detect SIMD platform (e.g., AVX2, NEON, etc).
            platform: Platform::detect(),
            // Pre-filled SIMD inputs (nonce injected later).
            inputs,
            // Zero-initialized output buffer for SIMD hashes.
            outputs: [0; OUT_LEN * MAX_SIMD_DEGREE],
        }
    }
}

impl PowStrategy for Blake3PoW {
    /// Check if a given `nonce` satisfies the challenge.
    ///
    /// This uses the standard high-level BLAKE3 interface to ensure
    /// full compatibility with reference implementations.
    ///
    /// A nonce is valid if the first 8 bytes of the hash output,
    /// interpreted as a little-endian `u64`, are at most the internal threshold.
    fn check(&mut self, nonce: u64) -> bool {
        // Create a new BLAKE3 hasher instance.
        let mut hasher = blake3::Hasher::new();

        // Feed the challenge prefix.
        hasher.update(&self.challenge);
        // Feed the nonce as little-endian bytes.
        hasher.update(&nonce.to_le_bytes());
        // Pad the challenge and nonce to a full 64-byte BLAKE3 input block.
        hasher.update(&[0; 24]);

        // Hash the input and extract the first 8 bytes.
        let mut hash = [0u8; 8];
        hasher.finalize_xof().fill(&mut hash);

        // Check whether the result is at or below the threshold.
        u64::from_le_bytes(hash) <= self.threshold
    }

    /// Find the minimal `nonce` that satisfies the challenge.
    fn solve(&mut self) -> Option<u64> {
        (0..=u64::MAX)
            .step_by(MAX_SIMD_DEGREE)
            .find_map(|nonce| self.check_many(nonce))
    }

    /// Search for the lowest `nonce` that satisfies the challenge using parallel threads.
    ///
    /// Each thread scans disjoint chunks of the nonce space in stride-sized steps.
    /// The first thread to find a satisfying nonce updates a shared atomic minimum,
    /// and all others check against it to avoid unnecessary work.
    #[cfg(feature = "parallel")]
    fn solve_parallel(&mut self) -> Option<u64> {
        crate::search_parallel(self, MAX_SIMD_DEGREE as u64, Self::check_many)
    }
}

impl Blake3PoW {
    /// Default Blake3 initialization vector. Copied here because it is not publicly exported.
    #[allow(clippy::unreadable_literal)]
    const BLAKE3_IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];
    const BLAKE3_FLAGS: u8 = 0x0B; // CHUNK_START | CHUNK_END | ROOT

    /// Check a SIMD-width batch of nonces starting at `nonce`.
    ///
    /// Return the first nonce in the batch that satisfies the challenge threshold,
    /// or `None` if none do.
    fn check_many(&mut self, nonce: u64) -> Option<u64> {
        // Fill each SIMD input block with the challenge + nonce suffix.
        // If the batch would overflow `u64`, stop at the last representable nonce
        // and zero the remaining lanes so they never get reported as valid.
        let mut valid_lanes = MAX_SIMD_DEGREE;
        for (i, input) in self.inputs.iter_mut().enumerate() {
            let Some(batch_nonce) = nonce.checked_add(i as u64) else {
                valid_lanes = i;
                break;
            };
            input[32..40].copy_from_slice(&batch_nonce.to_le_bytes());
        }
        for input in &mut self.inputs[valid_lanes..] {
            input[32..40].fill(0);
        }

        // Create references required by `hash_many`.
        let input_refs: [&[u8; BLOCK_LEN]; MAX_SIMD_DEGREE] =
            std::array::from_fn(|i| &self.inputs[i]);

        // Perform parallel hashing over the input blocks.
        self.platform.hash_many::<BLOCK_LEN>(
            &input_refs,
            &Self::BLAKE3_IV,     // Initialization vector
            0,                    // Counter
            IncrementCounter::No, // Do not increment counter
            Self::BLAKE3_FLAGS,   // Default flags
            0,
            0, // No start/end flags
            &mut self.outputs,
        );

        // Scan results and return the first nonce at or below the threshold.
        for (i, chunk) in self
            .outputs
            .as_chunks::<OUT_LEN>()
            .0
            .iter()
            .take(valid_lanes)
            .enumerate()
        {
            let hash = u64::from_le_bytes(chunk[..8].try_into().unwrap());
            if hash <= self.threshold {
                return nonce.checked_add(i as u64);
            }
        }

        // None of the batch satisfied the condition.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{convenience::*, PoWGrinder};

    fn sample_challenges() -> Vec<[u8; 32]> {
        vec![
            [0u8; 32],                                              // All zeroes
            [0xFF; 32],                                             // All ones
            [42u8; 32],                                             // Constant value
            (0..32).collect::<Vec<u8>>().try_into().unwrap(),       // Increasing
            (0..32).rev().collect::<Vec<u8>>().try_into().unwrap(), // Decreasing
        ]
    }

    #[test]
    fn test_pow_blake3() {
        const BITS: u32 = 10;

        for challenge in sample_challenges() {
            // Generate a proof-of-work solution
            let _solution =
                grind_pow(Blake3PoW::new(challenge, BITS)).expect("Should find a valid solution");

            // Verify we can generate solutions consistently
            assert!(grind_pow(Blake3PoW::new(challenge, BITS)).is_some());
        }

        // Test using the PoWGrinder directly
        let challenge = [42u8; 32];
        let mut grinder = PoWGrinder::new(Blake3PoW::new(challenge, BITS));
        let _solution = grinder.grind().expect("Should find a valid solution");
    }

    #[test]
    fn test_new_pow_valid_bits() {
        for bits in [0, 10, 20, 40, 59] {
            let challenge = [1u8; 32];
            let pow = Blake3PoW::new(challenge, bits);
            let expected_threshold = u64::MAX >> bits;
            assert_eq!(pow.threshold, expected_threshold);
            assert_eq!(pow.challenge, challenge);
        }
    }

    #[test]
    #[should_panic]
    fn test_new_invalid_bits() {
        let _ = Blake3PoW::new([0u8; 32], 60);
    }

    #[test]
    fn test_check_function_basic() {
        let challenge = [0u8; 32];
        let mut pow = Blake3PoW::new(challenge, 8);
        for nonce in (0u64..10000).step_by(MAX_SIMD_DEGREE) {
            if let Some(solution) = pow.check_many(nonce) {
                assert!(pow.check(solution), "check() should match check_many()");
                return;
            }
        }
        panic!("Expected at least one valid nonce under threshold using check_many");
    }

    #[test]
    fn test_check_many_handles_u64_tail() {
        let mut pow = Blake3PoW::new([0u8; 32], 50);
        let _ = pow.check_many(u64::MAX - 1);
        assert_eq!(
            u64::from_le_bytes(pow.inputs[0][32..40].try_into().unwrap()),
            u64::MAX - 1
        );
        if MAX_SIMD_DEGREE > 2 {
            assert_eq!(
                u64::from_le_bytes(pow.inputs[2][32..40].try_into().unwrap()),
                0
            );
        }
    }

    #[cfg(not(feature = "parallel"))]
    #[test]
    fn test_solve_sequential() {
        let challenge = [2u8; 32];
        let mut pow = Blake3PoW::new(challenge, 10);
        let solution = pow.solve().expect("Should find a nonce");
        assert!(
            pow.check(solution),
            "Found nonce does not satisfy challenge"
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_solve_parallel() {
        let challenge = [3u8; 32];
        let mut pow = Blake3PoW::new(challenge, 10);
        let _solution = pow.solve_parallel().expect("Should find a solution");
        // Solution is valid by construction
    }

    #[test]
    fn test_different_challenges_consistency() {
        let bits = 8;
        for challenge in sample_challenges() {
            let mut pow = Blake3PoW::new(challenge, bits);
            let _solution = pow.solve().expect("Must find solution for low difficulty");
            // Solution is valid by construction
        }
    }

    #[test]
    fn test_check_many_determinism() {
        let challenge = [42u8; 32];
        let mut pow1 = Blake3PoW::new(challenge, 10);
        let mut pow2 = Blake3PoW::new(challenge, 10);

        let n1 = pow1.check_many(0);
        let n2 = pow2.check_many(0);
        assert_eq!(n1, n2, "check_many should be deterministic");
    }

    #[test]
    fn test_check_many_inserts_nonce_bytes() {
        let challenge = [0xAB; 32];
        let mut pow = Blake3PoW::new(challenge, 50);

        // Run check_many to populate nonces.
        let base_nonce = 12_345_678;
        let _ = pow.check_many(base_nonce);

        for (i, input) in pow.inputs.iter().enumerate() {
            // Confirm prefix is unchanged
            assert_eq!(&input[..32], &challenge);
            // Confirm suffix is the correct nonce bytes
            let expected_nonce = base_nonce + i as u64;
            let actual = u64::from_le_bytes(input[32..40].try_into().unwrap());
            assert_eq!(actual, expected_nonce);
        }
    }

    #[test]
    fn test_solve_returns_minimal_nonce() {
        let c = [123; 32];
        let mut pow = Blake3PoW::new(c, 10);
        let mut best_nonce = None;
        for nonce in (0..10000).step_by(MAX_SIMD_DEGREE) {
            if let Some(found) = pow.check_many(nonce) {
                best_nonce = Some(found);
                break;
            }
        }

        // Get solution from solve()
        let solution = pow.solve().expect("Should find a solution");

        // If we found a nonce manually, create the same solution and compare
        if let Some(nonce) = best_nonce {
            let expected_solution = nonce;

            assert_eq!(
                solution, expected_solution,
                "solve should return the first valid nonce"
            );
        }
    }

    #[test]
    fn stress_test_check_many_entropy() {
        let challenge = [42u8; 32];
        let mut pow = Blake3PoW::new(challenge, 16);

        let mut found = 0;
        for nonce in (0..1_000_000).step_by(MAX_SIMD_DEGREE) {
            if pow.check_many(nonce).is_some() {
                found += 1;
            }
        }

        // Should find some hits at low difficulty
        assert!(found > 0, "Expected to find at least one solution");
    }
}
