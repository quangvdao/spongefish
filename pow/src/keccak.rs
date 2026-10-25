use ::keccak::{Keccak, State1600};

use super::PowStrategy;
use crate::difficulty_target;

#[derive(Clone, Copy)]
pub struct KeccakPoW {
    challenge: [u64; 4],
    threshold: u64,
    state: [u64; 25],
}

impl KeccakPoW {
    /// Create a new `KeccakPoW` instance with a given challenge and difficulty.
    ///
    /// # Panics
    /// - If `bits` is not in the range `0..60`.
    pub fn new(challenge: [u8; 32], bits: u32) -> Self {
        let threshold = difficulty_target(bits);
        Self {
            challenge: bytemuck::cast(challenge),
            threshold,
            state: [0; 25],
        }
    }
}

impl PowStrategy for KeccakPoW {
    fn check(&mut self, nonce: u64) -> bool {
        self.state[..4].copy_from_slice(&self.challenge);
        self.state[4] = nonce;
        for s in self.state.iter_mut().skip(5) {
            *s = 0;
        }
        f1600(&mut self.state);
        self.state[0] <= self.threshold
    }
}

fn f1600(state: &mut State1600) {
    Keccak::new().with_f1600(|f1600| f1600(state));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_pow_keccak() {
        use crate::{convenience::*, PoWGrinder};

        const BITS: u32 = 10;

        // Test with a fixed challenge
        let challenge = [42u8; 32];

        // Generate a proof-of-work solution
        let solution =
            grind_pow(KeccakPoW::new(challenge, BITS)).expect("Should find a valid solution");

        // Grinding is deterministic: it returns the minimal satisfying nonce, so
        // re-grinding the same challenge must yield the very same solution.
        let mut grinder = PoWGrinder::new(KeccakPoW::new(challenge, BITS));
        let solution2 = grinder.grind().expect("Should find a valid solution");
        assert_eq!(solution, solution2);

        // And the nonce must verify against the original challenge.
        assert!(verify_pow(KeccakPoW::new(challenge, BITS), solution));
    }

    /// Difficulties at or above 60 bits are out of the supported range.
    #[test]
    #[should_panic(expected = "bits must be smaller than 60")]
    fn test_keccak_rejects_excessive_bits() {
        let _ = KeccakPoW::new([0u8; 32], 60);
    }

    /// A difficulty inside the supported range still grinds and verifies.
    #[test]
    fn test_keccak_valid_difficulty_round_trip() {
        use crate::convenience::*;

        let challenge = [7u8; 32];
        for bits in [0, 1, 8, 12] {
            let solution =
                grind_pow(KeccakPoW::new(challenge, bits)).expect("Should find a valid solution");
            assert!(verify_pow(KeccakPoW::new(challenge, bits), solution));
        }
    }
}
