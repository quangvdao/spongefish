//! An interactive proof-of-work step shared by every `Transcript` implementation.

#[cfg(feature = "parallel")]
use spongefish::{DuplexSpongeInit, DuplexSpongeInterface, ProverState};
use spongefish::{FromUniform, Transcript, VerificationError, Witness};

use crate::{PoWGrinder, PowStrategy};

/// Proof-of-work-protected verifier messages for [`Transcript`] implementations.
///
/// This extension is available on every [`Transcript`], including concrete
/// [`ProverState`](spongefish::ProverState) and
/// [`VerifierState`](spongefish::VerifierState) values and the generic [`Transcript`]
/// passed to [`Argument::run`](spongefish::Argument::run).
///
/// Both parties exchange a short variable-length nonce, check it against
/// bytes from the public duplex sponge, then obtain the protected verifier
/// message. Grinding is a prover-only computation; the verifier checks the
/// received nonce without running the search.
///
/// A rejected nonce fails [`Transcript::check`], permanently rejecting the
/// verifier state even if the error is caught. Truncated nonces fail
/// during the prover-message read.
///
/// # Protocol parameters
///
/// The duplex sponge backend, difficulty, position of this step, and the codec of the
/// protected message must be fixed by the protocol and accounted for in its
/// session tag. The difficulty must not come from an untrusted proof value.
/// Any soundness benefit depends on the surrounding protocol and duplex sponge backend.
///
/// # Example
///
/// ```
/// use spongefish::{Argument, Narg, Transcript, VerificationError, Witness};
/// use spongefish_pow::PowTranscriptExt;
///
/// struct PowRound;
/// impl Argument for PowRound {
///     type Instance = u32;
///     type Witness = ();
///     type Output = u32;
///
///     fn run<T: Transcript>(
///         transcript: &mut T,
///         _instance: &u32,
///         _witness: Witness<&()>,
///     ) -> Result<u32, VerificationError> {
///         transcript.verifier_message_pow(8)
///     }
/// }
///
/// let tag = b"example/v1/sponge-pow-8/u32";
/// let (proof, challenge) = Narg::prove::<PowRound>(tag, &0, &())?;
/// let replay = Narg::verify::<PowRound>(tag, &0, &proof)?;
/// assert_eq!(challenge, replay);
/// # Ok::<(), spongefish::VerificationError>(())
/// ```
pub trait PowTranscriptExt: Transcript {
    /// A proof of work on the public duplex sponge itself.
    ///
    /// For `bits > 0`, the prover sends a nonce below `2^(bits + 7)` as
    /// canonical LEB128: seven bits per byte, least significant first, the
    /// high bit set on every byte but the last, and no trailing zero byte. Both
    /// parties then squeeze `ceil(bits / 8)` bytes and accept the nonce iff
    /// their low `bits` bits are zero, then return the protected verifier
    /// message. For `bits == 0`, it returns an ordinary verifier message without
    /// a nonce or check bytes.
    ///
    /// The returned message is protected, as are further verifier messages up to the
    /// next prover message. A type implementing [`FromUniform`] can bundle a
    /// group of protected challenges into one returned message.
    ///
    /// The prover sends the least accepted nonce. It is below 128, and takes one
    /// byte, with probability `1 - (1 - 2^-bits)^128`: at least `1 - e^-8` for
    /// `bits <= 4`. The nonce space holds `2^7` times the expected number of
    /// trials, so for an ideal duplex sponge an honest search fails with probability
    /// at most `e^-128`. This method always searches sequentially. The `parallel`
    /// feature provides `verifier_message_pow_parallel` for concrete provers;
    /// both paths return the same least nonce and produce identical proofs.
    ///
    /// # Security
    ///
    /// For a fresh ideal duplex sponge output, the check passes with
    /// probability `2^-bits`, and conditioning only on that check leaves the
    /// bytes that follow uniform. A cheating prover can also select on the
    /// protected messages, paying for both conditions. The soundness of the
    /// whole protocol depends on its state-restoration soundness, on the
    /// backend's reduction to an ideal primitive, and on the decoding bias of
    /// the protected messages. Chiesa and Orrù give such a reduction, with an
    /// additive error, for the permutation-backed overwrite duplex sponge; it
    /// does not by itself cover the digest and XOF bridges. The difficulty, the
    /// position of this step and the messages it protects must be fixed by the
    /// protocol and bound in its session.
    ///
    /// # Cost
    ///
    /// This step needs no separate proof-of-work hash and no grinding
    /// challenge. With a permutation-backed duplex sponge, when the nonce fits in the
    /// current absorb block and the check and the protected messages fit in one
    /// rate block, each search trial costs one permutation call and the
    /// verifier needs one permutation after the nonce. Other alignments, longer
    /// outputs and other backends can cost more.
    ///
    /// # Errors
    ///
    /// The prover returns [`VerificationError`] if the search exhausts the
    /// nonce space, or if the [`Transcript`] implementation does not support
    /// [`Transcript::search_verifier_message`] and rejects the resulting unknown prover
    /// message, as [`ProverState`](spongefish::ProverState) does. For
    /// `bits > 0`, the verifier returns it if the nonce is not canonical,
    /// exceeds the nonce space or misses the target, or if the proof is
    /// truncated. At any difficulty, an earlier failed read or check also
    /// rejects the step.
    ///
    /// # Panics
    ///
    /// Panics if `bits > 57`. Above that, a `u64` nonce no longer leaves `2^7`
    /// times the expected work.
    fn verifier_message_pow<T: FromUniform>(&mut self, bits: u32) -> Result<T, VerificationError> {
        validate_bits(bits);
        let nonce = if bits == 0 {
            Witness::unknown()
        } else {
            self.search_verifier_message()
                .map(|evaluate| PoWGrinder::new(TranscriptPoW::new(evaluate, bits)).grind())
        };
        finish_pow(self, bits, nonce)
    }
}

impl<T: Transcript + ?Sized> PowTranscriptExt for T {}

/// Obtain a protected verifier message using parallel search on a concrete prover.
///
/// Available with `parallel`. Only the public duplex sponge must be `Send`; evaluator
/// clones are made on the calling thread and moved into independent jobs.
/// There are as many jobs as pool threads, each with its own snapshot; Rayon
/// may schedule them on any worker. Each trial clones its job's snapshot to
/// restart from the same state. No `Sync` bound is required.
/// The private RNG and proof buffer stay on the calling thread. The least nonce,
/// proof format and returned message match [`PowTranscriptExt::verifier_message_pow`].
/// Verification uses that sequential method and never performs a search.
/// Difficulty, encoding, errors and the 57-bit limit are the same for both paths.
///
/// ```
/// use spongefish::{DefaultHash, Narg, ProverState, VerifierState};
/// use spongefish_pow::{verifier_message_pow_parallel, PowTranscriptExt};
///
/// let session = Narg::derive_session_id(b"parallel-pow/v1");
/// let mut prover = ProverState::<DefaultHash>::new_with_seed(&session, &0u32, [7; 32]);
/// let challenge = verifier_message_pow_parallel::<u64>(&mut prover, 8)?;
/// let proof = prover.into_narg_string();
/// let mut verifier = VerifierState::<DefaultHash>::new(&session, &0u32, &proof);
/// assert_eq!(verifier.verifier_message_pow::<u64>(8)?, challenge);
/// verifier.check_eof()?;
/// # Ok::<(), spongefish::VerificationError>(())
/// ```
#[cfg(feature = "parallel")]
pub fn verifier_message_pow_parallel<T: FromUniform>(
    prover: &mut ProverState<
        impl DuplexSpongeInterface<U = u8> + Send,
        impl DuplexSpongeInit<U = u8>,
    >,
    bits: u32,
) -> Result<T, VerificationError> {
    validate_bits(bits);
    let nonce = if bits == 0 {
        Witness::unknown()
    } else {
        Witness::known(
            PoWGrinder::new(TranscriptPoW::new(prover.search_verifier_message(), bits))
                .grind_parallel(),
        )
    };
    finish_pow(prover, bits, nonce)
}

// Both search paths share every proof-writing and verification operation.
fn finish_pow<T: FromUniform>(
    transcript: &mut (impl Transcript + ?Sized),
    bits: u32,
    nonce: Witness<Option<u64>>,
) -> Result<T, VerificationError> {
    if bits == 0 {
        transcript.check(|| true)?;
        return Ok(transcript.verifier_message());
    }
    let nonce = nonce
        .map(|nonce| nonce.ok_or(VerificationError))
        .transpose()?
        .map(Leb128::new);
    let mut value = 0u128;
    let mut last = 0x80;
    let mut len = 0;
    while last & 0x80 != 0 && len < max_nonce_len(bits) {
        last = transcript.prover_message(nonce.as_ref().map(|nonce| nonce.bytes[len]))?;
        value |= u128::from(last & 0x7f) << (7 * len);
        len += 1;
    }
    transcript.check(|| {
        last & 0x80 == 0 && (len == 1 || last != 0) && value <= u128::from(last_nonce(bits))
    })?;
    let mut word = [0u8; 8];
    for byte in &mut word[..word_len(bits)] {
        *byte = transcript.verifier_message();
    }
    transcript.check(|| accepts(bits, word))?;
    Ok(transcript.verifier_message())
}

// Reserve 2^7 times the expected work in the u64 nonce space.
const MAX_BITS: u32 = 57;

fn validate_bits(bits: u32) {
    assert!(bits <= MAX_BITS, "bits must be at most 57");
}

const fn last_nonce(bits: u32) -> u64 {
    u64::MAX >> (MAX_BITS - bits)
}

const fn max_nonce_len(bits: u32) -> usize {
    (bits as usize + 13) / 7
}

const fn word_len(bits: u32) -> usize {
    (bits as usize).div_ceil(8)
}

const fn accepts(bits: u32, word: [u8; 8]) -> bool {
    u64::from_le_bytes(word) & ((1u64 << bits) - 1) == 0
}

/// A prepared duplex sponge strategy using the same grinder as seeded PoW.
#[derive(Clone)]
struct TranscriptPoW<E> {
    evaluate: E,
    bits: u32,
}

impl<E> TranscriptPoW<E> {
    fn new(evaluate: E, bits: u32) -> Self {
        validate_bits(bits);
        Self { evaluate, bits }
    }
}

impl<E: Fn(&[u8], &mut [u8]) + Clone> PowStrategy for TranscriptPoW<E> {
    fn check(&mut self, nonce: u64) -> bool {
        let mut word = [0u8; 8];
        (self.evaluate)(
            Leb128::new(nonce).as_bytes(),
            &mut word[..word_len(self.bits)],
        );
        accepts(self.bits, word)
    }

    fn last_nonce(&self) -> u64 {
        last_nonce(self.bits)
    }
}

/// The canonical LEB128 encoding of a `u64`.
#[derive(Clone, Copy)]
struct Leb128 {
    bytes: [u8; 10],
    len: usize,
}

impl Leb128 {
    const fn new(mut value: u64) -> Self {
        let mut bytes = [0u8; 10];
        let mut len = 0;
        loop {
            let low = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                bytes[len] = low;
                return Self {
                    bytes,
                    len: len + 1,
                };
            }
            bytes[len] = low | 0x80;
            len += 1;
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use spongefish::{
        instantiations::{Shake128, TurboShake128},
        Argument, DuplexSpongeInit, DuplexSpongeInterface, Narg, ProverState, Transcript,
        VerificationError, VerifierState, Witness,
    };

    use super::PowTranscriptExt;
    // Use different public/private sponges to exercise the refactored RNG bound.
    fn prover() -> ProverState<TurboShake128, Shake128> {
        let session_id = Narg::derive_session_id(b"pow/tests/v1");
        ProverState::new_with_seed(&session_id, &0u32, [7; 32])
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Event {
        Absorb(Vec<u8>),
        Squeeze(usize),
    }

    thread_local! {
        static EVENTS: RefCell<Vec<Event>> = const { RefCell::new(Vec::new()) };
    }

    fn events() -> Vec<Event> {
        EVENTS.with_borrow(Clone::clone)
    }

    #[derive(Clone)]
    struct RecordingSponge<const OUTPUT: u8 = 0>;

    impl<const OUTPUT: u8> DuplexSpongeInterface for RecordingSponge<OUTPUT> {
        type U = u8;

        fn absorb(&mut self, input: &[u8]) -> &mut Self {
            EVENTS.with_borrow_mut(|events| events.push(Event::Absorb(input.to_vec())));
            self
        }

        fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
            EVENTS.with_borrow_mut(|events| events.push(Event::Squeeze(output.len())));
            output.fill(OUTPUT);
            self
        }
    }

    impl<const OUTPUT: u8> DuplexSpongeInit for RecordingSponge<OUTPUT> {
        fn init(_session_id: &[u8; 32]) -> Self {
            Self
        }
    }

    /// A verifier over [`RecordingSponge`], with the log cleared after the
    /// instance is absorbed.
    fn recording_verifier(proof: &[u8]) -> VerifierState<'_, RecordingSponge> {
        let session_id = Narg::derive_session_id(b"pow/tests/v1");
        let verifier = VerifierState::new(&session_id, &0u32, proof);
        EVENTS.with_borrow_mut(Vec::clear);
        verifier
    }

    #[test]
    fn exhausted_grinding_returns_an_error_without_sending_a_nonce() {
        let session_id = Narg::derive_session_id(b"pow/tests/exhausted");
        let mut prover =
            ProverState::<RecordingSponge<255>>::new_with_seed(&session_id, &0u32, [7; 32]);
        assert!(prover.verifier_message_pow::<u64>(1).is_err());
        assert!(prover.into_narg_string().is_empty());
    }

    #[test]
    fn argument_cannot_accept_a_caught_pow_failure() {
        struct SwallowsFailure;
        impl Argument for SwallowsFailure {
            type Instance = u32;
            type Witness = ();
            type Output = ();

            fn run<T: Transcript>(
                transcript: &mut T,
                _instance: &u32,
                _witness: Witness<&()>,
            ) -> Result<(), VerificationError> {
                let _ = transcript.verifier_message_pow::<u64>(8);
                Ok(())
            }
        }
        // Non-canonical nonce: an unnecessary trailing zero byte.
        assert!(Narg::verify::<SwallowsFailure>(b"caught PoW failure", &0, &[0x80, 0]).is_err());
    }

    #[test]
    fn rejected_nonce_produces_no_challenge_and_poisoning_survives_caught_errors() {
        let session_id = Narg::derive_session_id(b"pow/tests/rejected");
        let mut verifier = VerifierState::<RecordingSponge<255>>::new(&session_id, &0u32, &[0]);
        EVENTS.with_borrow_mut(Vec::clear);
        assert!(verifier.verifier_message_pow::<u64>(8).is_err());
        // Only the check byte is squeezed; no protected challenge is produced.
        assert_eq!(events(), [Event::Absorb(vec![0]), Event::Squeeze(1)]);
        assert!(verifier
            .check(|| panic!("a failed check must not run again"))
            .is_err());
        assert!(verifier.prover_message::<u8>().is_err());
        assert!(verifier.prover_messages_vec::<u8>(0).is_err());
        assert!(verifier.verifier_message_pow::<u64>(8).is_err());
        assert!(verifier.check_eof().is_err());
    }

    /// The canonical LEB128 encoding of `nonce`.
    fn leb128(nonce: u64) -> Vec<u8> {
        super::Leb128::new(nonce).as_bytes().to_vec()
    }

    /// Whether a candidate makes the next squeezed byte zero.
    fn meets_eight_bits(evaluate: &impl Fn(&[u8], &mut [u8]), nonce: u64) -> bool {
        let mut word = [0u8; 1];
        evaluate(&leb128(nonce), &mut word);
        word[0] == 0
    }

    #[test]
    fn leb128_is_canonical() {
        assert_eq!(leb128(0), [0]);
        assert_eq!(leb128(127), [0x7f]);
        assert_eq!(leb128(128), [0x80, 0x01]);
        assert_eq!(leb128(300), [0xac, 0x02]);
        assert_eq!(
            leb128(u64::MAX),
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );
    }

    #[test]
    fn verifier_message_pow_round_trip() {
        let mut prover = prover();
        prover.prover_message(&123u32);
        let first: u64 = prover.verifier_message_pow(8).unwrap();
        let second: [u8; 32] = prover.verifier_message_pow(12).unwrap();
        let third: u64 = prover.verifier_message_pow(0).unwrap();
        let proof = prover.into_narg_string();
        // 8 bits take at most 3 nonce bytes, 12 bits at most 3, 0 bits none.
        assert!((4 + 2..=4 + 6).contains(&proof.len()));

        let session_id = Narg::derive_session_id(b"pow/tests/v1");
        let mut verifier = VerifierState::<TurboShake128>::new(&session_id, &0u32, &proof);
        assert_eq!(verifier.prover_message::<u32>().unwrap(), 123);
        assert_eq!(verifier.verifier_message_pow::<u64>(8).unwrap(), first);
        assert_eq!(
            verifier.verifier_message_pow::<[u8; 32]>(12).unwrap(),
            second
        );
        assert_eq!(verifier.verifier_message_pow::<u64>(0).unwrap(), third);
        assert!(verifier.check_eof().is_ok());
    }

    #[test]
    fn verifier_message_pow_matches_the_manual_transcript() {
        let mut manual = prover();
        let nonce = Transcript::search_verifier_message(&manual)
            .map(|evaluate| {
                (0..=u64::MAX)
                    .find(|&nonce| meets_eight_bits(&evaluate, nonce))
                    .unwrap()
            })
            .into_known()
            .unwrap();
        for byte in leb128(nonce) {
            manual.prover_message(&byte);
        }
        assert_eq!(manual.verifier_message::<u8>(), 0);
        let expected: u64 = manual.verifier_message();

        let mut fused = prover();
        assert_eq!(fused.verifier_message_pow::<u64>(8).unwrap(), expected);
        assert_eq!(fused.into_narg_string(), leb128(nonce));
        assert_eq!(manual.into_narg_string(), leb128(nonce));
    }

    #[test]
    fn verifier_message_pow_argument_and_direct_state_apis_agree() {
        struct SpongePowRound;
        impl Argument for SpongePowRound {
            type Instance = u32;
            type Witness = ();
            type Output = u64;

            fn run<T: Transcript>(
                transcript: &mut T,
                _instance: &u32,
                _witness: Witness<&()>,
            ) -> Result<u64, VerificationError> {
                transcript.verifier_message_pow(10)
            }
        }

        let tag = b"pow/tests/v1";
        let (proof, challenge) = Narg::prove::<SpongePowRound>(tag, &0, &()).unwrap();
        assert!((1..=3).contains(&proof.len()));
        assert_eq!(
            Narg::verify::<SpongePowRound>(tag, &0, &proof).unwrap(),
            challenge
        );

        let mut direct = prover();
        assert_eq!(direct.verifier_message_pow::<u64>(10).unwrap(), challenge);
        assert_eq!(direct.into_narg_string(), proof);
    }

    #[test]
    fn verifier_message_pow_rejects_a_nonce_that_misses_the_target() {
        let session_id = Narg::derive_session_id(b"pow/tests/v1");
        // The prover and verifier sponges agree before the nonce.
        let (good, bad) = Transcript::search_verifier_message(&prover())
            .map(|evaluate| {
                let good = (0..=u64::MAX)
                    .find(|&n| meets_eight_bits(&evaluate, n))
                    .unwrap();
                let bad = (0..=u64::MAX)
                    .find(|&n| !meets_eight_bits(&evaluate, n))
                    .unwrap();
                (leb128(good), leb128(bad))
            })
            .into_known()
            .unwrap();

        let mut verifier = VerifierState::<TurboShake128>::new(&session_id, &0u32, &good);
        assert!(verifier.verifier_message_pow::<u64>(8).is_ok());
        assert!(verifier.check_eof().is_ok());

        let mut verifier = VerifierState::<TurboShake128>::new(&session_id, &0u32, &bad);
        assert!(verifier.verifier_message_pow::<u64>(8).is_err());
        assert!(verifier.prover_message::<u8>().is_err());
        assert!(verifier.check_eof().is_err());

        for length in 0..good.len() {
            let proof = &good[..length];
            let mut verifier = VerifierState::<TurboShake128>::new(&session_id, &0u32, proof);
            assert!(verifier.verifier_message_pow::<u64>(8).is_err());
            assert!(verifier.check_eof().is_err());
        }
    }

    #[test]
    fn verifier_message_pow_accepts_only_canonical_nonces_in_range() {
        // The recording sponge squeezes zeros, so every nonce meets the
        // target and only the encoding decides.
        let accepted: [(u32, &[u8]); 6] = [
            (1, &[0x00]),
            (1, &[0x7f]),
            (1, &[0x80, 0x01]),
            (1, &[0xff, 0x01]),
            (25, &[0xff, 0xff, 0xff, 0xff, 0x0f]),
            (
                57,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
            ),
        ];
        for (bits, proof) in accepted {
            let mut verifier = recording_verifier(proof);
            assert!(
                verifier.verifier_message_pow::<u64>(bits).is_ok(),
                "{proof:?}"
            );
            assert!(verifier.check_eof().is_ok());
        }
        // A trailing zero byte, a nonce of 2^8 at 1 bit, a continuation past
        // the longest encoding, 2^32 at 25 bits, and an overflowing u64 nonce.
        let rejected: [(u32, &[u8]); 6] = [
            (1, &[0x80, 0x00]),
            (8, &[0x81, 0x80, 0x00]),
            (1, &[0x80, 0x02]),
            (1, &[0x80, 0x80, 0x01]),
            (25, &[0x80, 0x80, 0x80, 0x80, 0x10]),
            (
                57,
                &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02],
            ),
        ];
        for (bits, proof) in rejected {
            let mut verifier = recording_verifier(proof);
            assert!(
                verifier.verifier_message_pow::<u64>(bits).is_err(),
                "{proof:?}"
            );
            assert!(verifier.check_eof().is_err());
        }
    }

    #[test]
    fn verifier_message_pow_verifier_absorbs_the_nonce_then_squeezes_the_check() {
        let mut verifier = recording_verifier(&[0x85, 0x01]);
        assert_eq!(verifier.verifier_message_pow::<u64>(10).unwrap(), 0);
        assert_eq!(
            events(),
            [
                Event::Absorb(vec![0x85]),
                Event::Absorb(vec![0x01]),
                Event::Squeeze(1),
                Event::Squeeze(1),
                Event::Squeeze(8)
            ]
        );
        assert!(verifier.check_eof().is_ok());

        let mut verifier = recording_verifier(&[]);
        assert_eq!(verifier.verifier_message_pow::<u64>(0).unwrap(), 0);
        assert_eq!(events(), [Event::Squeeze(8)]);
        assert!(verifier.check_eof().is_ok());
    }

    #[test]
    fn verifier_message_pow_layout() {
        use super::{accepts, last_nonce, max_nonce_len, word_len, Leb128};
        let layout = |bits| (last_nonce(bits), max_nonce_len(bits), word_len(bits));
        assert_eq!(layout(1), (255, 2, 1));
        assert_eq!(layout(8), ((1 << 15) - 1, 3, 1));
        assert_eq!(layout(10), ((1 << 17) - 1, 3, 2));
        assert_eq!(layout(25), (u64::from(u32::MAX), 5, 4));
        assert_eq!(layout(57), (u64::MAX, 10, 8));
        for bits in 1..=57 {
            assert_eq!(
                Leb128::new(last_nonce(bits)).as_bytes().len(),
                max_nonce_len(bits)
            );
        }
        assert!(accepts(10, [0, 0b1111_1100, 0xff, 0, 0, 0, 0, 0]));
        assert!(!accepts(10, [0, 0b0000_0010, 0, 0, 0, 0, 0, 0]));
        assert!(!accepts(10, [1, 0, 0, 0, 0, 0, 0, 0]));
        assert!(accepts(57, [0, 0, 0, 0, 0, 0, 0, 0xfe]));
        assert!(!accepts(57, [0, 0, 0, 0, 0, 0, 0, 1]));
    }

    #[test]
    fn verifier_message_pow_search_returns_the_least_nonce() {
        use super::{last_nonce, TranscriptPoW};
        use crate::PoWGrinder;
        let evaluate = prover().search_verifier_message();
        for bits in [1, 5, 12] {
            let mut pow = TranscriptPoW::new(evaluate.clone(), bits);
            let least =
                (0..=last_nonce(bits)).find(|&nonce| crate::PowStrategy::check(&mut pow, nonce));
            assert!(least.is_some());
            assert_eq!(PoWGrinder::new(pow).grind(), least);
        }
    }

    #[test]
    fn verifier_message_pow_search_finds_a_lone_nonce_anywhere_in_the_space() {
        use super::{last_nonce, TranscriptPoW};
        use crate::PoWGrinder;
        for bits in [1, 9] {
            let last = last_nonce(bits);
            for target in [None, Some(0), Some(1), Some(last / 2), Some(last)] {
                let evaluate = |candidate: &[u8], out: &mut [u8]| {
                    let hit = target.is_some_and(|nonce| candidate == leb128(nonce));
                    out.fill(if hit { 0 } else { 0xff });
                };
                assert_eq!(
                    PoWGrinder::new(TranscriptPoW::new(evaluate, bits)).grind(),
                    target
                );
                #[cfg(feature = "parallel")]
                {
                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(1)
                        .build()
                        .unwrap();
                    assert_eq!(
                        pool.install(
                            || PoWGrinder::new(TranscriptPoW::new(evaluate, bits)).grind_parallel()
                        ),
                        target
                    );
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "bits must be at most 57")]
    fn verifier_message_pow_rejects_unsupported_difficulty() {
        let _ = prover().verifier_message_pow::<u64>(58);
    }

    #[test]
    fn every_truncated_nonce_is_rejected() {
        // The largest nonce is valid at 57 bits; every proper prefix is incomplete.
        let proof = leb128(u64::MAX);
        for length in 0..proof.len() {
            let mut verifier = recording_verifier(&proof[..length]);
            assert!(verifier.verifier_message_pow::<u64>(57).is_err());
            assert!(!events()
                .iter()
                .any(|event| matches!(event, Event::Squeeze(_))));
            assert!(verifier.check_eof().is_err());
        }
    }
}
