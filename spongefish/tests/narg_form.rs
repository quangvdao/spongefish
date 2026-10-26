//! A prover message whose NARG form differs from its absorbed form.
//!
//! `Varint` is absorbed as a fixed-width `u64` word but written to the NARG
//! string as LEB128. The transcript must match a `u64` message's exactly, the
//! proof must be shorter, and a second serialization of the same value must be
//! rejected even though `Varint`'s parser accepts it.
use spongefish::{
    Argument, Encoding, FromNarg, Narg, NargReader, ToNarg, Transcript, VerificationError, Witness,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Varint(u64);

impl Encoding for Varint {
    fn encode(&self) -> impl AsRef<[u8]> {
        self.0.to_le_bytes()
    }
}

impl ToNarg for Varint {
    fn to_narg(&self, narg: &mut Vec<u8>) {
        let mut value = self.0;
        loop {
            let low = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                narg.push(low);
                return;
            }
            narg.push(low | 0x80);
        }
    }
}

impl FromNarg for Varint {
    /// Deliberately lax: it accepts a trailing zero byte, so `0x85 0x00`
    /// parses to 5 just as `0x05` does. The transcript must still reject it.
    fn from_narg(reader: &mut NargReader<'_>) -> Result<Self, VerificationError> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let [byte] = reader.take_array::<1>()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(Self(value));
            }
        }
        Err(VerificationError)
    }
}

/// A derived message composes each field's NARG form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encoding, FromNarg, ToNarg)]
struct Pair {
    a: Varint,
    b: u32,
}

const TAG: &[u8] = b"tests/narg-form";

struct Compact;
impl Argument for Compact {
    type Instance = u32;
    type Witness = u64;
    type Output = [u64; 2];

    fn run<T: Transcript>(
        transcript: &mut T,
        _instance: &u32,
        witness: Witness<&u64>,
    ) -> Result<[u64; 2], VerificationError> {
        let w = transcript.prover_message(witness.map(|&w| Varint(w)))?;
        let c: u64 = transcript.verifier_message();
        transcript.prover_message(Witness::known([Varint(c % 300), Varint(w.0)]))?;
        transcript.prover_message(Witness::known(Pair { a: Varint(3), b: 4 }))?;
        Ok([c, transcript.verifier_message()])
    }
}

/// The same messages, sent with the default `u64` codec.
struct Wide;
impl Argument for Wide {
    type Instance = u32;
    type Witness = u64;
    type Output = [u64; 2];

    fn run<T: Transcript>(
        transcript: &mut T,
        _instance: &u32,
        witness: Witness<&u64>,
    ) -> Result<[u64; 2], VerificationError> {
        let w = transcript.prover_message(witness.copied())?;
        let c: u64 = transcript.verifier_message();
        transcript.prover_message(Witness::known([c % 300, w]))?;
        transcript.prover_message(Witness::known(3u64))?;
        transcript.prover_message(Witness::known(4u32))?;
        Ok([c, transcript.verifier_message()])
    }
}

#[test]
fn the_wire_form_changes_the_proof_but_not_the_transcript() {
    let (compact, compact_out) = Narg::prove::<Compact>(TAG, &0, &5).unwrap();
    let (wide, wide_out) = Narg::prove::<Wide>(TAG, &0, &5).unwrap();
    assert_eq!(compact_out, wide_out, "both absorb the same words");
    assert_eq!(wide.len(), 8 + 16 + 12);
    let c = compact_out[0] % 300;
    let mut expected = vec![0x05];
    Varint(c).to_narg(&mut expected);
    expected.extend_from_slice(&[0x05, 0x03, 4, 0, 0, 0]);
    assert_eq!(compact, expected);
    assert_eq!(
        Narg::verify::<Compact>(TAG, &0, &compact).unwrap(),
        compact_out
    );
}

#[test]
fn a_second_serialization_of_the_same_value_is_rejected() {
    let (narg, _) = Narg::prove::<Compact>(TAG, &0, &5).unwrap();
    assert_eq!(narg[0], 0x05);
    let mut mauled = vec![0x85, 0x00];
    mauled.extend_from_slice(&narg[1..]);
    let mut reader = NargReader::new(&mauled);
    assert_eq!(
        reader.read::<Varint>().unwrap(),
        Varint(5),
        "the parser alone accepts it"
    );
    assert!(Narg::verify::<Compact>(TAG, &0, &mauled).is_err());
}
