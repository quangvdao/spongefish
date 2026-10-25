# Fiat–Shamir with proof-of-work for verifier messages

This crate is an extension of spongefish for grinding or proof-of-work mechanisms in multi-round public coin protocols.

## Security disclaimer and expectations

⚠️⚠️⚠️⚠️ THIS CRATE IS AN EXPERIMENT AND NOT READY FOR PRODUCTION USE ⚠️⚠️⚠️⚠️

It has not been reviewed, and should be considered a proof-of-concept example that does not make any claim about security.

## Wiring into a NARG

The `PowTranscriptExt` extension adds a proof-of-work step to every `Transcript`. It works both inside a generic `Argument::run` and directly on `ProverState` and `VerifierState`. The step returns `Result<(), VerificationError>`; callers then obtain the protected verifier message. The standalone `PoWGrinder` and convenience functions remain available for other integrations.

Both parties exchange a compact nonce and check bytes squeezed from the public duplex sponge. The caller then draws the protected verifier message. A rejected or truncated nonce poisons the verifier. Generic transcript search is sequential even with `parallel`; standalone prepared strategies still provide explicit parallel execution.

Use the default features of `spongefish` and `spongefish-pow` for this example:

```rust
use spongefish::{DefaultHash, Narg, ProverState, VerificationError, VerifierState};
use spongefish_pow::PowTranscriptExt;

// Fixed by the protocol, never read from the proof.
const POW_BITS: u32 = 8;

fn main() -> Result<(), VerificationError> {
    let session_id = Narg::derive_session_id(b"example/v1/sponge-pow-8/u32");
    let instance = 0u32;

    let mut prover = ProverState::<DefaultHash>::new(&session_id, &instance);
    prover.sponge_pow(POW_BITS)?;
    let challenge = prover.verifier_message::<u32>();
    let proof = prover.into_narg_string();

    let mut verifier = VerifierState::<DefaultHash>::new(&session_id, &instance, &proof);
    verifier.sponge_pow(POW_BITS)?;
    let replay = verifier.verifier_message::<u32>();
    assert_eq!(challenge, replay);
    verifier.check_eof()
}
```

The same method is available with only a `Transcript` bound, so an interactive argument can use it directly:

```rust
use spongefish::{Argument, Transcript, VerificationError, Witness};
use spongefish_pow::PowTranscriptExt;

struct PowRound;
impl Argument for PowRound {
    type Instance = u32;
    type Witness = ();
    type Output = u32;

    fn run<T: Transcript>(
        transcript: &mut T,
        _instance: &u32,
        _witness: Witness<&()>,
    ) -> Result<u32, VerificationError> {
        transcript.sponge_pow(8)?;
        Ok(transcript.verifier_message())
    }
}
```

The nonce is canonical LEB128 below `2^(bits + 7)`, with integer difficulty at most 25. The sponge backend, difficulty, placement of the step, and protected message type must be fixed by the protocol and accounted for in its session tag. The example uses a cheap difficulty for demonstration; the appropriate work factor and soundness benefit depend on the protocol.

## Prepared strategies

Standalone problems use a prepared strategy. Construction stays
with the backend, and the result is the nonce itself. With `blake3` enabled:

```rust
use spongefish_pow::{blake3::Blake3PoW, PoWGrinder};

let mut grinder = PoWGrinder::new(Blake3PoW::new([7; 32], 8));
let nonce = grinder.grind().unwrap(); // Always sequential.
assert!(grinder.verify(nonce));

// With the parallel feature: same problem and least nonce, independent jobs.
#[cfg(feature = "parallel")]
assert_eq!(grinder.grind_parallel(), Some(nonce));
```

`KeccakPoW::new(seed, bits)` is interchangeable at the grinder boundary.
