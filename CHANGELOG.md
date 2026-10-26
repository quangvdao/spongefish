# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

See [GitHub releases](https://github.com/arkworks-rs/spongefish/releases) and the git history for anything older than the entry below. From the next release on, this file is maintained by [release-plz](https://release-plz.dev/).

## [Unreleased]

Summary of the work on this branch since `v0.7.4`, as recorded by `git log v0.7.4..HEAD`. This release is a substantial redesign of the public API; expect breaking changes throughout.

### Added

- `Transcript::search_verifier_message` and `ProverState::search_verifier_message`: evaluate verifier output for candidate prover messages without sending an actual prover message. The prover gets an owned, clonable callback evaluated on a clone of the duplex sponge, without dynamic dispatch. The trait method wraps it in `Witness`; the inherent method returns it directly.
- `spongefish-pow::verifier_message_pow_parallel`, available with `parallel`, searches a concrete prover's public duplex sponge on Rayon workers. Only this function requires `H: Send`; generic PoW is sequential and ordinary proving, private RNG and verification bounds are unchanged. Both paths produce identical proofs.
- `spongefish-pow::PowTranscriptExt::verifier_message_pow`, a shared proof-of-work step available on generic `Transcript` implementations and directly on `ProverState` / `VerifierState`. Its signature and proof format changed after `v0.8.0`; see **Changed**.
- New traits: `Argument`, used to define an interactive argument, with type parameters `Instance`, `Witness` and `Output` that define the interactive protocol. The function `Argument::run` is the interactive protocol itself, and relies on a new trait `Transcript` to declare prover / verifier messages and the verifier checks. The trait `Transcript` is implemented by `ProverState` and `VerifierState`.
- Closure-based codecs (`prover_message_as` / `verifier_message_as`, and the alphabet-generic `prover_message_with` / `verifier_message_with`).
- `NargReader`, the forward-only cursor used to read the NARG string (without relying on `std`), and `NargReader::read`, the shorthand for reading one value through it. Every read returns `VerificationError` on failure. A failed read automatically poisons the reader: all later reads fail, including empty reads, and it is never empty.
- Public `NargReader::read_with` runs custom parsers. `read` and `read_with` refuse to invoke parsers on a poisoned reader and reject `Ok` if a nested read failed. Deserializers only return errors; nested parsing uses `read` / `read_with`. Direct calls to `FromNarg` implementation hooks bypass this guarantee.
- `PrivateRng` is now generic over the duplex sponge.
- The `LengthPrefixed` combinator for prefix-free encoding of variable-length sequences.
- `Encoding` for tuples up to arity 8; previously only pairs and triples were covered.
- `EncodedSessionId`, the embedding of 32-byte strings into a sponge alphabet. 
- Typed session identifiers (`SessionId`), so transcript constructors cannot confuse application tags with already-derived identifiers.
- A typed, single-body API for writing a public-coin argument once and a compiler into a non-interactive argument.
- Consuming terminal-message helpers that return the prover's NARG string and make the verifier's end-of-input check mandatory.
- `VerifierState::into_narg_string`, which consumes the verifier and returns the unread rest of the NARG string, for a proof followed by data the caller parses itself.
- `spongefish-circuit`: `PermutationRelation::compile` validates a relation into a `PermutationInstance`, `PermutationInstance::is_witness_valid` checks a recorded trace against it, linear equations are written with operators on wires (`x * a + y * b + z`), over the Boolean ring for integer units (a weight is a bit mask, an equation an XOR relation), and the relation forwards the allocator's methods.

### Changed

- **Breaking:** `Decoding` is renamed `FromUniform`, with `decode` renamed `from_uniform`, and `NargDeserialize` is renamed `FromNarg`, with `deserialize_from_narg` renamed `from_narg`. The two maps out of a string are named by the string they take: `FromNarg` parses an encoding and may fail, `FromUniform` takes a uniform squeezed string and may not. `NargSerialize` is gone: `Encoding<u8>` is the NARG serialization.
- **Breaking:** `Encoding`, `FromUniform`, and `Codec` are parameterised by the sponge [`Unit`] rather than by a slice type: `Encoding<[U]>` is now `Encoding<U>`, matching `DuplexSpongeInterface::U`. The default `Encoding<u8>` is unchanged for byte sponges; only explicit `Encoding<[u8]>` / `Decoding<[u8]>` spellings need updating.
- **Breaking:** `Transcript` implementations must provide the new `prover_only` hook.
- **Breaking:** `NargReader` and `VerifierState` are no longer `Sync`. The reader stores its state in a `Cell` so verification checks can poison it while preserving `Transcript::check(&self, ...)`.
- **Breaking:** `StdHash` is renamed `DefaultHash`, so it is not mistaken for `std::hash::Hash`.
- **Breaking:** the `VerificationResult<T>` alias is gone; the signatures spell out `Result<T, VerificationError>`.
- **Breaking:** the library aligns with the latest `draft-irtf-cfrg-fiat-shamir`: session identifiers replace `DomainSeparator`, and the SHAKE128 and TurboSHAKE128 suites are the draft's constructions.
- **Breaking:** raw `[u8]` no longer implements `Encoding`, as a bare byte string is not prefix-free. Use `LengthPrefixed`, `str`, a fixed-width array, or the closure codecs.
- **Breaking:** `PrivateRng::mix_entropy` accepts exactly one 32-byte seed.
- **Breaking:** external codecs drivers are removed, we are embracing the orphan rule. We are stopping to implement `Unit` for other libraries, as this caused a proliferation of feature flags, and down the line conflicts with versioning.
- **Breaking:** `rand` is now an optional dependency, and `getrandom`-seeded private RNG are the default for prover randomness.
- **Breaking:** `LengthPrefixed` provides a shorthand for prefix-free encodings, and replaces `Vec<T>`'s `Encoding` implementation.
- **Breaking:** deserialization reads through `&mut NargReader<'_>` instead of `&mut &[u8]`.
- **Breaking:** removed the implicit `Deref` conversion from `VerificationError` to `Result<(), VerificationError>`; construct `Err(VerificationError)` explicitly.
- **Breaking:** `VerifierState` owns its `NargReader`. A rejected prover message poisons the state rather than leaving the cursor where it was: every later read fails, `check_eof` fails, and `into_narg_string` returns an error.
- **Breaking:** A more clean approach at duplex sponge initialization. `DuplexSpongeInit` is for generic units, and `EncodedSessionId` takes care of algebraic sponges. Byte transcripts are unchanged.
- **Breaking:** the instance passed to `ProverState::{new, new_with_seed, from_parts}` and `VerifierState::new` is encoded into the sponge's alphabet (`Encoding<H::U>`) rather than into bytes. Identical for byte sponges.
- **Breaking:** `Permutation` requires `permute_mut` and provides `permute`, rather than the other way round. Every real permutation mixes the state in place, so implementations no longer have to write the by-value map as a wrapper around the in-place one.
- **Breaking:** `spongefish-circuit` is reworked after `sigma-proofs`' `LinearRelation`. `PermutationInstanceBuilder` is `PermutationRelation` and its `snapshot` is a validating `compile` returning `Result`, `LinearEquation` holds a `Sum` of `Weighted` terms, instance and witness fields are private behind slice accessors, the witness is the trace alone, and allocation methods follow `sigma-proofs` names (`allocate_var`, `allocate_vars_with`, `set_var`). Assigning a wire twice with different values is a panic instead of a silent overwrite, and the `hashbrown` and `itertools` dependencies are gone.
- `FromNarg` gained a provided `from_narg_array`, which `[T; N]` delegates to. `u8` overrides it with a single bounds-checked copy, so `[u8; 32]` — the shape carrying compressed points, scalars and digests — is one fixed-size read instead of 32 element parses: 57.7ns to 1.1ns, and 122ns to 4.7ns for a derived struct of two such fields. End to end this makes verification about twice as fast (a 32-round transcript goes from 7.8µs to 4.0µs). The NARG string is byte-identical.
- **Breaking:** prover messages are serialized into the NARG string through the new `ToNarg` trait, the dual of `FromNarg`, instead of directly through `Encoding<u8>`. Its provided method writes the `Encoding<u8>` bytes, so proofs are unchanged; a type can override it to send a wire form that differs from the absorbed form. `Transcript::prover_message` and the `ProverState` prover-message methods require `ToNarg`, and `Codec` (and `#[derive(Codec)]`) include it; `#[derive(ToNarg)]` is new. The `Transcript` verifier now rejects a prover message unless it serializes back to the bytes read, then absorbs its `Encoding`; for canonical codecs this absorbs the same bytes as before. Migration: add `impl ToNarg for T {}` next to each hand-written `Encoding` of a prover message.
- **Breaking:** `spongefish-circuit` moves to Plonky3 0.7 (`p3-baby-bear`, `p3-field`), so `BabyBearUnit` wraps the 0.7 `BabyBear`.
- Updated `ascon` to 0.5, along with routine dependency updates.
- **Breaking (since `v0.8.0`):** `spongefish-pow::PowTranscriptExt::verifier_message_pow` runs its proof of work on the public duplex sponge instead of a seeded strategy, and returns the protected verifier message (any `FromUniform` type, so one step can protect a group of challenges). The signature changes from `verifier_message_pow::<T, S: PowStrategy>(bits: f64)` to `verifier_message_pow::<T>(bits: u32)`. The proof format changes: instead of a 32-byte seed squeeze, an 8-byte little-endian nonce and a separate hash, the prover sends a canonical LEB128 nonce below `2^(bits + 7)` (usually one byte at small difficulties, none at zero) and both parties check `ceil(bits / 8)` squeezed bytes. Proofs made with `v0.8.0` do not verify. Migration: drop the strategy type parameter and pass an integer difficulty; protocols should also update their session tag, since the transcript changes.
- **Breaking (since `v0.8.0`):** `verifier_message_pow` accepts at most 57 bits and panics above that, so the `u64` nonce space keeps `2^7` times the expected work. Standalone seeded strategies accept up to 59 bits. Migration: protocols that grind harder can call `PoWGrinder` with `Blake3PoW` or `KeccakPoW` on a challenge they squeeze themselves.
- **Breaking (since `v0.8.0`):** generic `verifier_message_pow`, including inside `Argument::run`, searches sequentially on the calling thread with the backend's duplex sponge; in `v0.8.0`, with the default `parallel` feature, it searched BLAKE3 or Keccak on all Rayon threads. In one measurement at 20 bits with `DefaultHash` on a 10-core machine, it ran about 35 times fewer trials per second than the `v0.8.0` BLAKE3 search. Migration: callers holding a concrete `ProverState` with a `Send` public duplex sponge can call `verifier_message_pow_parallel`, which writes the same proof.
- **Breaking (since `v0.8.0`):** `PoWGrinder::new` takes a prepared `PowStrategy` instead of a challenge and difficulty, and `grind` returns the nonce as `Option<u64>`, searching sequentially; `grind_parallel` selects parallel search for `Send` strategies. `PowStrategy` no longer requires `Sync`, a seed constructor or `solution`; backends provide `check` and construct themselves, as in `Blake3PoW::new(challenge, bits)`. `convenience::{grind_pow, verify_pow}` take a prepared strategy. Migration: replace `PoWGrinder::<Blake3PoW>::new(challenge, bits)` with `PoWGrinder::new(Blake3PoW::new(challenge, bits))`, and read the nonce directly instead of `PoWSolution::nonce`.
- **Breaking (since `v0.8.0`):** difficulty is a `u32` throughout `spongefish-pow`, and seeded targets use exact integer arithmetic. For integer difficulties of at least 1, seeded strategies accept the same nonces as before.

### Removed

- **Breaking (since `v0.8.0`):** fractional proof-of-work difficulties. Migration: round a computed difficulty up (`bits.ceil() as u32`) to keep at least the intended work; this costs the prover up to twice as many expected trials. Rounding down loses soundness.
- **Breaking (since `v0.8.0`):** `spongefish-pow::PoWSolution`; grinders return the nonce.

### Fixed

- Failed `Transcript::check` calls permanently reject the verifier: subsequent checks, message reads, `check_eof`, and `into_narg_string` fail even if the original error is caught. A caught failure in a nested check also rejects the enclosing check.
- Reader and verifier batch methods reject empty reads after poisoning. Parsers returning `Ok` after a caught nested read failure are rejected at the reader boundary.
- Rejected zero-width elements in `LengthPrefixed`.
- More careful zeroize for the `DuplexSponge` state.
- `prover_message_as` and `prover_message_with` accept a closure that consumes the whole remaining NARG string. The pointer-identity check they used to validate the caller's cursor with rejected an empty remainder, failing verification for an otherwise valid proof.
- `spongefish-derive`: the generated code is usable from `no_std` crates, and the `FromUniform` derive now single-sources the field width. Malformed input is reported as a `compile_error!` on the offending span instead of aborting the macro with a panic.
- `spongefish-pow`: guarded the difficulty parameter and the endianness of the ground nonce. Dropped an unused dependency.

### Security

- Declared a minimum supported Rust version (1.88; `spongefish-circuit` requires 1.93 for its Plonky3 dependencies) and added supply-chain (`cargo-deny`), semver, and locked-dependency checks to CI.
- Added `SECURITY.md` with a private vulnerability disclosure process.
- Forbade `unsafe` code workspace-wide.

[Unreleased]: https://github.com/arkworks-rs/spongefish/compare/v0.7.4...HEAD
