#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(target_endian = "big")]
compile_error!(
    r#"
This crate doesn't support big-endian targets.
"#
);

#[cfg(feature = "blake3")]
pub mod blake3;
#[cfg(feature = "keccak")]
pub mod keccak;
mod protocol;

#[cfg(feature = "parallel")]
pub use protocol::verifier_message_pow_parallel;
pub use protocol::PowTranscriptExt;

/// Search a prepared proof-of-work strategy for its least accepted nonce.
///
/// Construction belongs to each strategy; the grinder only selects execution.
/// `grind` is always sequential, even with the `parallel` feature enabled.
///
/// ```
/// # #[cfg(feature = "blake3")]
/// # {
/// use spongefish_pow::{blake3::Blake3PoW, PoWGrinder};
/// let mut grinder = PoWGrinder::new(Blake3PoW::new([7; 32], 8));
/// let nonce = grinder.grind().unwrap();
/// assert!(grinder.verify(nonce));
/// # }
/// ```
pub struct PoWGrinder<S: PowStrategy> {
    strategy: S,
}

impl<S: PowStrategy> PoWGrinder<S> {
    /// Construct a grinder from a prepared strategy.
    pub const fn new(strategy: S) -> Self {
        Self { strategy }
    }

    /// Find the least accepted nonce sequentially, or `None` on exhaustion.
    pub fn grind(&mut self) -> Option<u64> {
        self.strategy.solve()
    }

    /// Find the same least nonce using owned strategy clones on Rayon workers.
    ///
    /// Only the strategy is transferred; no `Sync` bound is required. Clones
    /// are made on the calling thread before dispatch.
    #[cfg(feature = "parallel")]
    pub fn grind_parallel(&mut self) -> Option<u64>
    where
        S: Send,
    {
        self.strategy.solve_parallel()
    }

    /// Verify the nonce is in range and satisfies the prepared strategy.
    #[must_use = "unchecked proof of work verification"]
    pub fn verify(&mut self, nonce: u64) -> bool {
        nonce <= self.strategy.last_nonce() && self.strategy.check(nonce)
    }
}

/// Convenience functions accepting the same prepared strategies as [`PoWGrinder`].
pub mod convenience {
    use crate::{PoWGrinder, PowStrategy};

    /// Find the least accepted nonce sequentially.
    pub fn grind_pow(strategy: impl PowStrategy) -> Option<u64> {
        PoWGrinder::new(strategy).grind()
    }

    /// Check a nonce against a prepared strategy, including its range bound.
    #[must_use = "unchecked proof of work verification"]
    pub fn verify_pow(strategy: impl PowStrategy, nonce: u64) -> bool {
        PoWGrinder::new(strategy).verify(nonce)
    }
}

/// A prepared nonce predicate, independent of its seed or duplex sponge evaluator.
///
/// `check` and every clone must describe the same stable predicate. Mutable
/// hash scratch space is allowed, but acceptance must not depend on query order.
/// Override the search methods to provide optimized implementations, preserving
/// the least-nonce result and [`Self::last_nonce`] bound.
pub trait PowStrategy: Clone {
    /// Whether this nonce satisfies the prepared problem.
    #[must_use = "unchecked proof of work verification"]
    fn check(&mut self, nonce: u64) -> bool;

    /// The inclusive end of the nonce search space, starting at zero.
    fn last_nonce(&self) -> u64 {
        u64::MAX
    }

    /// Find the least accepted nonce sequentially, or `None` on exhaustion.
    fn solve(&mut self) -> Option<u64> {
        (0..=self.last_nonce()).find(|&nonce| self.check(nonce))
    }

    /// Find the same least nonce using independent owned clones.
    #[cfg(feature = "parallel")]
    fn solve_parallel(&mut self) -> Option<u64>
    where
        Self: Send,
    {
        search_parallel(self, 1, |strategy, nonce| {
            strategy.check(nonce).then_some(nonce)
        })
    }
}

// Each checker returns the least accepted nonce in a positive-width batch.
#[cfg(feature = "parallel")]
fn search_parallel<S, F>(strategy: &mut S, width: u64, check_batch: F) -> Option<u64>
where
    S: PowStrategy + Send,
    F: Fn(&mut S, u64) -> Option<u64> + Sync,
{
    use std::sync::atomic::{AtomicU64, Ordering};

    use rayon::prelude::*;

    let least = AtomicU64::new(u64::MAX);
    let jobs = rayon::current_num_threads();
    let limit = strategy.last_nonce();
    let strategies: Vec<_> = (0..jobs).map(|_| strategy.clone()).collect();
    strategies
        .into_par_iter()
        .enumerate()
        .for_each(|(index, mut strategy)| {
            // Batch indices avoid overflowing width * jobs or the starting nonce.
            for batch in (index as u64..=limit / width).step_by(jobs) {
                let start = batch * width;
                // MAX doubles as a sentinel and is checked after joining.
                if start >= least.load(Ordering::Relaxed) {
                    break;
                }
                if let Some(nonce) = check_batch(&mut strategy, start).filter(|&n| n <= limit) {
                    least.fetch_min(nonce, Ordering::Relaxed);
                    break;
                }
            }
        });
    let nonce = least.into_inner();
    if nonce != u64::MAX || (limit == u64::MAX && strategy.check(nonce)) {
        Some(nonce)
    } else {
        None
    }
}

// Inclusive target avoids representing 2^64 at zero difficulty.
#[cfg(any(feature = "blake3", feature = "keccak"))]
pub(crate) const fn difficulty_target(bits: u32) -> u64 {
    assert!(bits < 60, "bits must be smaller than 60");
    u64::MAX >> bits
}
