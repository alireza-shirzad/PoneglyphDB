pub mod chips;
pub mod circuits;
// pub mod gadgets;
pub mod data;
pub mod is_zero;
pub mod sql;

/// External benchmark entry points.
///
/// Each `run_q*` function builds the corresponding circuit at the requested
/// Halo2 degree `k` and runs setup + prove + verify, returning a
/// [`BenchResult`] with timings and proof size. Mapping:
///
/// | k  | lineitem rows |
/// |----|---------------|
/// | 16 | 60K           |
/// | 17 | 120K          |
/// | 18 | 240K          |
///
/// Q3 typically uses `k - 1` (one smaller circuit) for the same dataset size.
/// Callers are responsible for picking the right `k` per query.
pub mod poneglyph_bench {
    pub use crate::circuits::utils::{setup_params, BenchResult};
    pub use crate::sql::micro_kzg::{run as run_micro, supported as micro_supported, MicroResult};
    pub use crate::sql::q18_final_kzg::run as run_q18;
    pub use crate::sql::q1_final_kzg::run as run_q1;
    pub use crate::sql::q3_final_kzg::run as run_q3;
    pub use crate::sql::q5_final_kzg::run as run_q5;
    pub use crate::sql::q8_final_kzg::run as run_q8;
    pub use crate::sql::q9_final_kzg::run as run_q9;
}
