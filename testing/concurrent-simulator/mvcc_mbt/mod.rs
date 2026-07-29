//! MVCC model-based testing.
//!
//! Quint generates random-but-legal MVCC programs; whopper replays each
//! program many times under different deterministic actor/yield schedules and
//! checks the engine against the model's expected state after every replay.
//! The Quint trace decides *what* operations run; whopper's seeds decide
//! *when* they interleave.
//!
//! Pipeline, one file per stage:
//! - `itf`: decode a Quint ITF trace into an `MbtProgram`.
//! - `runtime`: turn the program into per-actor operation queues that whopper
//!   drains, and validate every result against the model.
//! - `run`: sweep the actor-schedule x yield-plan seed grid for one program,
//!   fingerprint failures, and write replay artifacts.

mod itf;
mod run;
mod runtime;

pub use itf::{AbstractState, MbtProgram, SemanticCommand, load_itf};
pub(crate) use run::run_itf_with_artifact_dir;
pub use run::{
    FailureFingerprint, MbtFailureSummary, MbtReplaySeeds, MbtReport, MbtRunConfig, MbtRunOutcome,
    run_itf,
};
pub use runtime::{MbtEvent, MbtEventKind};

use crate::operations::Operation;

/// The model's fixed universe: two logical tables.
pub(crate) const TABLE_IDS: [u8; 2] = [0, 1];

pub(crate) fn table_name(table: u8) -> String {
    format!("mbt_t{table}")
}

pub(crate) fn execute(sql: String) -> Operation {
    Operation::Execute { sql }
}
