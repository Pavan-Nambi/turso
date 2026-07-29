//! Sweep the replay seed grid for one program, fingerprint failures, and
//! write replay artifacts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, ensure};
use serde::Serialize;

use super::itf::{MbtProgram, load_itf};
use super::runtime::{FIBER_COUNT, MbtEvent, ProgramProperty, ProgramRuntime, ProgramWorkload};
use crate::{SchemaBias, Whopper, WhopperOpts};

const MAX_SIMULATOR_STEPS: usize = 200_000;
const MAX_FIBER_QUANTA: [usize; 4] = [1, 4, 16, 64];

// Seed scheme: one recorded base seed deterministically reproduces an entire
// campaign. `from_base` splits the base into four domains by xor with an
// ASCII tag (0x656e_7669_726f_6e6d is "environm", and so on); `for_program`
// re-derives all four per program id so distinct programs get distinct
// schedules; the replay grid then varies only the actor and yield dimensions,
// leaving offset zero equal to the first seeds so a single-trace replay with
// recorded seeds is exactly grid point zero. `mix_seed` is the splitmix64
// finalizer.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MbtReplaySeeds {
    pub environment: u64,
    pub actor_schedule: u64,
    pub yield_plan: u64,
    pub io: u64,
}

impl MbtReplaySeeds {
    pub fn from_base(base: u64) -> Self {
        Self {
            environment: base ^ 0x656e_7669_726f_6e6d,
            actor_schedule: base,
            yield_plan: base ^ 0x7969_656c_645f_6d62,
            io: base ^ 0x696f_5f6d_6274_5f73,
        }
    }

    fn with_search_point(self, actor_schedule: u64, yield_plan: u64) -> Self {
        Self {
            actor_schedule,
            yield_plan,
            ..self
        }
    }

    pub fn for_program(self, program_id: u64) -> Self {
        Self {
            environment: derive_seed(self.environment, program_id, 0x656e_7669_726f_6e6d),
            actor_schedule: derive_seed(self.actor_schedule, program_id, 0x6163_746f_725f_6d62),
            yield_plan: derive_seed(self.yield_plan, program_id, 0x7969_656c_645f_6d62),
            io: derive_seed(self.io, program_id, 0x696f_5f6d_6274_5f73),
        }
    }
}

fn mix_seed(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn derive_seed(base: u64, discriminator: u64, domain: u64) -> u64 {
    mix_seed(base ^ mix_seed(discriminator ^ domain))
}

fn search_dimension_seed(base: u64, offset: usize, domain: u64) -> u64 {
    if offset == 0 {
        base
    } else {
        derive_seed(base, offset as u64, domain)
    }
}

fn replay_seed_grid(config: MbtRunConfig) -> impl Iterator<Item = MbtReplaySeeds> {
    (0..config.yield_plans).flat_map(move |yield_offset| {
        let yield_seed = search_dimension_seed(
            config.first_seeds.yield_plan,
            yield_offset,
            0x7969_656c_645f_6772,
        );
        (0..config.actor_schedules).map(move |actor_offset| {
            let actor_seed = search_dimension_seed(
                config.first_seeds.actor_schedule,
                actor_offset,
                0x6163_746f_725f_6772,
            );
            config.first_seeds.with_search_point(actor_seed, yield_seed)
        })
    })
}

fn max_fiber_quantum(actor_schedule_seed: u64) -> usize {
    MAX_FIBER_QUANTA[(actor_schedule_seed % MAX_FIBER_QUANTA.len() as u64) as usize]
}

#[derive(Debug, Clone, Copy)]
pub struct MbtRunConfig {
    pub first_seeds: MbtReplaySeeds,
    pub actor_schedules: usize,
    pub yield_plans: usize,
    pub fail_fast: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MbtReport {
    pub command_count: usize,
    pub actor_schedules: usize,
    pub yield_plans: usize,
    pub schedules_run: usize,
    pub schedules_passed: usize,
    pub schedules_failed: usize,
    pub schedules_with_writer_checkpoint_overlap: usize,
    pub unique_failures: usize,
    pub first_seeds: MbtReplaySeeds,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FailureFingerprint {
    pub actor: String,
    pub action: String,
    pub error_class: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MbtFailureSummary {
    pub fingerprint: FailureFingerprint,
    pub occurrences: usize,
    pub first_seeds: MbtReplaySeeds,
    pub artifact_path: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct MbtRunOutcome {
    pub report: MbtReport,
    pub failures: Vec<MbtFailureSummary>,
}

impl MbtRunOutcome {
    pub fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }
}

fn run_program_attempt(
    program: &MbtProgram,
    seeds: MbtReplaySeeds,
) -> (anyhow::Result<usize>, Vec<MbtEvent>, bool, usize) {
    let max_fiber_quantum = max_fiber_quantum(seeds.actor_schedule);
    let runtime = ProgramRuntime::new(program);
    let result = (|| {
        let schema_bias = SchemaBias {
            num_tables_range: 0..=0,
            num_columns_range: 2..=2,
            unique_col_prob: 0.0,
            ..SchemaBias::default()
        };
        let mut opts = WhopperOpts::default()
            .with_seed(seeds.environment)
            .with_fiber_schedule_seed(seeds.actor_schedule)
            .with_yield_seed(seeds.yield_plan)
            .with_io_seed(seeds.io)
            .with_strict_operation_init_errors(true)
            .with_max_connections(FIBER_COUNT)
            .with_max_steps(MAX_SIMULATOR_STEPS)
            .with_enable_mvcc(true)
            .with_experimental_mvcc_passive_checkpoint(true)
            .with_randomized_fiber_quantum(max_fiber_quantum)
            .with_workloads(vec![(
                1,
                Box::new(ProgramWorkload {
                    runtime: runtime.clone(),
                }),
            )])
            .with_properties(vec![Box::new(ProgramProperty {
                runtime: runtime.clone(),
            })]);
        opts.schema_bias = schema_bias;
        opts.disable_mvcc_auto_checkpoint = true;

        let mut whopper = Whopper::new(opts)?;
        while !whopper.is_done() && !runtime.is_complete() {
            whopper.step().with_context(|| {
                format!(
                    "MVCC MBT replay failed at Whopper step {} with seeds {seeds:?}",
                    whopper.current_step
                )
            })?;
        }
        whopper.finalize_properties()?;
        Ok(whopper.current_step)
    })();
    (
        result,
        runtime.history(),
        runtime.writer_checkpoint_overlap(),
        max_fiber_quantum,
    )
}

pub fn run_itf(path: impl AsRef<Path>, config: MbtRunConfig) -> anyhow::Result<MbtRunOutcome> {
    run_itf_with_artifact_dir(path, config, None)
}

pub(crate) fn run_itf_with_artifact_dir(
    path: impl AsRef<Path>,
    config: MbtRunConfig,
    artifact_dir: Option<&Path>,
) -> anyhow::Result<MbtRunOutcome> {
    ensure!(
        config.actor_schedules > 0,
        "actor schedule count must be positive"
    );
    ensure!(config.yield_plans > 0, "yield-plan count must be positive");
    config
        .actor_schedules
        .checked_mul(config.yield_plans)
        .ok_or_else(|| anyhow!("replay grid size overflow"))?;

    let path = path.as_ref();
    let program = load_itf(path)?;
    let mut schedules_run = 0;
    let mut schedules_passed = 0;
    let mut schedules_failed = 0;
    let mut schedules_with_writer_checkpoint_overlap = 0;
    let mut failures = BTreeMap::<FailureFingerprint, MbtFailureSummary>::new();

    for seeds in replay_seed_grid(config) {
        let (result, history, overlapped, max_fiber_quantum) = run_program_attempt(&program, seeds);
        schedules_run += 1;
        schedules_with_writer_checkpoint_overlap += usize::from(overlapped);
        if let Err(error) = result {
            schedules_failed += 1;
            let fingerprint = failure_fingerprint(&error, &history);
            if let Some(failure) = failures.get_mut(&fingerprint) {
                failure.occurrences += 1;
            } else {
                let artifact_path = FailureArtifact {
                    model_trace: path.display().to_string(),
                    seeds,
                    max_fiber_quantum,
                    program: &program,
                    history: &history,
                    fingerprint: &fingerprint,
                    error: format!("{error:#}"),
                }
                .write(path, artifact_dir)?;
                failures.insert(
                    fingerprint.clone(),
                    MbtFailureSummary {
                        fingerprint,
                        occurrences: 1,
                        first_seeds: seeds,
                        artifact_path,
                    },
                );
            }
            if config.fail_fast {
                break;
            }
        } else {
            schedules_passed += 1;
        }
    }

    Ok(MbtRunOutcome {
        report: MbtReport {
            command_count: program.command_count(),
            actor_schedules: config.actor_schedules,
            yield_plans: config.yield_plans,
            schedules_run,
            schedules_passed,
            schedules_failed,
            schedules_with_writer_checkpoint_overlap,
            unique_failures: failures.len(),
            first_seeds: config.first_seeds,
        },
        failures: failures.into_values().collect(),
    })
}

fn failure_fingerprint(error: &anyhow::Error, history: &[MbtEvent]) -> FailureFingerprint {
    let failed_event = history
        .iter()
        .find(|event| event.oracle_passed == Some(false));
    let root_error = error
        .chain()
        .last()
        .map(ToString::to_string)
        .unwrap_or_else(|| error.to_string());
    FailureFingerprint {
        actor: failed_event
            .map(|event| event.actor.clone())
            .unwrap_or_else(|| "simulator".to_owned()),
        action: normalize_digits_after_marker(
            failed_event
                .map(|event| event.label.as_str())
                .unwrap_or("runtime"),
            "mbt_t",
        ),
        error_class: normalize_error_class(&root_error),
    }
}

fn normalize_error_class(message: &str) -> String {
    let normalized = message.to_lowercase();
    let normalized = normalize_digits_after_marker(&normalized, "page type: ");
    let normalized = normalize_digits_after_marker(&normalized, "page ");
    normalize_digits_after_marker(&normalized, "mbt_t")
}

fn normalize_digits_after_marker(message: &str, marker: &str) -> String {
    let mut normalized = String::with_capacity(message.len());
    let mut remainder = message;
    while let Some(marker_start) = remainder.find(marker) {
        let digits_start = marker_start + marker.len();
        normalized.push_str(&remainder[..digits_start]);
        remainder = &remainder[digits_start..];
        let digits_end = remainder
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(remainder.len());
        if digits_end == 0 {
            if remainder.is_empty() {
                break;
            }
            let character_len = remainder
                .chars()
                .next()
                .map(char::len_utf8)
                .expect("non-empty text has a first character");
            normalized.push_str(&remainder[..character_len]);
            remainder = &remainder[character_len..];
            continue;
        }
        normalized.push('#');
        remainder = &remainder[digits_end..];
    }
    normalized.push_str(remainder);
    normalized
}

#[derive(Serialize)]
struct FailureArtifact<'a> {
    model_trace: String,
    seeds: MbtReplaySeeds,
    max_fiber_quantum: usize,
    program: &'a MbtProgram,
    history: &'a [MbtEvent],
    fingerprint: &'a FailureFingerprint,
    error: String,
}

impl FailureArtifact<'_> {
    fn write(self, model_trace: &Path, artifact_dir: Option<&Path>) -> anyhow::Result<PathBuf> {
        let trace_name = model_trace
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("mvcc_mbt_trace");
        let artifact_name = format!(
            "{trace_name}.environment_seed_{}.actor_seed_{}.yield_seed_{}.io_seed_{}.failure.json",
            self.seeds.environment, self.seeds.actor_schedule, self.seeds.yield_plan, self.seeds.io
        );
        let artifact_path = artifact_dir
            .map(|directory| directory.join(&artifact_name))
            .unwrap_or_else(|| model_trace.with_file_name(artifact_name));
        let bytes = serde_json::to_vec_pretty(&self)?;
        std::fs::write(&artifact_path, bytes).with_context(|| {
            format!(
                "failed to write MVCC MBT failure artifact {}",
                artifact_path.display()
            )
        })?;
        Ok(artifact_path)
    }
}
