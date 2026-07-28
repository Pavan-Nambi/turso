use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};
use serde::Serialize;

use crate::mvcc_mbt::{
    FailureFingerprint, MbtReplaySeeds, MbtRunConfig, load_itf, run_itf_with_artifact_dir,
};

#[derive(Debug, Clone)]
pub struct MbtCorpusConfig {
    pub corpus_dir: PathBuf,
    pub report_dir: PathBuf,
    pub trace_count: usize,
    pub run: MbtRunConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorpusTrace {
    pub corpus_index: usize,
    pub program_id: u64,
    pub model_trace: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorpusFailure {
    pub fingerprint: FailureFingerprint,
    pub occurrences: usize,
    pub first_model_trace: PathBuf,
    pub first_seeds: MbtReplaySeeds,
    pub artifact_path: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct MbtCorpusReport {
    pub generated_traces: usize,
    pub distinct_programs: usize,
    pub actor_schedules: usize,
    pub yield_plans: usize,
    pub replay_seed_roots: MbtReplaySeeds,
    pub traces: Vec<CorpusTrace>,
    pub schedules_run: usize,
    pub schedules_passed: usize,
    pub schedules_failed: usize,
    pub schedules_with_writer_checkpoint_overlap: usize,
    pub unique_failures: usize,
    pub failures: Vec<CorpusFailure>,
}

impl MbtCorpusReport {
    pub fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }
}

#[derive(Debug)]
struct Candidate {
    corpus_index: usize,
    path: PathBuf,
    program_id: u64,
}

pub fn run_corpus(config: MbtCorpusConfig) -> anyhow::Result<MbtCorpusReport> {
    ensure!(config.trace_count > 0, "trace count must be positive");
    let candidates = load_candidates(&config.corpus_dir, config.trace_count)?;
    std::fs::create_dir_all(&config.report_dir).with_context(|| {
        format!(
            "failed to create MVCC MBT report directory {}",
            config.report_dir.display()
        )
    })?;

    let mut schedules_run = 0;
    let mut schedules_passed = 0;
    let mut schedules_failed = 0;
    let mut schedules_with_writer_checkpoint_overlap = 0;
    let mut failures = BTreeMap::<FailureFingerprint, CorpusFailure>::new();
    let mut traces = Vec::with_capacity(candidates.len());

    for candidate in candidates {
        let run = MbtRunConfig {
            first_seeds: config.run.first_seeds.for_program(candidate.program_id),
            ..config.run
        };
        let outcome = run_itf_with_artifact_dir(&candidate.path, run, Some(&config.report_dir))?;
        schedules_run += outcome.report.schedules_run;
        schedules_passed += outcome.report.schedules_passed;
        schedules_failed += outcome.report.schedules_failed;
        schedules_with_writer_checkpoint_overlap +=
            outcome.report.schedules_with_writer_checkpoint_overlap;
        for failure in outcome.failures {
            if let Some(existing) = failures.get_mut(&failure.fingerprint) {
                existing.occurrences += failure.occurrences;
            } else {
                failures.insert(
                    failure.fingerprint.clone(),
                    CorpusFailure {
                        fingerprint: failure.fingerprint,
                        occurrences: failure.occurrences,
                        first_model_trace: candidate.path.clone(),
                        first_seeds: failure.first_seeds,
                        artifact_path: failure.artifact_path,
                    },
                );
            }
        }
        traces.push(CorpusTrace {
            corpus_index: candidate.corpus_index,
            program_id: candidate.program_id,
            model_trace: candidate.path,
        });
    }

    let report = MbtCorpusReport {
        generated_traces: config.trace_count,
        distinct_programs: traces.len(),
        actor_schedules: config.run.actor_schedules,
        yield_plans: config.run.yield_plans,
        replay_seed_roots: config.run.first_seeds,
        traces,
        schedules_run,
        schedules_passed,
        schedules_failed,
        schedules_with_writer_checkpoint_overlap,
        unique_failures: failures.len(),
        failures: failures.into_values().collect(),
    };
    write_report(&config.report_dir, &report)?;
    Ok(report)
}

fn load_candidates(corpus_dir: &Path, trace_count: usize) -> anyhow::Result<Vec<Candidate>> {
    let mut distinct = BTreeMap::new();
    for corpus_index in 0..trace_count {
        let path = corpus_dir.join(format!("trace_{corpus_index}.itf.json"));
        ensure!(path.is_file(), "missing generated trace {}", path.display());
        let program = load_itf(&path)?;
        let canonical = program.canonical_json()?;
        let program_id = stable_program_id(&canonical);
        distinct.entry(canonical).or_insert(Candidate {
            corpus_index,
            path,
            program_id,
        });
    }
    ensure!(
        !distinct.is_empty(),
        "generated corpus contains no complete semantic programs"
    );
    Ok(distinct.into_values().collect())
}

fn stable_program_id(canonical_program: &str) -> u64 {
    canonical_program
        .as_bytes()
        .iter()
        .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
}

fn write_report(report_dir: &Path, report: &MbtCorpusReport) -> anyhow::Result<()> {
    let path = report_dir.join("campaign.report.json");
    std::fs::write(&path, serde_json::to_vec_pretty(report)?)
        .with_context(|| format!("failed to write MVCC MBT report {}", path.display()))
}
