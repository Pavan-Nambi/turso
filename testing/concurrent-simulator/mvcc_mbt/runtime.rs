//! Replay a decoded program through whopper's workload/property hooks.
//!
//! The program becomes a sequence of epochs, each holding one operation queue
//! per fiber (writer, reader, checkpoint, observer). Whopper asks
//! `ProgramWorkload::generate` for the next operation — the trace answers, the
//! RNG is ignored — and `ProgramProperty` validates every result against the
//! model's expectation. Epochs are barriers: the next epoch starts only when
//! all queues of the current one have drained.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, ensure};
use rand_chacha::ChaCha8Rng;
use serde::Serialize;
use turso_core::Value;

use super::itf::{AbstractState, MbtProgram, SemanticCommand};
use super::{TABLE_IDS, execute, table_name};
use crate::TxMode;
use crate::operations::{OpResult, Operation};
use crate::properties::Property;
use crate::workloads::{Workload, WorkloadContext};

const WRITER_FIBER: usize = 0;
const READER_FIBER: usize = 1;
const CHECKPOINT_FIBER: usize = 2;
const OBSERVER_FIBER: usize = 3;
pub(crate) const FIBER_COUNT: usize = 4;
/// The writer's BEGIN plus its first mutation run in their own epoch so the
/// dirty-read observer is guaranteed to see an open, uncommitted writer.
const DIRTY_READ_SPLIT_INDEX: usize = 2;

#[derive(Debug, Clone)]
enum ExpectedResult {
    Success,
    Checkpoint { must_complete: bool },
    SchemaPresence(bool),
    Rows(Vec<(i64, i64)>),
    Integrity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ObservationPoint {
    ReaderBeforeWriter,
    UncommittedObserver,
    ReaderAfterWriter,
    FinalBeforeCheckpoint,
    FinalAfterCheckpoint,
}

impl ObservationPoint {
    fn label(self) -> &'static str {
        match self {
            Self::ReaderBeforeWriter => "reader snapshot before writer",
            Self::UncommittedObserver => "fresh observer while writer is uncommitted",
            Self::ReaderAfterWriter => "reader snapshot after writer",
            Self::FinalBeforeCheckpoint => "fresh observer before follow-up checkpoint",
            Self::FinalAfterCheckpoint => "fresh observer after follow-up checkpoint",
        }
    }
}

#[derive(Debug, Clone)]
struct RuntimeAction {
    label: String,
    operation: Operation,
    expected: ExpectedResult,
}

impl RuntimeAction {
    fn semantic(command: &SemanticCommand) -> Self {
        Self {
            label: command.label(),
            operation: command.operation(),
            expected: if matches!(command, SemanticCommand::PassiveCheckpoint) {
                ExpectedResult::Checkpoint {
                    must_complete: false,
                }
            } else {
                ExpectedResult::Success
            },
        }
    }

    fn checkpoint_must_complete(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            operation: SemanticCommand::PassiveCheckpoint.operation(),
            expected: ExpectedResult::Checkpoint {
                must_complete: true,
            },
        }
    }

    fn success(label: impl Into<String>, operation: Operation) -> Self {
        Self {
            label: label.into(),
            operation,
            expected: ExpectedResult::Success,
        }
    }
}

#[derive(Debug)]
struct RuntimeEpoch {
    queues: Vec<VecDeque<RuntimeAction>>,
}

impl RuntimeEpoch {
    fn new() -> Self {
        Self {
            queues: (0..FIBER_COUNT).map(|_| VecDeque::new()).collect(),
        }
    }

    fn is_empty(&self) -> bool {
        self.queues.iter().all(VecDeque::is_empty)
    }
}

#[derive(Debug)]
struct RuntimeState {
    epochs: Vec<RuntimeEpoch>,
    epoch: usize,
    in_flight: HashMap<usize, RuntimeAction>,
    history: Vec<MbtEvent>,
    writer_checkpoint_overlap: bool,
}

impl RuntimeState {
    fn advance_empty_epochs(&mut self) {
        while self.in_flight.is_empty()
            && self
                .epochs
                .get(self.epoch)
                .is_some_and(RuntimeEpoch::is_empty)
        {
            self.epoch += 1;
        }
    }

    fn is_complete(&mut self) -> bool {
        self.advance_empty_epochs();
        self.epoch == self.epochs.len() && self.in_flight.is_empty()
    }
}

#[derive(Debug)]
pub(crate) struct ProgramRuntime {
    state: Mutex<RuntimeState>,
}

impl ProgramRuntime {
    pub(crate) fn new(program: &MbtProgram) -> Arc<Self> {
        let mut setup = RuntimeEpoch::new();
        for command in &program.setup {
            let action = if matches!(command, SemanticCommand::PassiveCheckpoint) {
                RuntimeAction::checkpoint_must_complete("setup passive checkpoint")
            } else {
                RuntimeAction::semantic(command)
            };
            setup.queues[WRITER_FIBER].push_back(action);
        }

        let mut open_reader = RuntimeEpoch::new();
        if program.reader_pinned {
            open_reader.queues[READER_FIBER].push_back(RuntimeAction::success(
                "begin reader snapshot",
                Operation::Begin {
                    mode: TxMode::Concurrent,
                },
            ));
            append_state_observations(
                &mut open_reader.queues[READER_FIBER],
                &program.reader_snapshot,
                ObservationPoint::ReaderBeforeWriter,
            );
        }

        let mut open_writer = RuntimeEpoch::new();
        open_writer.queues[WRITER_FIBER].extend(
            program.writer[..DIRTY_READ_SPLIT_INDEX]
                .iter()
                .map(RuntimeAction::semantic),
        );

        let mut reject_dirty_read = RuntimeEpoch::new();
        append_state_observations(
            &mut reject_dirty_read.queues[OBSERVER_FIBER],
            &program.reader_snapshot,
            ObservationPoint::UncommittedObserver,
        );

        let mut concurrent = RuntimeEpoch::new();
        concurrent.queues[WRITER_FIBER].extend(
            program.writer[DIRTY_READ_SPLIT_INDEX..]
                .iter()
                .map(RuntimeAction::semantic),
        );
        concurrent.queues[CHECKPOINT_FIBER]
            .extend(program.checkpoints.iter().map(RuntimeAction::semantic));

        let mut close_reader = RuntimeEpoch::new();
        if program.reader_pinned {
            append_state_observations(
                &mut close_reader.queues[READER_FIBER],
                &program.reader_snapshot,
                ObservationPoint::ReaderAfterWriter,
            );
            close_reader.queues[READER_FIBER].push_back(RuntimeAction::success(
                "commit reader snapshot",
                Operation::Commit,
            ));
        }

        let mut observe = RuntimeEpoch::new();
        append_state_observations(
            &mut observe.queues[OBSERVER_FIBER],
            &program.expected,
            ObservationPoint::FinalBeforeCheckpoint,
        );
        append_integrity_observation(
            &mut observe.queues[OBSERVER_FIBER],
            ObservationPoint::FinalBeforeCheckpoint,
        );
        observe.queues[OBSERVER_FIBER].push_back(RuntimeAction::checkpoint_must_complete(
            "quiescent follow-up passive checkpoint",
        ));
        append_state_observations(
            &mut observe.queues[OBSERVER_FIBER],
            &program.expected,
            ObservationPoint::FinalAfterCheckpoint,
        );
        append_integrity_observation(
            &mut observe.queues[OBSERVER_FIBER],
            ObservationPoint::FinalAfterCheckpoint,
        );

        Arc::new(Self {
            state: Mutex::new(RuntimeState {
                epochs: vec![
                    setup,
                    open_reader,
                    open_writer,
                    reject_dirty_read,
                    concurrent,
                    close_reader,
                    observe,
                ],
                epoch: 0,
                in_flight: HashMap::new(),
                history: Vec::new(),
                writer_checkpoint_overlap: false,
            }),
        })
    }

    fn next_operation(&self, fiber_id: usize) -> Option<Operation> {
        let mut state = self.state.lock().unwrap();
        state.advance_empty_epochs();
        if state.in_flight.contains_key(&fiber_id) {
            return None;
        }
        let epoch = state.epoch;
        let action = state.epochs.get_mut(epoch)?.queues[fiber_id].pop_front()?;
        let operation = action.operation.clone();
        state.in_flight.insert(fiber_id, action);
        Some(operation)
    }

    fn start_operation(&self, step: usize, fiber_id: usize) -> anyhow::Result<()> {
        let mut state = self.state.lock().unwrap();
        let label = state
            .in_flight
            .get(&fiber_id)
            .ok_or_else(|| anyhow!("fiber {fiber_id} started an untracked MBT operation"))?
            .label
            .clone();
        state.history.push(MbtEvent {
            step,
            actor: actor_name(fiber_id).to_owned(),
            event: MbtEventKind::Invoke,
            label,
            oracle_passed: None,
        });
        state.writer_checkpoint_overlap |= state.in_flight.contains_key(&WRITER_FIBER)
            && state.in_flight.contains_key(&CHECKPOINT_FIBER);
        Ok(())
    }

    fn finish_operation(
        &self,
        step: usize,
        fiber_id: usize,
        result: &OpResult,
    ) -> anyhow::Result<()> {
        let mut state = self.state.lock().unwrap();
        let action = state
            .in_flight
            .remove(&fiber_id)
            .ok_or_else(|| anyhow!("fiber {fiber_id} finished an untracked MBT operation"))?;
        let validation = validate_result(&action, result);
        state.history.push(MbtEvent {
            step,
            actor: actor_name(fiber_id).to_owned(),
            event: MbtEventKind::Return,
            label: action.label,
            oracle_passed: Some(validation.is_ok()),
        });
        validation
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.state.lock().unwrap().is_complete()
    }

    fn finalize(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.is_complete() {
            return Ok(());
        }
        let pending = state
            .epochs
            .iter()
            .skip(state.epoch)
            .flat_map(|epoch| epoch.queues.iter())
            .flatten()
            .map(|action| action.label.as_str())
            .collect::<Vec<_>>();
        bail!(
            "MBT replay ended before quiescence: epoch={}, in_flight={:?}, pending={pending:?}",
            state.epoch,
            state.in_flight.keys().collect::<Vec<_>>()
        )
    }

    pub(crate) fn history(&self) -> Vec<MbtEvent> {
        self.state.lock().unwrap().history.clone()
    }

    pub(crate) fn writer_checkpoint_overlap(&self) -> bool {
        self.state.lock().unwrap().writer_checkpoint_overlap
    }
}

fn actor_name(fiber_id: usize) -> &'static str {
    match fiber_id {
        WRITER_FIBER => "writer",
        READER_FIBER => "reader",
        CHECKPOINT_FIBER => "checkpoint",
        OBSERVER_FIBER => "observer",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MbtEventKind {
    Invoke,
    Return,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MbtEvent {
    step: usize,
    pub(crate) actor: String,
    event: MbtEventKind,
    pub(crate) label: String,
    pub(crate) oracle_passed: Option<bool>,
}

fn append_state_observations(
    queue: &mut VecDeque<RuntimeAction>,
    expected: &AbstractState,
    point: ObservationPoint,
) {
    for table in TABLE_IDS {
        let name = table_name(table);
        let expected_rows = expected.tables.get(&table);
        queue.push_back(RuntimeAction {
            label: format!("{}: observe schema {name}", point.label()),
            operation: execute(format!(
                "SELECT count(*) FROM sqlite_schema \
                 WHERE type = 'table' AND name = '{name}'"
            )),
            expected: ExpectedResult::SchemaPresence(expected_rows.is_some()),
        });
        if let Some(expected_rows) = expected_rows {
            queue.push_back(RuntimeAction {
                label: format!("{}: observe rows {name}", point.label()),
                operation: execute(format!("SELECT k, v FROM {name} ORDER BY k")),
                expected: ExpectedResult::Rows(
                    expected_rows
                        .iter()
                        .map(|(key, value)| (*key, *value))
                        .collect(),
                ),
            });
        }
    }
}

fn append_integrity_observation(queue: &mut VecDeque<RuntimeAction>, point: ObservationPoint) {
    queue.push_back(RuntimeAction {
        label: format!("{}: observe integrity", point.label()),
        operation: Operation::IntegrityCheck,
        expected: ExpectedResult::Integrity,
    });
}

#[derive(Debug)]
pub(crate) struct ProgramWorkload {
    pub(crate) runtime: Arc<ProgramRuntime>,
}

impl Workload for ProgramWorkload {
    fn generate(&self, context: &WorkloadContext, _rng: &mut ChaCha8Rng) -> Option<Operation> {
        self.runtime.next_operation(context.fiber_id)
    }
}

pub(crate) struct ProgramProperty {
    pub(crate) runtime: Arc<ProgramRuntime>,
}

impl Property for ProgramProperty {
    fn init_op(
        &mut self,
        step: usize,
        fiber_id: usize,
        _txn_id: Option<u64>,
        _execution_id: u64,
        _operation: &Operation,
    ) -> anyhow::Result<()> {
        self.runtime.start_operation(step, fiber_id)
    }

    fn finish_op(
        &mut self,
        step: usize,
        fiber_id: usize,
        _txn_id: Option<u64>,
        _start_exec_id: u64,
        _end_exec_id: u64,
        _operation: &Operation,
        result: &OpResult,
    ) -> anyhow::Result<()> {
        self.runtime.finish_operation(step, fiber_id, result)
    }

    fn finalize(&mut self) -> anyhow::Result<()> {
        self.runtime.finalize()
    }
}

fn validate_result(action: &RuntimeAction, result: &OpResult) -> anyhow::Result<()> {
    if let ExpectedResult::Checkpoint { must_complete } = action.expected {
        return validate_checkpoint(action, result, must_complete);
    }

    let rows = result
        .as_ref()
        .map_err(|error| anyhow!("MBT action `{}` failed: {error}", action.label))?;
    match &action.expected {
        ExpectedResult::Success => Ok(()),
        ExpectedResult::Checkpoint { .. } => unreachable!("checkpoint handled above"),
        ExpectedResult::SchemaPresence(expected) => {
            let actual = rows
                .first()
                .and_then(|row| row.first())
                .and_then(Value::as_int);
            ensure!(
                rows.len() == 1 && rows[0].len() == 1 && actual == Some(i64::from(*expected)),
                "MBT oracle `{}` expected schema presence {}, got {rows:?}",
                action.label,
                i64::from(*expected),
            );
            Ok(())
        }
        ExpectedResult::Rows(expected) => {
            let actual = rows
                .iter()
                .map(|row| {
                    ensure!(row.len() == 2, "row observation has {} columns", row.len());
                    let key = row[0]
                        .as_int()
                        .ok_or_else(|| anyhow!("row key is not an integer: {:?}", row[0]))?;
                    let value = row[1]
                        .as_int()
                        .ok_or_else(|| anyhow!("row value is not an integer: {:?}", row[1]))?;
                    Ok((key, value))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            ensure!(
                &actual == expected,
                "MBT oracle `{}` expected rows {expected:?}, got {actual:?}",
                action.label
            );
            Ok(())
        }
        ExpectedResult::Integrity => {
            let actual = rows
                .first()
                .and_then(|row| row.first())
                .and_then(|value| match value {
                    Value::Text(text) => Some(text.as_str()),
                    _ => None,
                });
            ensure!(
                rows.len() == 1 && rows[0].len() == 1 && actual == Some("ok"),
                "MBT oracle `{}` expected integrity_check = \"ok\", got {rows:?}",
                action.label
            );
            Ok(())
        }
    }
}

fn validate_checkpoint(
    action: &RuntimeAction,
    result: &OpResult,
    must_complete: bool,
) -> anyhow::Result<()> {
    match result {
        Err(turso_core::LimboError::Busy) => {
            ensure!(
                !must_complete,
                "MBT quiescent checkpoint action `{}` returned BUSY",
                action.label
            );
            Ok(())
        }
        Err(error) => bail!("MBT checkpoint action `{}` failed: {error}", action.label),
        Ok(rows) => {
            ensure!(
                rows.len() == 1 && rows[0].len() == 3,
                "MBT checkpoint action `{}` expected one [busy, log, total_backfilled] row, got {rows:?}",
                action.label
            );
            let busy = rows[0][0]
                .as_int()
                .ok_or_else(|| anyhow!("checkpoint busy flag is not an integer"))?;
            let log_frames = rows[0][1]
                .as_int()
                .ok_or_else(|| anyhow!("checkpoint log count is not an integer"))?;
            let total_backfilled = rows[0][2]
                .as_int()
                .ok_or_else(|| anyhow!("checkpoint backfill count is not an integer"))?;
            ensure!(
                matches!(busy, 0 | 1),
                "checkpoint busy flag must be 0 or 1, got {busy}"
            );
            ensure!(
                log_frames >= 0 && (0..=log_frames).contains(&total_backfilled),
                "checkpoint reports log={log_frames}, total_backfilled={total_backfilled}"
            );
            if must_complete {
                ensure!(
                    busy == 0 && total_backfilled == log_frames,
                    "MBT quiescent checkpoint action `{}` did not fully backfill: busy={busy}, log={log_frames}, total_backfilled={total_backfilled}",
                    action.label
                );
            }
            Ok(())
        }
    }
}
