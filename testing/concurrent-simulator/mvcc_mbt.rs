use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, anyhow, bail, ensure};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use turso_core::Value;

use crate::operations::{OpResult, Operation};
use crate::properties::Property;
use crate::workloads::{Workload, WorkloadContext};
use crate::{SchemaBias, TxMode, Whopper, WhopperOpts};

const WRITER_FIBER: usize = 0;
const READER_FIBER: usize = 1;
const CHECKPOINT_FIBER: usize = 2;
const OBSERVER_FIBER: usize = 3;
const FIBER_COUNT: usize = 4;
const MAX_SIMULATOR_STEPS: usize = 200_000;
const TABLE_IDS: [u8; 2] = [0, 1];
const MAX_FIBER_QUANTA: [usize; 4] = [1, 4, 16, 64];
const DIRTY_READ_SPLIT_INDEX: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SemanticCommand {
    CreateTable { table: u8 },
    Put { table: u8, key: i64, value: i64 },
    Delete { table: u8, key: i64 },
    DropTable { table: u8 },
    PassiveCheckpoint,
    BeginWrite,
    CommitWrite,
    RollbackWrite,
}

impl SemanticCommand {
    fn operation(&self) -> Operation {
        match self {
            Self::CreateTable { table } => execute(format!(
                "CREATE TABLE {}(k INTEGER PRIMARY KEY, v INTEGER NOT NULL)",
                table_name(*table)
            )),
            Self::Put { table, key, value } => execute(format!(
                "INSERT INTO {}(k, v) VALUES ({key}, {value}) \
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                table_name(*table)
            )),
            Self::Delete { table, key } => execute(format!(
                "DELETE FROM {} WHERE k = {key}",
                table_name(*table)
            )),
            Self::DropTable { table } => execute(format!("DROP TABLE {}", table_name(*table))),
            Self::PassiveCheckpoint => Operation::WalCheckpoint {
                mode: "PASSIVE".to_owned(),
            },
            Self::BeginWrite => Operation::Begin {
                mode: TxMode::Default,
            },
            Self::CommitWrite => Operation::Commit,
            Self::RollbackWrite => Operation::Rollback,
        }
    }

    fn label(&self) -> String {
        match self {
            Self::CreateTable { table } => format!("create table {}", table_name(*table)),
            Self::Put { table, key, value } => {
                format!("put {} ({key}, {value})", table_name(*table))
            }
            Self::Delete { table, key } => {
                format!("delete {} key {key}", table_name(*table))
            }
            Self::DropTable { table } => format!("drop table {}", table_name(*table)),
            Self::PassiveCheckpoint => "passive checkpoint".to_owned(),
            Self::BeginWrite => "begin writer transaction".to_owned(),
            Self::CommitWrite => "commit writer transaction".to_owned(),
            Self::RollbackWrite => "rollback writer transaction".to_owned(),
        }
    }
}

fn execute(sql: String) -> Operation {
    Operation::Execute { sql }
}

fn table_name(table: u8) -> String {
    format!("mbt_t{table}")
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AbstractState {
    pub tables: BTreeMap<u8, BTreeMap<i64, i64>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MbtProgram {
    pub setup: Vec<SemanticCommand>,
    pub writer: Vec<SemanticCommand>,
    pub checkpoints: Vec<SemanticCommand>,
    pub reader_pinned: bool,
    pub reader_snapshot: AbstractState,
    pub expected: AbstractState,
}

impl MbtProgram {
    pub fn command_count(&self) -> usize {
        self.setup.len() + self.writer.len() + self.checkpoints.len()
    }

    pub(crate) fn canonical_json(&self) -> serde_json::Result<String> {
        #[derive(Serialize)]
        struct CanonicalProgram<'a> {
            setup: &'a [SemanticCommand],
            writer: &'a [SemanticCommand],
            checkpoints: &'a [SemanticCommand],
            reader_pinned: bool,
        }

        serde_json::to_string(&CanonicalProgram {
            setup: &self.setup,
            writer: &self.writer,
            checkpoints: &self.checkpoints,
            reader_pinned: self.reader_pinned,
        })
    }

    fn validate_shape(&self) -> anyhow::Result<()> {
        ensure!(!self.setup.is_empty(), "model program has no setup");
        ensure!(
            self.setup.iter().all(|command| !matches!(
                command,
                SemanticCommand::BeginWrite
                    | SemanticCommand::CommitWrite
                    | SemanticCommand::RollbackWrite
            )),
            "setup contains transaction control"
        );
        ensure!(
            self.writer.len() >= 3,
            "writer requires BEGIN, a mutation, and COMMIT or ROLLBACK"
        );
        ensure!(
            matches!(self.writer.first(), Some(SemanticCommand::BeginWrite)),
            "writer does not begin with BEGIN"
        );
        ensure!(
            matches!(
                self.writer.last(),
                Some(SemanticCommand::CommitWrite | SemanticCommand::RollbackWrite)
            ),
            "writer does not end with COMMIT or ROLLBACK"
        );
        ensure!(
            self.writer[1..self.writer.len() - 1]
                .iter()
                .all(|command| matches!(
                    command,
                    SemanticCommand::CreateTable { .. }
                        | SemanticCommand::Put { .. }
                        | SemanticCommand::Delete { .. }
                        | SemanticCommand::DropTable { .. }
                )),
            "writer body contains a non-mutation command"
        );
        ensure!(
            matches!(self.checkpoints.len(), 1 | 2)
                && self
                    .checkpoints
                    .iter()
                    .all(|command| matches!(command, SemanticCommand::PassiveCheckpoint)),
            "checkpoint actor must contain one or two PASSIVE checkpoints"
        );
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct ItfDocument {
    states: Vec<HashMap<String, JsonValue>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodePhase {
    Setup,
    Concurrent,
    Done,
}

pub fn load_itf(path: impl AsRef<Path>) -> anyhow::Result<MbtProgram> {
    let path = path.as_ref();
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read Quint ITF trace {}", path.display()))?;
    parse_itf(&bytes)
        .with_context(|| format!("failed to decode Quint ITF trace {}", path.display()))
}

fn parse_itf(bytes: &[u8]) -> anyhow::Result<MbtProgram> {
    let document: ItfDocument = serde_json::from_slice(bytes).context("invalid Quint ITF JSON")?;
    ensure!(!document.states.is_empty(), "Quint ITF trace has no states");

    let mut phase = DecodePhase::Setup;
    let mut setup = Vec::new();
    let mut writer = Vec::new();
    let mut checkpoints = Vec::new();
    let mut reader_pinned = None;

    for (state_index, state) in document.states.iter().enumerate() {
        let action = state
            .get("mbt::actionTaken")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| anyhow!("ITF state {state_index} has no `mbt::actionTaken`"))?;
        match action {
            "init" | "step" if state_index == 0 => {}
            "SetupCreate" if phase == DecodePhase::Setup => {
                setup.push(SemanticCommand::CreateTable {
                    table: nondet_table(state, state_index)?,
                });
            }
            "SetupPut" if phase == DecodePhase::Setup => {
                setup.push(SemanticCommand::Put {
                    table: nondet_table(state, state_index)?,
                    key: nondet_int(state, state_index, "key")?,
                    value: nondet_int(state, state_index, "value")?,
                });
            }
            "SetupDelete" if phase == DecodePhase::Setup => {
                setup.push(SemanticCommand::Delete {
                    table: nondet_table(state, state_index)?,
                    key: nondet_int(state, state_index, "key")?,
                });
            }
            "SetupCheckpoint" if phase == DecodePhase::Setup => {
                setup.push(SemanticCommand::PassiveCheckpoint);
            }
            "BeginConcurrent" if phase == DecodePhase::Setup => {
                reader_pinned = Some(nondet_bool(state, state_index, "pinReader")?);
                writer.push(SemanticCommand::BeginWrite);
                phase = DecodePhase::Concurrent;
            }
            "WriterPut" if phase == DecodePhase::Concurrent => {
                writer.push(SemanticCommand::Put {
                    table: nondet_table(state, state_index)?,
                    key: nondet_int(state, state_index, "key")?,
                    value: nondet_int(state, state_index, "value")?,
                });
            }
            "WriterDelete" if phase == DecodePhase::Concurrent => {
                writer.push(SemanticCommand::Delete {
                    table: nondet_table(state, state_index)?,
                    key: nondet_int(state, state_index, "key")?,
                });
            }
            "WriterDrop" if phase == DecodePhase::Concurrent => {
                writer.push(SemanticCommand::DropTable {
                    table: nondet_table(state, state_index)?,
                });
            }
            "WriterCreate" if phase == DecodePhase::Concurrent => {
                writer.push(SemanticCommand::CreateTable {
                    table: nondet_table(state, state_index)?,
                });
            }
            "WriterCommit" if phase == DecodePhase::Concurrent => {
                writer.push(SemanticCommand::CommitWrite);
            }
            "WriterRollback" if phase == DecodePhase::Concurrent => {
                writer.push(SemanticCommand::RollbackWrite);
            }
            "ConcurrentCheckpoint" if phase == DecodePhase::Concurrent => {
                checkpoints.push(SemanticCommand::PassiveCheckpoint);
            }
            "EndConcurrent" if phase == DecodePhase::Concurrent => {
                phase = DecodePhase::Done;
            }
            "DoneStutter" if phase == DecodePhase::Done => {}
            other => {
                bail!("ITF state {state_index} has action `{other}` in invalid phase {phase:?}")
            }
        }
    }
    ensure!(
        phase == DecodePhase::Done,
        "Quint trace did not complete its concurrent epoch"
    );

    let final_state = document.states.last().expect("states is non-empty");
    let model = final_state
        .get("model")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| anyhow!("final Quint state has no `model` record"))?;
    ensure!(
        model.get("phase").and_then(JsonValue::as_str) == Some("done"),
        "final Quint model state is not done"
    );
    let program = MbtProgram {
        setup,
        writer,
        checkpoints,
        reader_pinned: reader_pinned
            .ok_or_else(|| anyhow!("Quint trace never began its concurrent epoch"))?,
        reader_snapshot: decode_abstract_state(model, "snapshot")?,
        expected: decode_abstract_state(model, "committed")?,
    };
    program.validate_shape()?;
    Ok(program)
}

fn nondet_int(
    state: &HashMap<String, JsonValue>,
    state_index: usize,
    name: &str,
) -> anyhow::Result<i64> {
    let pick = state
        .get("mbt::nondetPicks")
        .and_then(JsonValue::as_object)
        .and_then(|picks| picks.get(name))
        .ok_or_else(|| anyhow!("ITF state {state_index} has no nondeterministic pick `{name}`"))?;
    ensure!(
        pick.get("tag").and_then(JsonValue::as_str) == Some("Some"),
        "ITF state {state_index} did not pick `{name}`"
    );
    itf_int(
        pick.get("value")
            .ok_or_else(|| anyhow!("ITF state {state_index} pick `{name}` has no value"))?,
    )
    .ok_or_else(|| anyhow!("ITF state {state_index} pick `{name}` is not an integer"))
}

fn nondet_bool(
    state: &HashMap<String, JsonValue>,
    state_index: usize,
    name: &str,
) -> anyhow::Result<bool> {
    let pick = state
        .get("mbt::nondetPicks")
        .and_then(JsonValue::as_object)
        .and_then(|picks| picks.get(name))
        .ok_or_else(|| anyhow!("ITF state {state_index} has no nondeterministic pick `{name}`"))?;
    ensure!(
        pick.get("tag").and_then(JsonValue::as_str) == Some("Some"),
        "ITF state {state_index} did not pick `{name}`"
    );
    pick.get("value")
        .and_then(JsonValue::as_bool)
        .ok_or_else(|| anyhow!("ITF state {state_index} pick `{name}` is not a boolean"))
}

fn nondet_table(state: &HashMap<String, JsonValue>, state_index: usize) -> anyhow::Result<u8> {
    let table = nondet_int(state, state_index, "table")?;
    let table = u8::try_from(table)
        .map_err(|_| anyhow!("ITF state {state_index} table id {table} is out of range"))?;
    ensure!(
        TABLE_IDS.contains(&table),
        "ITF state {state_index} has unknown table id {table}"
    );
    Ok(table)
}

fn decode_abstract_state(
    model: &serde_json::Map<String, JsonValue>,
    prefix: &str,
) -> anyhow::Result<AbstractState> {
    let mut tables = BTreeMap::new();
    for table in TABLE_IDS {
        let field = format!("{prefix}{table}");
        let table_state = model
            .get(&field)
            .and_then(JsonValue::as_object)
            .ok_or_else(|| anyhow!("final Quint model has no `{field}` record"))?;
        let exists = table_state
            .get("exists")
            .and_then(JsonValue::as_bool)
            .ok_or_else(|| anyhow!("final Quint model `{field}` has no boolean `exists`"))?;
        let mut rows = BTreeMap::new();
        for key in [0, 1] {
            let row_field = format!("row{key}");
            let slot = table_state
                .get(&row_field)
                .and_then(JsonValue::as_object)
                .ok_or_else(|| anyhow!("final Quint model `{field}` has no `{row_field}`"))?;
            let present = slot
                .get("present")
                .and_then(JsonValue::as_bool)
                .ok_or_else(|| {
                    anyhow!("final Quint model `{field}.{row_field}` has no boolean `present`")
                })?;
            if present {
                let value = slot.get("value").and_then(itf_int).ok_or_else(|| {
                    anyhow!("final Quint model `{field}.{row_field}` has no integer `value`")
                })?;
                rows.insert(key, value);
            }
        }
        ensure!(
            exists || rows.is_empty(),
            "Quint model contains rows for absent table {table}"
        );
        if exists {
            tables.insert(table, rows);
        }
    }
    Ok(AbstractState { tables })
}

fn itf_int(value: &JsonValue) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.get("#bigint")?.as_str()?.parse().ok())
}

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
struct InFlightAction {
    action: RuntimeAction,
}

#[derive(Debug)]
struct RuntimeState {
    epochs: Vec<RuntimeEpoch>,
    epoch: usize,
    in_flight: HashMap<usize, InFlightAction>,
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
struct ProgramRuntime {
    state: Mutex<RuntimeState>,
}

impl ProgramRuntime {
    fn new(program: &MbtProgram) -> Arc<Self> {
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
        state.in_flight.insert(fiber_id, InFlightAction { action });
        Some(operation)
    }

    fn start_operation(&self, step: usize, fiber_id: usize) -> anyhow::Result<()> {
        let mut state = self.state.lock().unwrap();
        let label = state
            .in_flight
            .get(&fiber_id)
            .ok_or_else(|| anyhow!("fiber {fiber_id} started an untracked MBT operation"))?
            .action
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
            .ok_or_else(|| anyhow!("fiber {fiber_id} finished an untracked MBT operation"))?
            .action;
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

    fn is_complete(&self) -> bool {
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

    fn history(&self) -> Vec<MbtEvent> {
        self.state.lock().unwrap().history.clone()
    }

    fn writer_checkpoint_overlap(&self) -> bool {
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
    actor: String,
    event: MbtEventKind,
    label: String,
    oracle_passed: Option<bool>,
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

#[derive(Debug)]
struct ProgramWorkload {
    runtime: Arc<ProgramRuntime>,
}

impl Workload for ProgramWorkload {
    fn generate(&self, context: &WorkloadContext, _rng: &mut ChaCha8Rng) -> Option<Operation> {
        self.runtime.next_operation(context.fiber_id)
    }
}

struct ProgramProperty {
    runtime: Arc<ProgramRuntime>,
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
            &failed_event
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
