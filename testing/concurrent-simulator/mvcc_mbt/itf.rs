//! Decode a Quint ITF trace into a semantic MVCC program.
//!
//! The trace is a linear sequence of model actions (`mbt::actionTaken`) with
//! the nondeterministic picks Quint made for each (`mbt::nondetPicks`). We
//! replay that sequence through a small phase machine to recover the setup,
//! writer, and checkpoint command lists, and read the model's final
//! committed/snapshot state as the oracle expectation.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::{TABLE_IDS, execute, table_name};
use crate::TxMode;
use crate::operations::Operation;

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
    pub(crate) fn operation(&self) -> Operation {
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

    pub(crate) fn label(&self) -> String {
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
