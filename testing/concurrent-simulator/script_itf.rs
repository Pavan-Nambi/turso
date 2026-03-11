use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, anyhow, bail};
use serde_json::{Map, Value};

use crate::operations::{Operation, TxMode};

#[derive(Debug, Clone)]
pub enum ScriptedAction {
    Operation(Operation),
    Reopen,
}

#[derive(Debug, Clone)]
pub struct ScriptedStep {
    pub fiber_id: usize,
    pub action: ScriptedAction,
    pub source_action: String,
}

pub fn load_scripted_steps_from_itf(
    path: &Path,
    strict: bool,
    max_connections: usize,
    repeat: usize,
) -> anyhow::Result<Vec<ScriptedStep>> {
    if repeat == 0 {
        bail!("script repeat must be >= 1");
    }
    if max_connections == 0 {
        bail!("max_connections must be >= 1 when loading scripted ITF");
    }

    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read ITF trace from {}", path.display()))?;
    let root: Value = serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse ITF trace JSON from {}", path.display()))?;
    let states = root
        .get("states")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("ITF trace is missing top-level `states` array"))?;

    let mut table_prelude = HashSet::new();
    let mut steps = Vec::new();

    for (state_idx, state) in states.iter().enumerate() {
        let state_obj = state
            .as_object()
            .ok_or_else(|| anyhow!("state {state_idx} in ITF trace is not an object"))?;

        let action_name = state_obj
            .get("mbt::actionTaken")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("state {state_idx} is missing string `mbt::actionTaken`"))?;

        let picks = state_obj
            .get("mbt::nondetPicks")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("state {state_idx} is missing object `mbt::nondetPicks`"))?;

        let action_key = normalize_key(action_name);
        if action_key.is_empty() || action_key == "init" {
            continue;
        }

        let fiber_id = pick_fiber_id(picks, max_connections, strict).with_context(|| {
            format!("failed to map fiber for action `{action_name}` in state {state_idx}")
        })?;

        let mapped = map_action(action_name, &action_key, picks, state_idx, strict)?;
        let Some(mut step) = mapped else {
            continue;
        };
        step.fiber_id = fiber_id;

        if let ScriptedAction::Operation(Operation::SimpleInsert { table_name, .. })
        | ScriptedAction::Operation(Operation::SimpleSelect { table_name, .. }) = &step.action
        {
            table_prelude.insert(table_name.clone());
        }

        steps.push(step);
    }

    if steps.is_empty() {
        bail!(
            "no replayable actions found in ITF trace {}",
            path.display()
        );
    }

    let mut prelude = table_prelude
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|table_name| ScriptedStep {
            fiber_id: 0,
            action: ScriptedAction::Operation(Operation::CreateSimpleTable {
                table_name: table_name.clone(),
            }),
            source_action: format!("scripted-prelude:create-table:{table_name}"),
        })
        .collect::<Vec<_>>();

    prelude.append(&mut steps);
    if repeat == 1 {
        return Ok(prelude);
    }

    let base = prelude.clone();
    for _ in 1..repeat {
        prelude.extend(base.iter().cloned());
    }
    Ok(prelude)
}

fn map_action(
    action_name: &str,
    action_key: &str,
    picks: &Map<String, Value>,
    state_idx: usize,
    strict: bool,
) -> anyhow::Result<Option<ScriptedStep>> {
    let source_action = action_name.to_string();

    let mapped = if is_begin_action(action_key) {
        let mode = pick_string(
            picks,
            &[
                "mode",
                "tx_mode",
                "txn_mode",
                "begin_mode",
                "transaction_mode",
            ],
        )
        .or_else(|| infer_begin_mode(action_key))
        .unwrap_or_else(|| "default".to_string());

        let mode = parse_tx_mode(&mode).ok_or_else(|| {
            anyhow!(
                "unsupported begin mode `{mode}` for action `{action_name}` at state {state_idx}"
            )
        })?;
        Some(ScriptedAction::Operation(Operation::Begin { mode }))
    } else if action_key.contains("commit") {
        Some(ScriptedAction::Operation(Operation::Commit))
    } else if action_key.contains("rollback") || action_key.contains("abort") {
        Some(ScriptedAction::Operation(Operation::Rollback))
    } else if action_key.contains("checkpoint") {
        let mode = pick_string(
            picks,
            &[
                "mode",
                "checkpoint_mode",
                "wal_mode",
                "ckpt_mode",
                "ckptMode",
            ],
        )
        .or_else(|| infer_checkpoint_mode(action_key))
        .unwrap_or_else(|| "PASSIVE".to_string());
        let mode = normalize_checkpoint_mode(&mode).ok_or_else(|| {
            anyhow!(
                "unsupported checkpoint mode `{mode}` for action `{action_name}` at state {state_idx}"
            )
        })?;
        Some(ScriptedAction::Operation(Operation::WalCheckpoint { mode }))
    } else if action_key.contains("integritycheck") {
        Some(ScriptedAction::Operation(Operation::IntegrityCheck))
    } else if action_key.contains("quickcheck") {
        Some(ScriptedAction::Operation(Operation::Select {
            sql: "PRAGMA quick_check".to_string(),
        }))
    } else if action_key.contains("reopen")
        || action_key.contains("restart")
        || action_key.contains("reconnect")
    {
        Some(ScriptedAction::Reopen)
    } else if is_insert_action(action_key) {
        if let Some(sql) = pick_string(
            picks,
            &[
                "sql",
                "sql_write",
                "sqlWrite",
                "write_sql",
                "query",
                "statement",
            ],
        ) {
            Some(ScriptedAction::Operation(Operation::Insert { sql }))
        } else {
            let table_name = pick_string(picks, &["table", "table_name"])
                .unwrap_or_else(|| "simple_kv_quint".to_string());
            let key = pick_string(picks, &["key", "id", "account"])
                .unwrap_or_else(|| format!("k{state_idx}"));
            let value_length = pick_u64(picks, &["value_length", "bytes", "amount"])
                .unwrap_or(64)
                .clamp(1, 64 * 1024) as usize;
            Some(ScriptedAction::Operation(Operation::SimpleInsert {
                table_name,
                key,
                value_length,
            }))
        }
    } else if is_delete_action(action_key) {
        if let Some(sql) = pick_string(
            picks,
            &[
                "sql",
                "sql_write",
                "sqlWrite",
                "write_sql",
                "query",
                "statement",
            ],
        ) {
            Some(ScriptedAction::Operation(Operation::Delete { sql }))
        } else {
            let table_name = pick_string(picks, &["table", "table_name"])
                .unwrap_or_else(|| "simple_kv_quint".to_string());
            let key = pick_string(picks, &["key", "id", "account"])
                .unwrap_or_else(|| format!("k{state_idx}"));
            let key = key.replace('\'', "''");
            Some(ScriptedAction::Operation(Operation::Delete {
                sql: format!("DELETE FROM {table_name} WHERE key = '{key}'"),
            }))
        }
    } else if is_select_action(action_key) {
        if let Some(sql) = pick_string(
            picks,
            &[
                "sql",
                "sql_read",
                "sqlRead",
                "read_sql",
                "query",
                "statement",
            ],
        ) {
            Some(ScriptedAction::Operation(Operation::Select { sql }))
        } else {
            let table_name = pick_string(picks, &["table", "table_name"])
                .unwrap_or_else(|| "simple_kv_quint".to_string());
            let key = pick_string(picks, &["key", "id", "account"])
                .unwrap_or_else(|| format!("k{state_idx}"));
            Some(ScriptedAction::Operation(Operation::SimpleSelect {
                table_name,
                key,
            }))
        }
    } else {
        None
    };

    match mapped {
        Some(action) => Ok(Some(ScriptedStep {
            fiber_id: 0,
            action,
            source_action,
        })),
        None if strict => bail!(
            "unmapped action `{action_name}` in ITF state {state_idx}; use a supported action vocabulary"
        ),
        None => Ok(None),
    }
}

fn pick_fiber_id(
    picks: &Map<String, Value>,
    max_connections: usize,
    strict: bool,
) -> anyhow::Result<usize> {
    let Some(v) = pick_u64(
        picks,
        &[
            "fiber",
            "fiber_id",
            "connection",
            "conn",
            "client",
            "thread",
            "process",
        ],
    ) else {
        return Ok(0);
    };
    let raw = usize::try_from(v).map_err(|_| anyhow!("fiber id is out of range: {v}"))?;
    if raw < max_connections {
        return Ok(raw);
    }
    if strict {
        bail!(
            "fiber id {} is out of range for max_connections={}",
            raw,
            max_connections
        );
    }
    Ok(raw % max_connections)
}

fn is_begin_action(key: &str) -> bool {
    key.starts_with("begin")
        || key.contains("begin")
        || key.contains("starttx")
        || key.contains("starttransaction")
        || key.contains("txbegin")
}

fn is_insert_action(key: &str) -> bool {
    key.contains("insert")
        || key.contains("write")
        || key.contains("deposit")
        || key.contains("withdraw")
}

fn is_select_action(key: &str) -> bool {
    key.contains("select") || key.contains("read") || key.contains("lookup")
}

fn is_delete_action(key: &str) -> bool {
    key.contains("delete") || key.contains("remove")
}

fn infer_begin_mode(action_key: &str) -> Option<String> {
    if action_key.contains("immediate") {
        Some("immediate".to_string())
    } else if action_key.contains("deferred") {
        Some("deferred".to_string())
    } else if action_key.contains("concurrent") {
        Some("concurrent".to_string())
    } else {
        None
    }
}

fn infer_checkpoint_mode(action_key: &str) -> Option<String> {
    ["passive", "full", "restart", "truncate"]
        .iter()
        .find(|mode| action_key.contains(**mode))
        .map(|mode| mode.to_string())
}

fn parse_tx_mode(mode: &str) -> Option<TxMode> {
    match normalize_key(mode).as_str() {
        "default" | "begin" => Some(TxMode::Default),
        "deferred" => Some(TxMode::Deferred),
        "immediate" => Some(TxMode::Immediate),
        "concurrent" => Some(TxMode::Concurrent),
        _ => None,
    }
}

fn normalize_checkpoint_mode(mode: &str) -> Option<String> {
    match normalize_key(mode).as_str() {
        "passive" => Some("PASSIVE".to_string()),
        "full" => Some("FULL".to_string()),
        "restart" => Some("RESTART".to_string()),
        "truncate" => Some("TRUNCATE".to_string()),
        _ => None,
    }
}

fn normalize_key(input: &str) -> String {
    input
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn pick_string(picks: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    let value = pick_value(picks, keys)?;
    value_to_string(value)
}

fn pick_u64(picks: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    let value = pick_value(picks, keys)?;
    value_to_u64(value)
}

fn pick_value<'a>(picks: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    for key in keys {
        if let Some(value) = picks.get(*key) {
            if let Some(unwrapped) = unwrap_quint_option(value) {
                return Some(unwrapped);
            }
        }
    }

    let normalized_keys = keys.iter().map(|k| normalize_key(k)).collect::<Vec<_>>();
    picks.iter().find_map(|(key, value)| {
        let normalized = normalize_key(key);
        if normalized_keys.iter().any(|k| k == &normalized) {
            unwrap_quint_option(value)
        } else {
            None
        }
    })
}

fn unwrap_quint_option(value: &Value) -> Option<&Value> {
    let obj = value.as_object()?;
    let tag = obj.get("tag")?.as_str()?;
    match tag {
        "Some" => obj.get("value"),
        "None" => None,
        _ => Some(value),
    }
}

fn value_to_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(num) => num.as_u64().or_else(|| num.as_i64()?.try_into().ok()),
        Value::String(s) => s.parse::<u64>().ok(),
        Value::Object(obj) => {
            if let Some(bigint) = obj.get("#bigint").and_then(Value::as_str) {
                bigint.parse::<u64>().ok()
            } else if let Some(tag) = obj.get("tag").and_then(Value::as_str) {
                if tag == "Some" {
                    obj.get("value").and_then(value_to_u64)
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(num) => Some(num.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Object(obj) => {
            if let Some(bigint) = obj.get("#bigint").and_then(Value::as_str) {
                Some(bigint.to_string())
            } else if let Some(tag) = obj.get("tag").and_then(Value::as_str) {
                if tag == "Some" {
                    obj.get("value").and_then(value_to_string)
                } else {
                    Some(tag.to_string())
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn loads_scripted_steps_with_prelude_repeat_and_modes() {
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            r##"{{
  "vars": ["x"],
  "states": [
    {{
      "mbt::actionTaken": "init",
      "mbt::nondetPicks": {{}}
    }},
    {{
      "mbt::actionTaken": "begin",
      "mbt::nondetPicks": {{
        "fiber": {{ "tag": "Some", "value": {{ "#bigint": "1" }} }},
        "mode": {{ "tag": "Some", "value": "immediate" }}
      }}
    }},
    {{
      "mbt::actionTaken": "insert",
      "mbt::nondetPicks": {{
        "fiber": {{ "tag": "Some", "value": {{ "#bigint": "1" }} }},
        "table_name": {{ "tag": "Some", "value": "kv" }},
        "key": {{ "tag": "Some", "value": "alice" }},
        "amount": {{ "tag": "Some", "value": {{ "#bigint": "19" }} }}
      }}
    }},
    {{
      "mbt::actionTaken": "opInsertSql",
      "mbt::nondetPicks": {{
        "fiber": {{ "tag": "Some", "value": {{ "#bigint": "1" }} }},
        "sqlWrite": {{ "tag": "Some", "value": "INSERT OR REPLACE INTO kv (key, value) VALUES ('bob', zeroblob(32))" }}
      }}
    }},
    {{
      "mbt::actionTaken": "checkpoint",
      "mbt::nondetPicks": {{
        "ckptMode": {{ "tag": "Some", "value": "full" }}
      }}
    }},
    {{
      "mbt::actionTaken": "opIntegrityCheck",
      "mbt::nondetPicks": {{
        "fiber": {{ "tag": "Some", "value": {{ "#bigint": "1" }} }}
      }}
    }},
    {{
      "mbt::actionTaken": "reopen",
      "mbt::nondetPicks": {{}}
    }},
    {{
      "mbt::actionTaken": "commit",
      "mbt::nondetPicks": {{
        "fiber": {{ "tag": "Some", "value": {{ "#bigint": "1" }} }}
      }}
    }}
  ]
}}"##
        )
        .unwrap();

        let steps = load_scripted_steps_from_itf(file.path(), true, 4, 2).unwrap();
        assert_eq!(steps.len(), 16);

        match &steps[0].action {
            ScriptedAction::Operation(Operation::CreateSimpleTable { table_name }) => {
                assert_eq!(table_name, "kv");
            }
            other => panic!("unexpected prelude action: {other:?}"),
        }

        match &steps[1].action {
            ScriptedAction::Operation(Operation::Begin { mode }) => {
                assert_eq!(*mode, TxMode::Immediate);
            }
            other => panic!("unexpected action: {other:?}"),
        }

        match &steps[2].action {
            ScriptedAction::Operation(Operation::SimpleInsert {
                table_name,
                key,
                value_length,
            }) => {
                assert_eq!(table_name, "kv");
                assert_eq!(key, "alice");
                assert_eq!(*value_length, 19);
            }
            other => panic!("unexpected insert action: {other:?}"),
        }

        match &steps[4].action {
            ScriptedAction::Operation(Operation::WalCheckpoint { mode }) => {
                assert_eq!(mode, "FULL");
            }
            other => panic!("unexpected checkpoint action: {other:?}"),
        }

        match &steps[5].action {
            ScriptedAction::Operation(Operation::IntegrityCheck) => {}
            other => panic!("unexpected integrity action: {other:?}"),
        }

        match &steps[6].action {
            ScriptedAction::Reopen => {}
            other => panic!("unexpected action: {other:?}"),
        }

        // second replay cycle starts with prelude again
        match &steps[8].action {
            ScriptedAction::Operation(Operation::CreateSimpleTable { table_name }) => {
                assert_eq!(table_name, "kv");
            }
            other => panic!("unexpected repeated prelude action: {other:?}"),
        }
    }

    #[test]
    fn strict_mode_rejects_unknown_action() {
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            r#"{{
  "states": [
    {{
      "mbt::actionTaken": "init",
      "mbt::nondetPicks": {{}}
    }},
    {{
      "mbt::actionTaken": "totally_unknown",
      "mbt::nondetPicks": {{}}
    }}
  ]
}}"#
        )
        .unwrap();
        let err = load_scripted_steps_from_itf(file.path(), true, 4, 1).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unmapped action"));
    }
}
