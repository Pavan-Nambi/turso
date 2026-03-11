use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, anyhow, bail};
use serde_json::{Map, Value};

use crate::generate::GeneratedStatement;

const DEFAULT_TABLE: &str = "quint_seed_kv";

pub fn load_seed_corpus(path: &Path) -> anyhow::Result<Vec<GeneratedStatement>> {
    if path.is_dir() {
        let mut statements = Vec::new();
        let mut entries = fs::read_dir(path)
            .with_context(|| format!("failed to read seed corpus directory {}", path.display()))?
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("failed to list seed corpus directory {}", path.display()))?;
        entries.sort_by_key(|entry| entry.path());
        for entry in entries {
            let entry_path = entry.path();
            if entry_path.is_dir() {
                continue;
            }
            let file_name = entry_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if !(file_name.ends_with(".sql")
                || file_name.ends_with(".itf.json")
                || file_name.ends_with(".itf"))
            {
                continue;
            }
            statements.extend(load_seed_corpus_file(&entry_path)?);
        }
        if statements.is_empty() {
            bail!(
                "seed corpus directory {} produced no statements",
                path.display()
            );
        }
        return Ok(statements);
    }

    load_seed_corpus_file(path)
}

fn load_seed_corpus_file(path: &Path) -> anyhow::Result<Vec<GeneratedStatement>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read seed corpus file {}", path.display()))?;

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    if ext.eq_ignore_ascii_case("sql") {
        let statements = split_sql_statements(&text)
            .into_iter()
            .map(to_generated_statement)
            .collect::<Vec<_>>();
        if statements.is_empty() {
            bail!("seed SQL corpus {} has no statements", path.display());
        }
        return Ok(statements);
    }

    let value: Value = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse JSON seed corpus {}", path.display()))?;
    if let Some(trace_files) = value
        .as_object()
        .and_then(|obj| obj.get("trace_files"))
        .and_then(Value::as_array)
    {
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let mut statements = Vec::new();
        for file in trace_files {
            let rel = file
                .as_str()
                .ok_or_else(|| anyhow!("manifest trace_files entries must be strings"))?;
            let trace_path = base.join(rel);
            statements.extend(load_seed_corpus_file(&trace_path).with_context(|| {
                format!(
                    "failed to load manifest trace file {}",
                    trace_path.display()
                )
            })?);
        }
        if statements.is_empty() {
            bail!(
                "seed manifest {} did not resolve to statements",
                path.display()
            );
        }
        return Ok(statements);
    }
    parse_json_seed(value).with_context(|| {
        format!(
            "failed to parse JSON seed corpus statements from {}",
            path.display()
        )
    })
}

fn parse_json_seed(value: Value) -> anyhow::Result<Vec<GeneratedStatement>> {
    if let Some(states) = value.get("states").and_then(Value::as_array) {
        return parse_itf_states(states);
    }

    let Some(items) = value.as_array() else {
        bail!("JSON seed corpus must be an ITF trace or an array of SQL strings");
    };
    let mut statements = Vec::new();
    for item in items {
        let sql = item
            .as_str()
            .ok_or_else(|| anyhow!("JSON array seed entries must be strings"))?;
        statements.push(to_generated_statement(sql.to_string()));
    }
    if statements.is_empty() {
        bail!("JSON seed corpus did not contain any SQL statements");
    }
    Ok(statements)
}

fn parse_itf_states(states: &[Value]) -> anyhow::Result<Vec<GeneratedStatement>> {
    let mut statements = Vec::new();
    let mut needs_default_table = false;

    for (idx, state) in states.iter().enumerate() {
        let obj = state
            .as_object()
            .ok_or_else(|| anyhow!("ITF state {idx} is not an object"))?;
        let action = obj
            .get("mbt::actionTaken")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("ITF state {idx} missing `mbt::actionTaken`"))?;
        let action_key = normalize_key(action);
        if action_key.is_empty() || action_key == "init" {
            continue;
        }

        let picks = obj
            .get("mbt::nondetPicks")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("ITF state {idx} missing `mbt::nondetPicks`"))?;

        if is_begin_action(&action_key) {
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
            .or_else(|| infer_begin_mode(&action_key))
            .unwrap_or_else(|| "BEGIN".to_string());
            let sql = begin_sql(&mode);
            statements.push(to_generated_statement(sql));
            continue;
        }

        if action_key.contains("commit") {
            statements.push(to_generated_statement("COMMIT".to_string()));
            continue;
        }
        if action_key.contains("rollback") || action_key.contains("abort") {
            statements.push(to_generated_statement("ROLLBACK".to_string()));
            continue;
        }
        if action_key.contains("checkpoint") {
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
            .or_else(|| infer_checkpoint_mode(&action_key))
            .unwrap_or_else(|| "PASSIVE".to_string());
            let mode = normalize_checkpoint_mode(&mode).unwrap_or_else(|| "PASSIVE".to_string());
            statements.push(to_generated_statement(format!(
                "PRAGMA wal_checkpoint({mode})"
            )));
            continue;
        }
        if action_key.contains("integritycheck") {
            statements.push(to_generated_statement("PRAGMA integrity_check".to_string()));
            continue;
        }
        if action_key.contains("quickcheck") {
            statements.push(to_generated_statement("PRAGMA quick_check".to_string()));
            continue;
        }
        if action_key.contains("reopen")
            || action_key.contains("restart")
            || action_key.contains("reconnect")
        {
            continue;
        }

        if is_insert_action(&action_key) {
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
                statements.push(to_generated_statement(sql));
            } else {
                needs_default_table = true;
                let key = pick_string(picks, &["key", "id", "account"])
                    .unwrap_or_else(|| format!("k{idx}"));
                let key = sql_escape(&key);
                let value = pick_string(picks, &["value", "payload", "amount"])
                    .unwrap_or_else(|| format!("v{idx}"));
                let value = sql_escape(&value);
                statements.push(to_generated_statement(format!(
                    "INSERT OR REPLACE INTO {DEFAULT_TABLE} (key, value) VALUES ('{key}', '{value}')"
                )));
            }
            continue;
        }

        if is_delete_action(&action_key) {
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
                statements.push(to_generated_statement(sql));
            } else {
                needs_default_table = true;
                let key = pick_string(picks, &["key", "id", "account"])
                    .unwrap_or_else(|| format!("k{idx}"));
                let key = sql_escape(&key);
                statements.push(to_generated_statement(format!(
                    "DELETE FROM {DEFAULT_TABLE} WHERE key = '{key}'"
                )));
            }
            continue;
        }

        if is_select_action(&action_key) {
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
                statements.push(to_generated_statement(sql));
            } else {
                needs_default_table = true;
                let key = pick_string(picks, &["key", "id", "account"])
                    .unwrap_or_else(|| format!("k{idx}"));
                let key = sql_escape(&key);
                statements.push(to_generated_statement(format!(
                    "SELECT key, value FROM {DEFAULT_TABLE} WHERE key = '{key}'"
                )));
            }
        }
    }

    if statements.is_empty() {
        bail!("ITF seed corpus does not contain replayable actions");
    }

    if needs_default_table {
        let mut out = Vec::new();
        out.push(to_generated_statement(format!(
            "CREATE TABLE IF NOT EXISTS {DEFAULT_TABLE} (key TEXT PRIMARY KEY, value TEXT)"
        )));
        out.extend(statements);
        return Ok(out);
    }

    Ok(statements)
}

fn split_sql_statements(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut chars = sql.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\'' => {
                current.push(ch);
                if in_single {
                    if chars.peek() == Some(&'\'') {
                        current.push(chars.next().expect("peeked quote should exist"));
                    } else {
                        in_single = false;
                    }
                } else {
                    in_single = true;
                }
            }
            ';' if !in_single => {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    out.push(trimmed.to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_string());
    }
    out
}

fn to_generated_statement(sql: String) -> GeneratedStatement {
    let key = normalize_key(&sql);
    let is_ddl = key.starts_with("create")
        || key.starts_with("drop")
        || key.starts_with("alter")
        || key.starts_with("reindex");
    let has_unordered_limit = key.contains("limit") && !key.contains("orderby");
    GeneratedStatement {
        sql,
        is_ddl,
        has_unordered_limit,
        unordered_limit_reason: None,
    }
}

fn begin_sql(mode: &str) -> String {
    match normalize_key(mode).as_str() {
        "begin" | "default" | "deferred" => "BEGIN".to_string(),
        "immediate" => "BEGIN IMMEDIATE".to_string(),
        "concurrent" => "BEGIN CONCURRENT".to_string(),
        _ => "BEGIN".to_string(),
    }
}

fn normalize_key(input: &str) -> String {
    input
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn sql_escape(input: &str) -> String {
    input.replace('\'', "''")
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

fn normalize_checkpoint_mode(mode: &str) -> Option<String> {
    match normalize_key(mode).as_str() {
        "passive" => Some("PASSIVE".to_string()),
        "full" => Some("FULL".to_string()),
        "restart" => Some("RESTART".to_string()),
        "truncate" => Some("TRUNCATE".to_string()),
        _ => None,
    }
}

fn pick_string(picks: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    let value = pick_value(picks, keys)?;
    value_to_string(value)
}

fn pick_value<'a>(picks: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    for key in keys {
        if let Some(value) = picks.get(*key) {
            if let Some(unwrapped) = unwrap_quint_option(value) {
                return Some(unwrapped);
            }
        }
    }

    let normalized_keys = keys
        .iter()
        .map(|k| normalize_key(k))
        .collect::<BTreeSet<_>>();
    picks.iter().find_map(|(key, value)| {
        if normalized_keys.contains(&normalize_key(key)) {
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
    use super::*;

    #[test]
    fn parse_itf_seed_corpus() {
        let value: Value = serde_json::from_str(
            r#"{
  "states": [
    {
      "mbt::actionTaken": "init",
      "mbt::nondetPicks": {}
    },
    {
      "mbt::actionTaken": "begin",
      "mbt::nondetPicks": { "mode": { "tag": "Some", "value": "immediate" } }
    },
    {
      "mbt::actionTaken": "insert",
      "mbt::nondetPicks": { "key": { "tag": "Some", "value": "alice" } }
    },
    {
      "mbt::actionTaken": "opInsertSql",
      "mbt::nondetPicks": {
        "sqlWrite": { "tag": "Some", "value": "INSERT OR REPLACE INTO quint_seed_kv (key, value) VALUES ('x', 7)" }
      }
    },
    {
      "mbt::actionTaken": "opIntegrityCheck",
      "mbt::nondetPicks": {}
    },
    {
      "mbt::actionTaken": "commit",
      "mbt::nondetPicks": {}
    }
  ]
}"#,
        )
        .unwrap();

        let out = parse_json_seed(value).unwrap();
        assert_eq!(
            out.first().unwrap().sql,
            format!(
                "CREATE TABLE IF NOT EXISTS {DEFAULT_TABLE} (key TEXT PRIMARY KEY, value TEXT)"
            )
        );
        assert_eq!(out[1].sql, "BEGIN IMMEDIATE");
        assert!(
            out.iter()
                .any(|stmt| stmt.sql.contains("INSERT OR REPLACE"))
        );
        assert!(out.iter().any(|stmt| stmt.sql == "PRAGMA integrity_check"));
    }

    #[test]
    fn split_sql_preserves_semicolons_in_strings() {
        let stmts =
            split_sql_statements("INSERT INTO t VALUES ('a;b'); SELECT 1; UPDATE t SET v='x'';y';");
        assert_eq!(stmts.len(), 3);
    }
}
