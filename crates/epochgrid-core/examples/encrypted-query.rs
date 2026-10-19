//! Read-only smoke-test inspector. Not installed as an application command.
use anyhow::{Context, Result, ensure};
use epochgrid_core::secrets::{Kind, SecretRef};
use rusqlite::{Connection, OpenFlags, types::Value};
use serde::Deserialize;
use std::{io::Read, path::PathBuf, time::Duration};
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct Request {
    sql: String,
    values: Vec<serde_json::Value>,
}
fn run() -> Result<()> {
    let path = PathBuf::from(std::env::args().nth(1).context("database path required")?);
    let role = path
        .file_stem()
        .context("database name required")?
        .to_str()
        .context("invalid name")?;
    let metadata: serde_json::Value = serde_json::from_slice(&std::fs::read(
        path.with_file_name(format!("{role}.database.json")),
    )?)?;
    let reference: SecretRef = serde_json::from_value(metadata["key"].clone())?;
    ensure!(reference.kind == Kind::Database, "expected database key");
    let key = reference.read()?;
    let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let cipher: String = db.query_row("PRAGMA cipher_version", [], |r| r.get(0))?;
    ensure!(!cipher.is_empty(), "SQLCipher required");
    let raw = Zeroizing::new(format!("x'{}'", key.as_str()));
    // SAFETY: live connection and buffer, both owned by this thread.
    let rc =
        unsafe { rusqlite::ffi::sqlite3_key(db.handle(), raw.as_ptr().cast(), raw.len() as i32) };
    ensure!(rc == rusqlite::ffi::SQLITE_OK, "key configuration failed");
    db.busy_timeout(Duration::ZERO)?;
    db.execute_batch("PRAGMA query_only=ON; PRAGMA temp_store=MEMORY;")?;
    let mut input = String::new();
    std::io::stdin().take(65536).read_to_string(&mut input)?;
    let request: Request = serde_json::from_str(&input)?;
    let values: Vec<Value> = request
        .values
        .into_iter()
        .map(|v| {
            Ok(match v {
                serde_json::Value::String(s) => Value::Text(s),
                serde_json::Value::Number(n) => {
                    Value::Integer(n.as_i64().context("integer parameter required")?)
                }
                serde_json::Value::Null => Value::Null,
                serde_json::Value::Object(o) => Value::Blob(
                    data_encoding::HEXLOWER.decode(
                        o["blob"]
                            .as_str()
                            .context("blob parameter required")?
                            .as_bytes(),
                    )?,
                ),
                _ => anyhow::bail!("unsupported query parameter"),
            })
        })
        .collect::<Result<_>>()?;
    let value: Value = db.query_row(&request.sql, rusqlite::params_from_iter(values), |r| {
        r.get(0)
    })?;
    let result = match value {
        Value::Null => serde_json::Value::Null,
        Value::Integer(n) => n.into(),
        Value::Real(n) => n.into(),
        Value::Text(s) => s.into(),
        Value::Blob(b) => serde_json::json!({"blob": data_encoding::HEXLOWER.encode(&b)}),
    };
    println!("{result}");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        let busy = error
            .downcast_ref::<rusqlite::Error>()
            .and_then(|e| e.sqlite_error())
            .is_some_and(|e| {
                matches!(
                    e.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                )
            });
        eprintln!("{error:#}");
        std::process::exit(if busy { 75 } else { 1 });
    }
}
