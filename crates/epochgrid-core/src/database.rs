//! All persistent SQLite connections must pass through this module.
use crate::secrets::{Kind, SecretRef, Vault, private_file, save};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path, time::Duration};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    role: String,
    key: SecretRef,
    ready: bool,
}

/// Reject old plaintext state before even creating provisioning metadata.
pub(crate) fn reject_plaintext(path: &Path) -> Result<()> {
    match path.metadata() {
        Ok(meta) if meta.len() == 0 => return Ok(()),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    // Closing ANY ordinary fd for this inode can release the process's POSIX
    // locks, including locks owned by other SQLite handles. SQLite coordinates
    // deferred closes across its own connections; use its read-only probe.
    let probe = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    probe.busy_timeout(Duration::from_secs(1))?;
    match probe.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| {
        r.get::<_, u64>(0)
    }) {
        Ok(_) => return Err(inspection::InspectionError::Plaintext.into()),
        Err(e) if e.sqlite_error_code() == Some(rusqlite::ErrorCode::NotADatabase) => {}
        Err(e) => return Err(e).context("could not inspect database format without modification"),
    }
    Ok(())
}

pub(crate) fn open(root: &Path, role: &str) -> Result<Connection> {
    ensure!(matches!(role, "identity" | "auth"), "invalid database role");
    let path = root.join(format!("{role}.sqlite"));
    reject_plaintext(&path)?;
    std::fs::create_dir_all(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    // Held only during open/provisioning, not for the connection lifetime.
    let lock = private_file(&root.join(format!("{role}.database.lock")), false)?;
    lock.try_lock()
        .context("database initialization/open already in progress; retry")?;
    reject_plaintext(&path)?;
    let state_path = root.join(format!("{role}.database.json"));
    let mut state: State = match std::fs::read(&state_path) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("invalid database metadata")?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ensure!(
                !path.exists(),
                "database metadata missing; restore original metadata and keyring; database was not changed"
            );
            let key = Vault::new(root).provision(&format!("database-{role}"), Kind::Database)?;
            let state = State {
                version: 1,
                role: role.into(),
                key,
                ready: false,
            };
            // Must reach disk before any database file is created.
            save(&state_path, &state)?;
            state
        }
        Err(e) => return Err(e.into()),
    };
    ensure!(
        state.version == 1 && state.role == role && state.key.kind == Kind::Database,
        "unsupported or mismatched database metadata"
    );
    if state.ready {
        ensure!(
            path.metadata().map(|m| m.len() > 0).unwrap_or(false),
            "established database is missing or empty; restore original database; refusing reset"
        );
    }
    let key = state.key.read()?;
    // Restrictive permissions from creation, before SQLite opens the file.
    if !path.exists() {
        let file = private_file(&path, false)?;
        file.sync_all()?;
        File::open(root)?.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    let db = keyed(&path, &key)?;
    let binding: Option<(u32, String, String)> = if db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='database_binding')",
        [],
        |r| r.get::<_, bool>(0),
    )? {
        db.query_row(
            "SELECT version,role,key_id FROM database_binding WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
    } else {
        None
    };
    match binding {
        Some((version, stored_role, id)) => ensure!(
            version == 1 && stored_role == role && id == state.key.id,
            "database binding mismatch; restore matching metadata and keyring"
        ),
        None => {
            ensure!(!state.ready, "database binding missing; refusing reset");
            let count: u64 =
                db.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get(0))?;
            ensure!(
                count == 0,
                "unrecognized database schema; refusing initialization"
            );
            db.execute_batch("BEGIN IMMEDIATE; CREATE TABLE database_binding(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,role TEXT NOT NULL,key_id TEXT NOT NULL);")?;
            db.execute(
                "INSERT INTO database_binding VALUES(1,1,?1,?2)",
                params![role, state.key.id],
            )?;
            db.execute_batch("COMMIT")?;
        }
    }
    if !state.ready {
        state.ready = true;
        save(&state_path, &state)?;
    }
    Ok(db)
}

fn keyed(path: &Path, key: &str) -> Result<Connection> {
    keyed_with_flags(path, key, OpenFlags::SQLITE_OPEN_READ_WRITE)
}

fn keyed_with_flags(path: &Path, key: &str, flags: OpenFlags) -> Result<Connection> {
    let db = Connection::open_with_flags(path, flags)?;
    let cipher: String = db
        .query_row("PRAGMA cipher_version", [], |r| r.get(0))
        .context("SQLCipher is required; refusing unencrypted SQLite")?;
    ensure!(!cipher.is_empty(), "SQLCipher unavailable");
    // Configure a raw key without placing secret material in SQL or error text.
    let raw = Zeroizing::new(format!("x'{key}'"));
    // SAFETY: live, exclusively borrowed connection; valid buffer during this call.
    let rc =
        unsafe { rusqlite::ffi::sqlite3_key(db.handle(), raw.as_ptr().cast(), raw.len() as i32) };
    ensure!(
        rc == rusqlite::ffi::SQLITE_OK,
        "could not configure database encryption"
    );
    db.busy_timeout(Duration::from_secs(1))?;
    db.execute_batch("PRAGMA temp_store=MEMORY; PRAGMA cipher_memory_security=ON;")?;
    if flags.contains(OpenFlags::SQLITE_OPEN_READ_ONLY) {
        // SQLite owns all WAL/SHM handling. Never use immutable mode or ordinary
        // descriptors for database contents, even for the format probe.
        db.execute_batch("PRAGMA query_only=ON; BEGIN;")?;
    }
    db.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get::<_, u64>(0))
        .context("database cannot be decrypted or is corrupt; restore matching database, metadata and keyring")?;
    Ok(db)
}

pub(crate) mod inspection;

#[cfg(test)]
mod tests;
