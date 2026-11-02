//! Existing-state inspection: no provisioning, schema migration or data writes.
use super::*;
use crate::identity;

#[derive(Debug, thiserror::Error)]
pub(crate) enum InspectionError {
    #[error("established database is missing or empty")]
    Missing,
    #[error("database metadata is missing")]
    MetadataMissing,
    #[error("database metadata has an unsupported version or wrong role/key type")]
    MetadataInvalid,
    #[error("initialization is incomplete")]
    Incomplete,
    #[error("database credential does not match the established vault role")]
    CredentialBinding,
    #[error(
        "pre-Milestone-25 plaintext database is unsupported; use fresh state and enrollment (original database was not changed)"
    )]
    Plaintext,
    #[error("database cannot be decrypted or is corrupt")]
    Unreadable,
    #[error("database binding is missing or mismatched")]
    Binding,
    #[error("schema is incomplete, unsupported, or requires migration")]
    Schema,
    #[error("database integrity check failed")]
    Integrity,
    #[error("database inspection is busy; retry after the active transaction")]
    Busy,
    #[error(
        "control identity does not match its signed registration, credentials or configuration"
    )]
    ControlBinding,
}
impl InspectionError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Missing => "database_missing",
            Self::MetadataMissing => "database_metadata_missing",
            Self::MetadataInvalid => "database_metadata_invalid",
            Self::Incomplete => "initialization_incomplete",
            Self::CredentialBinding => "credential_binding_mismatch",
            Self::Plaintext => "plaintext_database",
            Self::Unreadable => "database_unreadable",
            Self::Binding => "database_binding_mismatch",
            Self::Schema => "schema_unsupported",
            Self::Integrity => "database_integrity_failed",
            Self::Busy => "database_busy",
            Self::ControlBinding => "control_identity_mismatch",
        }
    }
}

fn sql_error(error: anyhow::Error, fallback: InspectionError) -> anyhow::Error {
    if error
        .downcast_ref::<rusqlite::Error>()
        .is_some_and(|error| {
            matches!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
            )
        })
    {
        InspectionError::Busy.into()
    } else {
        fallback.into()
    }
}

pub(crate) fn inspect(root: &Path, role: &str) -> Result<Connection> {
    ensure!(
        matches!(role, "identity" | "auth"),
        InspectionError::MetadataInvalid
    );
    let path = root.join(format!("{role}.sqlite"));
    ensure!(
        path.metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0),
        InspectionError::Missing
    );
    reject_plaintext(&path).map_err(|error| {
        if error.downcast_ref::<InspectionError>().is_some() {
            error
        } else {
            sql_error(error, InspectionError::Unreadable)
        }
    })?;
    let bytes = std::fs::read(root.join(format!("{role}.database.json"))).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            InspectionError::MetadataMissing
        } else {
            InspectionError::MetadataInvalid
        }
    })?;
    let state: State =
        serde_json::from_slice(&bytes).map_err(|_| InspectionError::MetadataInvalid)?;
    ensure!(
        state.version == 1 && state.role == role && state.key.kind == Kind::Database,
        InspectionError::MetadataInvalid
    );
    ensure!(state.ready, InspectionError::Incomplete);
    let reference = Vault::new(root).existing(&format!("database-{role}"), Kind::Database)?;
    ensure!(reference == state.key, InspectionError::CredentialBinding);
    let key = state.key.read()?;
    let db = keyed_with_flags(&path, &key, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| sql_error(error, InspectionError::Unreadable))?;
    let binding = (|| -> Result<(u32, String, String)> {
        let count: u64 = db.query_row("SELECT COUNT(*) FROM database_binding", [], |row| {
            row.get(0)
        })?;
        ensure!(count == 1, InspectionError::Binding);
        Ok(db.query_row(
            "SELECT version,role,key_id FROM database_binding WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?)
    })()
    .map_err(|_| InspectionError::Binding)?;
    ensure!(
        binding == (1, role.into(), state.key.id),
        InspectionError::Binding
    );
    // Never include SQLite's diagnostic rows: they may contain application data.
    let integrity: String = db
        .query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))
        .map_err(|error| sql_error(error.into(), InspectionError::Integrity))?;
    ensure!(integrity == "ok", InspectionError::Integrity);
    let mut cipher = db.prepare("PRAGMA cipher_integrity_check")?;
    ensure!(
        cipher.query([])?.next()?.is_none(),
        InspectionError::Integrity
    );
    drop(cipher);
    let mut foreign_keys = db.prepare("PRAGMA foreign_key_check")?;
    ensure!(
        foreign_keys.query([])?.next()?.is_none(),
        InspectionError::Integrity
    );
    drop(foreign_keys);
    Ok(db)
}

fn schema(db: &Connection, table: &str, latest: u32, projections: &[(&str, &str)]) -> Result<()> {
    let result = (|| -> Result<()> {
        let mut statement = db.prepare(&format!("SELECT version FROM {table} ORDER BY version"))?;
        let versions = statement
            .query_map([], |row| row.get::<_, u32>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(
            versions == (1..=latest).collect::<Vec<_>>(),
            InspectionError::Schema
        );
        for (table, columns) in projections {
            let object_type: String = db.query_row(
                "SELECT type FROM sqlite_master WHERE name=?1",
                [table],
                |row| row.get(0),
            )?;
            ensure!(object_type == "table", InspectionError::Schema);
            db.prepare(&format!("SELECT {columns} FROM {table} LIMIT 0"))?;
        }
        Ok(())
    })();
    result.map_err(|error| sql_error(error, InspectionError::Schema))
}

pub(crate) fn auth(root: &Path) -> Result<()> {
    let db = inspect(root, "auth")?;
    schema(
        &db,
        "auth_migrations",
        3,
        &[
            (
                "audit_state",
                "store_id,next_sequence,retained_from,events,bytes,gaps,policy_version,prune_through,degraded",
            ),
            ("audit_events", "sequence,payload"),
            ("audit_pending", "kind,operation"),
            ("users", "id,enabled,audit_ref"),
            ("identity_bindings", "provider,subject,user_id"),
            ("enrollment_tokens", "digest,user_id,expires,used_key"),
            (
                "devices",
                "nkey,user_id,device_id,registration,ready,revoked,authorization_generation,audit_ref",
            ),
            (
                "authorization_groups",
                "gid,generation,epoch,coordinator,last_update,audit_ref",
            ),
            ("authorization_members", "gid,nkey,leaf"),
        ],
    )
}

pub(crate) fn control(root: &Path, expected: &str) -> Result<()> {
    let db = inspect(root, "identity")?;
    schema(
        &db,
        "epochgrid_migrations",
        8,
        &[
            ("local_identity", "id,secret_ref,registration"),
            ("groups", "name,gid,mls_id"),
            ("outbox", "id,subject,payload,sent"),
            ("welcomes", "payload,name"),
            ("received", "payload"),
            ("chat_deliveries", "sequence,subject,payload,state"),
            (
                "transcript",
                "id,gid,payload,sender,plaintext,outgoing,stream_sequence,displayed",
            ),
            ("group_join_epochs", "gid,epoch"),
            (
                "device_trust",
                "user,device,fingerprint,latest_fingerprint,state",
            ),
            ("transparency_state", "id,signer,checkpoint"),
            ("trust_alert", "id,message"),
            ("revoked_devices", "nkey,user,device,mls_key,cutoff"),
            ("group_coordinators", "gid,mls_key"),
            ("blocked_outbox", "id"),
            ("revocation_checkpoint", "id,checkpoint"),
            ("recovery_metadata", "id,metadata"),
            ("attachments", "gid,object_id,manifest"),
            ("receipt_messages", "transcript_id,gid,reference"),
            ("device_receipts", "transcript_id,device,state"),
            (
                "message_events",
                "transcript_id,gid,message_id,target,kind,counter,event",
            ),
            ("participant_events", "gid,message_id"),
        ],
    )?;
    schema(
        &db,
        "openmls_sqlite_storage_migrations",
        6,
        &[
            (
                "openmls_encryption_keys",
                "provider_version,public_key,key_pair",
            ),
            (
                "openmls_epoch_keys_pairs",
                "provider_version,group_id,epoch_id,leaf_index,key_pairs",
            ),
            (
                "openmls_group_data",
                "provider_version,group_id,data_type,group_data",
            ),
            (
                "openmls_key_packages",
                "provider_version,key_package_ref,key_package",
            ),
            (
                "openmls_own_leaf_nodes",
                "provider_version,id,group_id,leaf_node",
            ),
            (
                "openmls_proposals",
                "provider_version,group_id,proposal_ref,proposal",
            ),
            ("openmls_psks", "provider_version,psk_id,psk_bundle"),
            (
                "openmls_signature_keys",
                "provider_version,public_key,signature_key",
            ),
            (
                "vc_emulation_group_secrets",
                "provider_version,epoch_id,secret_type,vc_secret",
            ),
            (
                "vc_emulation_bindings",
                "provider_version,group_id,bindings",
            ),
            (
                "vc_operation_trees",
                "provider_version,epoch_id,operation_tree",
            ),
            (
                "vc_retained_key_package_material",
                "provider_version,key_package_ref,epoch_id,record",
            ),
            (
                "registered_vc_emulation_epochs",
                "provider_version,group_id,registration",
            ),
        ],
    )?;
    let count: u64 = db.query_row("SELECT COUNT(*) FROM local_identity", [], |row| row.get(0))?;
    ensure!(count == 1, InspectionError::Incomplete);
    let (encoded, bytes): (String, Vec<u8>) = db
        .query_row(
            "SELECT secret_ref,registration FROM local_identity WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| InspectionError::ControlBinding)?;
    let reference: SecretRef =
        serde_json::from_str(&encoded).map_err(|_| InspectionError::ControlBinding)?;
    let registration: crate::wire::DeviceRegistration =
        postcard::from_bytes(&bytes).map_err(|_| InspectionError::ControlBinding)?;
    identity::verify_signature(&registration).map_err(|_| InspectionError::ControlBinding)?;
    ensure!(
        reference == Vault::new(root).existing("device", Kind::User)?
            && reference.public_key == expected
            && registration.payload.nats_public_key == expected
            && registration.payload.user_id == "service"
            && registration.payload.device_id == "laptop",
        InspectionError::ControlBinding
    );
    Ok(())
}
