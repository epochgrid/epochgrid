//! Sanitized deployment validation. Offline inspection never connects to NATS.
mod online;
use crate::{
    auth_callout::Config,
    database::inspection,
    deployment::DeploymentManifest,
    secrets::{Kind, SecretRef, Vault},
    tls::{Profile, TlsConfig},
};
use anyhow::{Result, ensure};
pub use online::{PermissionMonitor, inspect_resources, online};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Passed,
    Failed,
    NotChecked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub id: String,
    pub status: Status,
    pub required: bool,
    pub expected: Value,
    pub observed: Value,
    pub remediation: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub version: u32,
    pub mode: String,
    pub success: bool,
    pub checks: Vec<Check>,
}
impl Report {
    /// Reject unsupported report versions rather than silently interpreting them.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let report: Self = serde_json::from_slice(bytes)?;
        ensure!(
            report.version == 1 && matches!(report.mode.as_str(), "offline" | "online" | "startup"),
            "unsupported validation report"
        );
        let ids: BTreeSet<_> = report.checks.iter().map(|check| &check.id).collect();
        ensure!(
            ids.len() == report.checks.len() && !report.checks.is_empty(),
            "invalid validation checks"
        );
        ensure!(
            report.success
                == report
                    .checks
                    .iter()
                    .filter(|check| check.required)
                    .all(|check| check.status == Status::Passed),
            "inconsistent validation outcome"
        );
        Ok(report)
    }
    pub fn human(&self) -> String {
        let mut text = format!(
            "{} validation {}.{}\n",
            self.mode,
            if self.success { "passed" } else { "failed" },
            if self.mode == "offline" {
                " Network deployment readiness was NOT evaluated."
            } else {
                " See coverage checks for inspection limits."
            }
        );
        for check in &self.checks {
            let state = match check.status {
                Status::Passed => "PASS",
                Status::Failed => "FAIL",
                Status::NotChecked => "NOT CHECKED",
            };
            text.push_str(&format!("{state} {}: {}\n", check.id, check.observed));
            if let Some(remediation) = &check.remediation {
                text.push_str(&format!("  {remediation}\n"));
            }
        }
        text
    }
    fn check<T>(
        &mut self,
        id: &str,
        expected: &str,
        fallback: &'static str,
        remediation: &str,
        operation: impl FnOnce() -> Result<T>,
    ) -> Option<T> {
        let (value, status, observed, remedy) = match operation() {
            Ok(value) => (Some(value), Status::Passed, json!("valid"), None),
            Err(error) => {
                let (code, advice) = diagnostic(&error, fallback, remediation);
                (None, Status::Failed, json!(code), Some(advice.to_owned()))
            }
        };
        self.checks.push(Check {
            id: id.into(),
            status,
            required: true,
            expected: json!(expected),
            observed,
            remediation: remedy,
        });
        value
    }
    fn skip(&mut self, id: &str, required: bool, reason: &str) {
        self.checks.push(Check {
            id: id.into(),
            status: Status::NotChecked,
            required,
            expected: json!("check completed"),
            observed: json!(reason),
            remediation: required
                .then(|| "Resolve the failed prerequisite and rerun validation.".into()),
        });
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct LocalFailure(&'static str);

// Only typed/static diagnostics enter reports. Never serialize error chains,
// SQLite rows, paths, config values, JWTs, URLs, credential values or private records.
fn diagnostic<'a>(
    error: &anyhow::Error,
    fallback: &'a str,
    remediation: &'a str,
) -> (&'a str, &'a str) {
    if let Some(error) = error.downcast_ref::<crate::secrets::Error>() {
        use crate::secrets::Error;
        return match error {
            Error::Missing => (
                "credential_missing",
                "Restore the original keyring item; validation never regenerates established credentials.",
            ),
            Error::Locked => (
                "keyring_locked",
                "Unlock the backend account's Secret Service keyring, then retry.",
            ),
            Error::Duplicate => (
                "credential_duplicate",
                "Resolve duplicate items with the backend account's keyring manager, then retry.",
            ),
            Error::Binding => (
                "credential_binding_mismatch",
                "Restore the matching original credential and public metadata; do not replace keys.",
            ),
            Error::Unavailable => (
                "keyring_unavailable",
                "Run under the backend Linux account with its provisioned Secret Service session.",
            ),
            Error::Timeout => (
                "keyring_timeout",
                "Check the backend Secret Service session; the credential operation timed out.",
            ),
            Error::Backend => (
                "keyring_denied",
                "Check keyring access for the backend Linux account.",
            ),
        };
    }
    if let Some(error) = error.downcast_ref::<inspection::InspectionError>() {
        let advice = match error {
            inspection::InspectionError::Plaintext => {
                "Legacy plaintext is unsupported. Preserve the original state and use fresh enrollment; validation does not migrate it."
            }
            inspection::InspectionError::Incomplete => {
                "Initialization is incomplete. Review the setup state and retry the original auth-init command only for an interrupted fresh setup."
            }
            inspection::InspectionError::Busy => {
                "Retry after the current database transaction completes; validation did not repair or modify state."
            }
            inspection::InspectionError::Schema => {
                "Use a compatible binary and complete setup separately; validation never runs migrations."
            }
            _ => {
                "Restore matching encrypted state, public metadata and keyring from the same installation; validation never repairs or resets state."
            }
        };
        return (error.code(), advice);
    }
    if let Some(error) = error.downcast_ref::<LocalFailure>() {
        return (error.0, remediation);
    }
    if error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        return ("state_missing", remediation);
    }
    (fallback, remediation)
}

fn private_path(path: &Path, directory: bool) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink()
            && if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            },
        LocalFailure("unsafe_file_type")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            metadata.uid() == rustix::process::getuid().as_raw(),
            LocalFailure("wrong_file_owner")
        );
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            LocalFailure("permissions_too_open")
        );
        let required = if directory { 0o500 } else { 0o400 };
        ensure!(
            metadata.permissions().mode() & required == required,
            LocalFailure("permissions_insufficient")
        );
    }
    Ok(())
}

fn files(report: &mut Report, root: &Path, role: &str, prefix: &str) -> bool {
    let mut valid = true;
    for (suffix, name) in [
        ("credentials", "credentials.json".into()),
        ("metadata", format!("{role}.database.json")),
        ("database", format!("{role}.sqlite")),
    ] {
        let path = root.join(name);
        let passed = report.check(&format!("local.permissions.{prefix}.{suffix}"), "existing owner-only regular file", "file_permissions_invalid", "Restore missing original state or restrict file access to the backend account (0600); do not initialize over existing state.", || private_path(&path, false)).is_some();
        // Missing inputs are safe to inspect: the non-initializing paths return
        // specific missing/plaintext errors. Unsafe existing files are not read.
        valid &= passed
            || matches!(std::fs::symlink_metadata(&path), Err(error) if error.kind() == std::io::ErrorKind::NotFound);
    }
    for extension in ["wal", "shm", "journal"] {
        let path = root.join(format!("{role}.sqlite-{extension}"));
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => {
                valid &= report.check(&format!("local.permissions.{prefix}.{extension}"), "owner-only SQLite sidecar", "sidecar_permissions_invalid", "Restrict SQLite sidecar access to the backend account; never delete live WAL/SHM files.", || private_path(&path, false)).is_some();
            }
        }
    }
    valid
}

pub fn offline(home: &Path, auth_config: &Path, endpoint: Option<&str>) -> Report {
    let mut report = Report {
        version: 1,
        mode: "offline".into(),
        success: false,
        checks: Vec::new(),
    };
    let home_ok = report.check("local.home", "existing owner-only backend directory", "home_invalid", "Select the established backend home and run as its owner; use 0700 directory permissions. Initialize a fresh home separately if needed.", || private_path(home, true)).is_some();
    let config = if home_ok {
        report.check("local.auth_config", "supported complete version-2 authentication configuration in backend home", "auth_config_invalid", "Review auth.json and its permissions. Operator mode requires a current signed non-bearer service JWT; validation does not complete setup.", || {
            private_path(auth_config, false)?;
            let parent = auth_config.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."));
            ensure!(parent.canonicalize()? == home.canonicalize()?, LocalFailure("auth_config_location"));
            let config = Config::load_for_export(auth_config)?;
            ensure!(!config.operator_jwt.as_ref().is_some_and(|operator| operator.connection_jwt.is_empty()), LocalFailure("operator_setup_incomplete"));
            Ok(config)
        })
    } else {
        report.skip("local.auth_config", true, "backend home unavailable");
        None
    };
    if home_ok {
        let manifest = report.check("local.deployment_manifest", "version-1 manifest with explicit replicas 1 or 3", "deployment_manifest_invalid", "Run deployment-export with explicit --replicas 1 or 3 for an existing M26 home; preserve established deployment choices.", || {
            let path = home.join(crate::deployment::MANIFEST_FILE);
            private_path(&path, false)?;
            Ok(serde_json::from_slice::<DeploymentManifest>(&std::fs::read(path)?)?)
        });
        if let Some(manifest) = manifest {
            report.checks.last_mut().unwrap().observed =
                json!({"version":1,"replicas":manifest.replicas()});
        }
    } else {
        report.skip(
            "local.deployment_manifest",
            true,
            "backend home unavailable",
        );
    }
    let auth_files = home_ok && files(&mut report, home, "auth", "auth");
    let control_root = home.join("control");
    let control_ok = if home_ok {
        report
            .check(
                "local.control_home",
                "existing owner-only control directory",
                "control_home_invalid",
                "Restore the original control home and use backend-owned 0700 permissions.",
                || private_path(&control_root, true),
            )
            .is_some()
    } else {
        report.skip("local.control_home", true, "backend home unavailable");
        false
    };
    let control_files = control_ok && files(&mut report, &control_root, "identity", "control");
    let mut references = Vec::<SecretRef>::new();
    for (id, root, role, kind, ready) in [
        ("issuer", home, "issuer", Kind::Account, auth_files),
        ("encryption", home, "encryption", Kind::XKey, auth_files),
        ("connection", home, "connection", Kind::User, auth_files),
        (
            "auth_database",
            home,
            "database-auth",
            Kind::Database,
            auth_files,
        ),
        (
            "control",
            control_root.as_path(),
            "device",
            Kind::User,
            control_files,
        ),
        (
            "control_database",
            control_root.as_path(),
            "database-identity",
            Kind::Database,
            control_files,
        ),
    ] {
        let check_id = format!("local.credentials.{id}");
        if ready {
            if let Some(reference) = report.check(&check_id, "established credential with matching role and public binding", "credential_invalid", "Restore the matching original credential metadata and keyring; validation cannot provision missing keys.", || {
                let reference = Vault::new(root).existing(role, kind)?;
                if let Some(config) = &config {
                    let expected = match id { "issuer" => Some(&config.issuer), "encryption" => Some(&config.encryption), "connection" => Some(&config.connection), _ => None };
                    ensure!(expected.is_none_or(|expected| expected == &reference), LocalFailure("credential_binding_mismatch"));
                    if id == "control" { ensure!(reference.public_key == config.control_nkey, LocalFailure("control_identity_mismatch")); }
                }
                Ok(reference)
            }) { references.push(reference); }
        } else {
            report.skip(&check_id, true, "credential files unavailable or unsafe");
        }
    }
    if references.len() == 6 {
        report.check("local.credentials.independent", "six independent credential IDs and public bindings", "credential_reuse", "Restore independent role credentials from the original installation; do not generate replacements.", || {
            ensure!(references.iter().map(|r| &r.id).collect::<BTreeSet<_>>().len() == 6 && references.iter().map(|r| &r.public_key).collect::<BTreeSet<_>>().len() == 6, LocalFailure("credential_reuse"));
            Ok(())
        });
    } else {
        report.skip(
            "local.credentials.independent",
            true,
            "one or more credentials unavailable",
        );
    }
    if auth_files {
        report.check("local.database.auth", "encrypted bound auth database, schema 2, integrity valid", "database_inspection_failed", "Restore matching encrypted database, metadata and keyring; validation does not migrate or reset state.", || inspection::auth(home));
    } else {
        report.skip(
            "local.database.auth",
            true,
            "auth database files unavailable or unsafe",
        );
    }
    if control_files && config.is_some() {
        report.check("local.database.control", "encrypted bound control database, schema 8/OpenMLS 6, signed service identity", "database_inspection_failed", "Restore matching control state and credentials; validation does not migrate or initialize identity.", || inspection::control(&control_root, &config.as_ref().unwrap().control_nkey));
    } else {
        report.skip(
            "local.database.control",
            true,
            "control files or valid auth configuration unavailable",
        );
    }
    let tls = report.check("local.transport.inputs", "valid TLS profile and nonempty usable trust roots", "tls_inputs_invalid", "Review EPOCHGRID_PROFILE, EPOCHGRID_TLS_CA_PATH, EPOCHGRID_TLS_MIN_VERSION and EPOCHGRID_TLS_FIRST; provide a valid CA bundle.", || {
        let tls = TlsConfig::from_env()?;
        tls.validate_local()?;
        if let Some(config) = &config { ensure!(!config.development_plaintext || tls.profile == Profile::Development, LocalFailure("development_transport_in_production")); }
        Ok(tls)
    });
    if let Some(endpoint) = endpoint {
        if let (Some(tls), Some(config)) = (&tls, &config) {
            report.check("local.transport.endpoint", "valid credential-free endpoint allowed by the shared TLS policy", "endpoint_invalid", "Supply a verified tls:// endpoint without embedded credentials; no connection was attempted.", || {
                tls.validate_endpoint(endpoint)?;
                config.check_transport(endpoint)
            });
        } else {
            report.skip(
                "local.transport.endpoint",
                true,
                "TLS inputs or auth configuration unavailable",
            );
        }
    } else {
        report.skip(
            "local.transport.endpoint",
            false,
            "no endpoint supplied; transport reachability and server identity are not evaluated",
        );
    }
    report.skip("coverage.network", false, "offline mode: NATS authentication, JetStream resources, replicas and deployment readiness were not evaluated");
    report.skip("coverage.operator", false, "route TLS, account isolation, signer delegation, resolver lifecycle and capacity require operator/online checks");
    report.success = report
        .checks
        .iter()
        .filter(|check| check.required)
        .all(|check| check.status == Status::Passed);
    report
}

#[cfg(test)]
mod tests;
