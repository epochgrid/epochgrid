//! Offline setup and public, no-clobber deployment artifact publication.
use anyhow::{Context, Result, ensure};
use clap::{Args, ValueEnum};
use epochgrid_core::{
    auth_callout::{Config, OperatorJwt},
    deployment::{DeploymentManifest, MANIFEST_FILE},
    identity::IdentityStore,
    identity_model::AuthRegistry,
    secrets::{Kind, Vault},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io::Write, path::Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMode {
    Configuration,
    OperatorJwt,
}

#[derive(Clone, Debug, PartialEq, Eq, Args, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitOptions {
    #[arg(long, value_enum, default_value = "configuration")]
    pub auth_mode: AuthMode,
    /// Application account name (configuration) or public account NKey (operator JWT).
    #[arg(long)]
    pub target_account: Option<String>,
    /// Authentication account public NKey; required only in operator-JWT mode.
    #[arg(long)]
    pub auth_account: Option<String>,
    #[arg(long, default_value_t = 1)]
    pub replicas: usize,
}

impl InitOptions {
    fn target(&self) -> &str {
        self.target_account.as_deref().unwrap_or("EPOCHGRID")
    }
    fn validate(&self) -> Result<DeploymentManifest> {
        let manifest = DeploymentManifest::bounded(
            self.replicas,
            epochgrid_core::capacity::Capacity::default(),
        )?;
        match self.auth_mode {
            AuthMode::Configuration => {
                ensure!(
                    self.auth_account.is_none(),
                    "--auth-account is only for operator-jwt mode"
                );
                let name = self.target();
                ensure!(
                    nkeys::KeyPair::from_seed(name).is_err()
                        && nkeys::XKey::from_seed(name).is_err(),
                    "target account must be a public account name, never a seed"
                );
                ensure!(
                    !name.is_empty()
                        && name.len() <= 64
                        && name
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'),
                    "invalid target account name"
                );
                ensure!(
                    name != "EPOCHGRID_AUTH",
                    "authentication and application accounts must be separate"
                );
            }
            AuthMode::OperatorJwt => {
                let target = self
                    .target_account
                    .as_deref()
                    .context("operator-jwt requires --target-account PUBLIC_ACCOUNT_NKEY")?;
                let auth = self
                    .auth_account
                    .as_deref()
                    .context("operator-jwt requires --auth-account PUBLIC_ACCOUNT_NKEY")?;
                for key in [target, auth] {
                    ensure!(
                        nkeys::KeyPair::from_public_key(key)
                            .is_ok_and(|key| key.key_pair_type() == nkeys::KeyPairType::Account),
                        "operator-jwt requires public account NKeys, never seeds"
                    );
                }
                ensure!(
                    target != auth,
                    "authentication and application accounts must be separate"
                );
            }
        }
        Ok(manifest)
    }
}

fn private_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "setup directory must not be a symlink"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn lock(home: &Path) -> Result<fs::File> {
    let path = home.join("auth-init.lock");
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "setup lock must be a regular file"
        );
    }
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    file.try_lock()
        .context("authentication initialization/export already in progress")?;
    Ok(file)
}

/// Validate before publishing anything. Symlinks and changed operator files fail.
fn same_or_absent(path: &Path, bytes: &[u8]) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "artifact must be a regular file: {}",
                path.display()
            );
            ensure!(
                fs::read(path)? == bytes,
                "refusing to overwrite changed artifact: {}; choose a new --output directory for exported artifacts",
                path.display()
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Atomic publication without replacing even a concurrently created destination.
fn publish_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if same_or_absent(path, bytes)? {
        return Ok(());
    }
    let parent = path.parent().context("artifact parent required")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)
        .map_err(|_| anyhow::anyhow!("artifact publication conflict: {}", path.display()))?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn bundle_matches(output: &Path, artifacts: &BTreeMap<String, String>) -> Result<bool> {
    match fs::symlink_metadata(output) {
        Ok(metadata) => {
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "artifact output must be a directory"
            );
            ensure!(
                fs::read_dir(output)?.count() == artifacts.len(),
                "artifact bundle differs; choose a new --output directory"
            );
            for (name, bytes) in artifacts {
                ensure!(
                    same_or_absent(&output.join(name), bytes.as_bytes())?,
                    "artifact bundle incomplete; choose a new --output directory"
                );
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn publish_bundle(output: &Path, artifacts: &BTreeMap<String, String>) -> Result<()> {
    if bundle_matches(output, artifacts)? {
        return Ok(());
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure!(parent.is_dir(), "artifact output parent must already exist");
    let staging = tempfile::Builder::new()
        .prefix(".epochgrid-artifacts-")
        .tempdir_in(parent)?;
    private_directory(staging.path())?;
    for (name, bytes) in artifacts {
        publish_file(&staging.path().join(name), bytes.as_bytes())?;
    }
    fs::File::open(staging.path())?.sync_all()?;
    // A bundle appears only after all files have been flushed. The home lock
    // serializes cooperating exporters; an existing edited bundle is never used.
    ensure!(
        !output.try_exists()?,
        "artifact output appeared during export"
    );
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staging.path(),
        rustix::fs::CWD,
        output,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .context("artifact output appeared during export; nothing was replaced")?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn artifacts(config: &Config, manifest: &DeploymentManifest) -> Result<BTreeMap<String, String>> {
    InitOptions {
        auth_mode: if config.operator_jwt.is_some() {
            AuthMode::OperatorJwt
        } else {
            AuthMode::Configuration
        },
        target_account: Some(config.target_account.clone()),
        auth_account: config
            .operator_jwt
            .as_ref()
            .map(|operator| operator.auth_account.clone()),
        replicas: manifest.replicas(),
    }
    .validate()?;
    let mut artifacts = manifest.artifacts()?;
    let guide = if let Some(operator) = &config.operator_jwt {
        artifacts.insert(
            "operator-delegation.json".into(),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&serde_json::json!({
                    "version": 1,
                    "authentication_account": operator.auth_account,
                    "application_account": config.target_account,
                    "external_authorization": {
                        "auth_users": [config.connection.public_key],
                        "allowed_accounts": [config.target_account],
                        "xkey": config.encryption.public_key
                    },
                    "application_signing_keys": [config.issuer.public_key],
                    "service_user": {
                        "subject": config.connection.public_key,
                        "bearer_token": false,
                        "subscribe": ["$SYS.REQ.USER.AUTH", "_INBOX.>"],
                        "publish": ["$SYS._INBOX.>"]
                    }
                }))?
            ),
        );
        "Operator-JWT mode: setup is INCOMPLETE until you issue a signed non-bearer service user JWT for the public connection key in operator-delegation.json and set auth.json.operator_jwt.connection_jwt. Runtime refuses an empty JWT; do not remove operator_jwt to bypass this. Apply external_authorization to the authentication account JWT's nats.authorization and application_signing_keys as unscoped application-account nats.signing_keys. Sign and distribute both account JWTs using your external administration tooling. Configure the operator, system account, resolver and deny-all authentication-account default_sentinel on every server. Never give EpochGrid operator/account root seeds or system-account credentials. The delegation JSON is a public signing specification, not itself a signed JWT."
    } else {
        let snippet = format!(
            r#"# Reference only: integrate with operator-owned configuration; do not replace it.
# Add operator-managed TLS and JetStream. No static device users.
accounts {{
  EPOCHGRID_AUTH {{ users: [{{nkey: "{}", permissions: {{subscribe: ["$SYS.REQ.USER.AUTH", "_INBOX.>"], publish: ["$SYS._INBOX.>"]}}}}] }}
  "{}" {{ jetstream: enabled }}
}}
authorization {{
  timeout: 2
  auth_callout {{ issuer: "{}", xkey: "{}", account: EPOCHGRID_AUTH, auth_users: ["{}"], allowed_accounts: ["{}"] }}
}}
"#,
            config.connection.public_key,
            config.target_account,
            config.issuer.public_key,
            config.encryption.public_key,
            config.connection.public_key,
            config.target_account
        );
        artifacts.insert("nats-reference.conf".into(), snippet);
        "Configuration mode: integrate nats-reference.conf into your operator-owned NATS configuration. Keep EPOCHGRID_AUTH separate from the application account. Supply your own application-account administrator for resource provisioning; the snippet does not issue administrator credentials."
    };
    artifacts.insert("SETUP.md".into(), format!("# EpochGrid public deployment artifacts\n\nArtifact publication complete; deployment readiness has NOT been evaluated.\n\n{guide}\n\nSupply TLS certificates and verified tls:// endpoints, EPOCHGRID_TLS_CA_PATH when using a private CA, and mutual TLS on cluster routes. NATS Server 2.14.5 is the qualified target; configure server max_payload exactly 65536. Do not import/export application or Auth Callout subjects to other accounts.\n\nUsing your application's administrative NATS context, apply each native stream configuration (including KV backing streams):\n\n```sh\nfor resource in CHAT MAILBOX KV_IDENTITIES KV_CHANNELS KV_TRANSPARENCY; do\n  nats --context APPLICATION_ADMIN stream add --config \"$resource.json\"\ndone\n```\n\nSet storage budgets for your workload before applying resources. Matching configuration does not certify capacity. Review existing resources instead of overwriting them. All five resources declare R{}. Keep deployment.json beside auth.json. Resource ownership and root signing keys remain with the operator. See docs/operator/byo-nats.md for the complete account/JWT and transport contract.\n", manifest.replicas()));
    Ok(artifacts)
}

pub fn initialize(home: &Path, options: &InitOptions) -> Result<()> {
    // Validate every operator choice before any directory, database or secret is created.
    let manifest = options.validate()?;
    ensure!(
        !home.join("auth.json").try_exists()?,
        "authentication configuration already exists"
    );
    ensure!(
        !["issuer.seed", "encryption.seed", "auth.seed"]
            .iter()
            .any(|name| home.join(name).exists()),
        "pre-Milestone-24 backend is unsupported; choose a fresh home"
    );
    private_directory(home)?;
    let _lock = lock(home)?;
    ensure!(
        !home.join("auth.json").try_exists()?,
        "authentication configuration already exists"
    );
    // Persist choices before secrets. Retries cannot silently change mode/accounts/R3.
    publish_file(
        &home.join("auth-init.json"),
        &serde_json::to_vec_pretty(options)?,
    )?;
    publish_file(
        &home.join(epochgrid_core::capacity::FILE),
        format!(
            "{}\n",
            serde_json::to_string_pretty(manifest.capacity().context("capacity missing")?)?
        )
        .as_bytes(),
    )?;
    AuthRegistry::open(home)?;
    let vault = Vault::new(home);
    let issuer = vault.provision("issuer", Kind::Account)?;
    let encryption = vault.provision("encryption", Kind::XKey)?;
    let connection = vault.provision("connection", Kind::User)?;
    let mut control = IdentityStore::open(&home.join("control"))?;
    if control.registration().is_err() {
        control.init("service", "laptop")?;
    }
    let config = Config {
        version: 2,
        issuer,
        encryption,
        connection,
        target_account: options.target().into(),
        control_nkey: control.nkey()?.public_key(),
        authorization_ttl_seconds: 30,
        development_plaintext: false,
        operator_jwt: options
            .auth_account
            .as_ref()
            .map(|auth_account| OperatorJwt {
                auth_account: auth_account.clone(),
                connection_jwt: String::new(),
            }),
    };
    let artifacts = artifacts(&config, &manifest)?;
    // Keep the established replica manifest stable; capacity.json is the
    // independently versioned, atomically replaceable capacity contract.
    let local_manifest = format!(
        "{}\n",
        serde_json::to_string_pretty(&DeploymentManifest::new(manifest.replicas())?)?
    );
    let manifest_bytes = local_manifest.as_bytes();
    same_or_absent(&home.join(MANIFEST_FILE), manifest_bytes)?;
    if let Some(snippet) = artifacts.get("nats-reference.conf") {
        same_or_absent(&home.join("nats-reference.conf"), snippet.as_bytes())?;
    }
    publish_bundle(&home.join("deployment-artifacts"), &artifacts)?;
    if let Some(snippet) = artifacts.get("nats-reference.conf") {
        publish_file(&home.join("nats-reference.conf"), snippet.as_bytes())?;
    }
    publish_file(&home.join(MANIFEST_FILE), manifest_bytes)?;
    // auth.json is the final local initialization commit marker, including in
    // operator mode where external signing still remains mandatory.
    publish_file(
        &home.join("auth.json"),
        &serde_json::to_vec_pretty(&config)?,
    )?;
    completion(&config);
    Ok(())
}

pub fn export(
    home: &Path,
    path: &Path,
    replicas: Option<usize>,
    output: Option<&Path>,
) -> Result<()> {
    if let Some(replicas) = replicas {
        DeploymentManifest::new(replicas)?;
    }
    ensure!(
        home.is_dir(),
        "existing backend home required; run auth-init first"
    );
    ensure!(
        path.parent()
            .context("auth config parent required")?
            .canonicalize()?
            == home.canonicalize()?,
        "auth configuration must be in --home; deployment.json belongs beside it"
    );
    let _lock = lock(home)?;
    let config = Config::load_for_export(path)?;
    let vault = Vault::new(home);
    for (role, reference) in [
        ("issuer", &config.issuer),
        ("encryption", &config.encryption),
        ("connection", &config.connection),
    ] {
        ensure!(
            &vault.existing(role, reference.kind)? == reference,
            "auth configuration credential does not match backend metadata"
        );
    }
    let control = Vault::new(&home.join("control")).existing("device", Kind::User)?;
    ensure!(
        control.public_key == config.control_nkey,
        "control identity does not match callout configuration"
    );
    let manifest_path = home.join(MANIFEST_FILE);
    let manifest = match fs::read(&manifest_path) {
        Ok(bytes) => {
            let manifest: DeploymentManifest = serde_json::from_slice(&bytes)?;
            ensure!(replicas.is_none_or(|replicas| replicas == manifest.replicas()), "--replicas conflicts with established deployment manifest; review deployment changes explicitly");
            manifest
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => DeploymentManifest::new(replicas.context("deployment manifest missing: supply --replicas 1 or 3 for this existing installation")?)?,
        Err(error) => return Err(error.into()),
    };
    let manifest = if home.join(epochgrid_core::capacity::FILE).try_exists()? {
        DeploymentManifest::bounded(
            manifest.replicas(),
            epochgrid_core::capacity::Capacity::load(home)?,
        )?
    } else {
        manifest
    };
    let artifacts = artifacts(&config, &manifest)?;
    let default_output = home.join("deployment-artifacts");
    let output = output.unwrap_or(&default_output);
    // Preserve existing manifest formatting; semantic equality was checked above.
    if manifest_path.try_exists()? {
        ensure!(
            !fs::symlink_metadata(&manifest_path)?
                .file_type()
                .is_symlink(),
            "deployment manifest must not be a symlink"
        );
    }
    publish_bundle(output, &artifacts)?;
    if !manifest_path.try_exists()? {
        publish_file(
            &manifest_path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&DeploymentManifest::new(manifest.replicas())?)?
            )
            .as_bytes(),
        )?;
    }
    completion(&config);
    Ok(())
}

fn completion(config: &Config) {
    if config
        .operator_jwt
        .as_ref()
        .is_some_and(|operator| operator.connection_jwt.is_empty())
    {
        println!(
            "Public artifacts ready. Operator setup INCOMPLETE: supply the signed non-bearer service JWT in auth.json.operator_jwt.connection_jwt before serve. NATS was not contacted or modified."
        );
    } else {
        println!(
            "Public deployment artifacts ready. Integrate accounts/TLS and provision resources using operator administration tooling. Deployment readiness was not evaluated; NATS was not contacted or modified."
        );
    }
}

#[cfg(test)]
mod tests;

/// Explicit stopped-service upgrade. Original M28 manifest and artifacts survive.
pub fn capacity_export(
    home: &Path,
    path: &Path,
    policy: &Path,
    output: &Path,
    replace: bool,
) -> Result<()> {
    ensure!(
        path.parent()
            .context("auth config parent required")?
            .canonicalize()?
            == home.canonicalize()?,
        "auth configuration must belong to the backend home"
    );
    let bytes = fs::read(policy)?;
    ensure!(bytes.len() <= 8192, "capacity file too large");
    let capacity: epochgrid_core::capacity::Capacity = serde_json::from_slice(&bytes)?;
    capacity.validate()?;
    let _runtime = crate::roles::runtime_lock(home)?;
    let _setup = lock(home)?;
    capacity.inspect_registry(home)?;
    let config = Config::load_for_export(path)?;
    let old: DeploymentManifest = serde_json::from_slice(&fs::read(home.join(MANIFEST_FILE))?)?;
    let manifest = DeploymentManifest::bounded(old.replicas(), capacity.clone())?;
    let bundle = artifacts(&config, &manifest)?;
    // Do all checks before publishing. No existing policy is silently replaced.
    let policy_bytes = bundle[epochgrid_core::capacity::FILE].as_bytes();
    let destination = home.join(epochgrid_core::capacity::FILE);
    if replace && destination.try_exists()? {
        let metadata = fs::symlink_metadata(&destination)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "capacity policy must be a regular file"
        );
        epochgrid_core::capacity::Capacity::load(home)?;
    } else {
        same_or_absent(&destination, policy_bytes)?;
    }
    publish_bundle(output, &bundle)?;
    if replace {
        let mut staged = tempfile::NamedTempFile::new_in(home)?;
        staged.write_all(policy_bytes)?;
        staged.as_file().sync_all()?;
        staged.persist(&destination)?;
        fs::File::open(home)?.sync_all()?;
    } else {
        publish_file(&destination, policy_bytes)?;
    }
    println!(
        "Capacity installed locally. Apply exported broker resources with operator credentials, validate both roles, then restart. Existing deployment artifacts are unchanged."
    );
    Ok(())
}
