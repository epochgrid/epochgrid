use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use epochgrid_core::{
    identity::IdentityStore,
    recovery::{MAX_PACKAGE, MAX_SECRET_FILE, RecoveryArchive, RecoverySecret},
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Subcommand)]
pub enum Command {
    /// Encrypt control credentials/trust evidence; never backs up MLS secrets or history.
    Export {
        #[arg(long)]
        output: PathBuf,
        /// New private file for the random secret. Store separately from the package.
        #[arg(long)]
        secret_file: PathBuf,
    },
    /// Restore identity administration into an empty home; messaging needs a fresh device.
    Restore {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        secret_file: PathBuf,
    },
    /// Show recovery-only status and channel hints, without secrets.
    Status,
}

fn read_bounded(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        std::fs::metadata(path)?.is_file(),
        "recovery input must be a regular file"
    );
    let file = File::open(path).context("cannot open recovery input")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit as u64,
        "recovery input exceeds size limit or is not a regular file"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "recovery input exceeds size limit");
    Ok(bytes)
}

/// Remove only files created by this invocation if a normal I/O error occurs.
/// A crash can leave incomplete files; it never overwrites an existing backup.
struct NewFile {
    file: File,
    path: PathBuf,
    complete: bool,
}
impl NewFile {
    fn create(path: &Path) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        Ok(Self {
            file: options
                .open(path)
                .context("recovery output must be a new file in an existing directory")?,
            path: path.into(),
            complete: false,
        })
    }
}
impl Drop for NewFile {
    fn drop(&mut self) {
        if !self.complete {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
fn save(package: &[u8], secret: &RecoverySecret, output: &Path, secret_file: &Path) -> Result<()> {
    ensure!(
        output != secret_file,
        "package and secret require different files"
    );
    let mut encrypted = NewFile::create(output)?;
    let mut key = NewFile::create(secret_file)?;
    key.file.write_all(secret.encode().as_bytes())?;
    key.file.sync_all()?;
    encrypted.file.write_all(package)?;
    encrypted.file.sync_all()?;
    key.complete = true;
    encrypted.complete = true;
    Ok(())
}

pub fn run(home: &Path, command: Command) -> Result<()> {
    match command {
        Command::Export {
            output,
            secret_file,
        } => {
            let store = IdentityStore::open(home)?;
            let (package, secret) = store.export_recovery()?;
            save(&package, &secret, &output, &secret_file)?;
            println!(
                "EpochGrid encrypted recovery package saved: {}",
                output.display()
            );
            println!(
                "Recovery secret saved separately: {}. Keep it apart from the package.",
                secret_file.display()
            );
            println!(
                "Recovers identity administration and trust evidence only; no MLS secrets or message history."
            );
        }
        Command::Restore { input, secret_file } => {
            let bytes = read_bounded(&input, MAX_PACKAGE)?;
            let secret_bytes = read_bounded(&secret_file, MAX_SECRET_FILE)?;
            let secret = RecoverySecret::parse(
                std::str::from_utf8(&secret_bytes).context("invalid recovery secret encoding")?,
            )?;
            let archive = RecoveryArchive::decrypt(&bytes, &secret)?;
            // Validate/authenticate first: malformed input never creates a database.
            if home.exists() {
                ensure!(
                    home.is_dir() && std::fs::read_dir(home)?.next().is_none(),
                    "restore requires an empty home; choose a new --home directory"
                );
            }
            let store = IdentityStore::open(home)?;
            archive.restore(&store)?;
            let identity = store.registration()?.payload;
            println!(
                "EpochGrid recovery-only identity restored: {}/{}",
                identity.user_id, identity.device_id
            );
            println!(
                "Audit the directory, enroll a fresh device, revoke the lost device, and obtain a new invitation. This home cannot chat."
            );
        }
        Command::Status => {
            let store = IdentityStore::open(home)?;
            store.registration()?;
            if let Some(status) = store.recovery_status()? {
                println!(
                    "EpochGrid recovery-only home: identity administration; messaging disabled"
                );
                println!(
                    "Exported at {} UTC Unix seconds; restored at {} UTC Unix seconds",
                    status.exported_at, status.restored_at
                );
                println!(
                    "Device fingerprint: {}",
                    epochgrid_core::trust::display_fingerprint(&status.fingerprint)
                );
                for group in status.groups {
                    println!(
                        "Re-invitation hint: {} ({}) — no membership or history restored",
                        group.name, group.gid
                    );
                }
                if let Some(warning) = store.trust_warning()? {
                    println!("{warning}");
                }
            } else {
                println!(
                    "EpochGrid normal messaging home; recovery exports are not tracked locally"
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_files_no_overwrite_and_authenticate_before_creating_home() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("alice");
        let mut store = IdentityStore::open(&home)?;
        store.init("alice", "laptop")?;
        let (package, secret) = store.export_recovery()?;
        drop(store);
        let output = root.path().join("backup.egrecovery");
        let key = root.path().join("backup.egsecret");
        save(&package, &secret, &output, &key)?;
        assert!(save(&package, &secret, &output, &key).is_err());
        assert_eq!(std::fs::read(&output)?, package);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for file in [&output, &key] {
                assert_eq!(std::fs::metadata(file)?.permissions().mode() & 0o777, 0o600);
            }
        }
        let other = root.path().join("other.egrecovery");
        assert!(save(&package, &secret, &other, &key).is_err());
        assert!(!other.exists());
        assert!(save(&package, &secret, &other, &other).is_err());
        assert!(!other.exists());
        let restored = root.path().join("restored");
        let mut corrupted = package.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        std::fs::write(&output, corrupted)?;
        assert!(
            run(
                &restored,
                Command::Restore {
                    input: output.clone(),
                    secret_file: key.clone()
                }
            )
            .is_err()
        );
        assert!(!restored.exists());
        std::fs::write(&output, &package)?;
        run(
            &restored,
            Command::Restore {
                input: output.clone(),
                secret_file: key.clone(),
            },
        )?;
        assert!(
            run(
                &restored,
                Command::Restore {
                    input: output,
                    secret_file: key
                }
            )
            .is_err()
        );
        assert!(read_bounded(&restored, MAX_PACKAGE).is_err());
        assert!(read_bounded(&other, MAX_PACKAGE).is_err());
        let oversized = root.path().join("large");
        std::fs::write(&oversized, vec![0; MAX_SECRET_FILE + 1])?;
        assert!(read_bounded(&oversized, MAX_SECRET_FILE).is_err());
        Ok(())
    }
}
