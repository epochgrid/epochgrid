//! Nonblocking file locks whose lifetime belongs to the acquiring process.
use std::fs::{File, TryLockError};

/// Explicitly release the lock before closing its descriptor. On Linux, closing
/// only releases flock after the last reference to its open file description is
/// closed. A concurrently forked child can retain such a reference until exec,
/// even with CLOEXEC set, and otherwise prolong an already completed operation.
pub struct ExclusiveLock {
    file: File,
    owner: rustix::process::Pid,
}

impl ExclusiveLock {
    pub fn try_acquire(file: File) -> Result<Self, TryLockError> {
        file.try_lock()?;
        Ok(Self {
            file,
            owner: rustix::process::getpid(),
        })
    }
}

impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        // A forked child must not unlock an operation still owned by its parent.
        if rustix::process::getpid() == self.owner {
            let _ = self.file.unlock();
        }
        // File closes even if unlock failed; process death also closes it.
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{fs::OpenOptions, os::unix::process::CommandExt, process::Command};

    #[test]
    fn child_drop_cannot_unlock_live_parent_and_failed_acquisition_cannot_unlock_owner()
    -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("lock");
        let open = || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
        };
        let guard = ExclusiveLock::try_acquire(open()?)?;
        // Only this test can duplicate a guard. Production exposes no cloning or
        // descriptor access. The captured guard simulates a child-owned copy.
        let mut inherited = Some(ExclusiveLock {
            file: guard.file.try_clone()?,
            owner: guard.owner,
        });
        let mut command = Command::new("/bin/true");
        // SAFETY: dropping the guard only invokes getpid, close (and, if broken,
        // unlock). There are no allocations or application locks in this child.
        unsafe {
            command.pre_exec(move || {
                drop(inherited.take());
                Ok(())
            });
        }
        assert!(command.status()?.success());
        assert!(ExclusiveLock::try_acquire(open()?).is_err());
        assert!(
            open()?.try_lock().is_err(),
            "failed acquisition released the owner's lock"
        );
        // Parent's captured copy is still alive; dispose it with the actual guard.
        drop(command);
        drop(guard);
        ExclusiveLock::try_acquire(open()?)?;
        Ok(())
    }
}
