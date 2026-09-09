use crate::{
    identity::verify,
    transport::{self, Enrollment},
    wire::{self, Body, DeviceRegistration},
};
use anyhow::{Result, ensure};
use std::collections::BTreeSet;

pub async fn find_devices(
    store: &async_nats::jetstream::kv::Store,
    enrollment: &Enrollment,
    user: &str,
) -> Result<Body> {
    wire::validate_id(user)?;
    let prefix = format!("users.{user}.devices.");
    let mut registrations = Vec::new();
    for endpoint in enrollment.keys().filter(|key| key.starts_with(&prefix)) {
        let device = &endpoint[prefix.len()..];
        if let Body::Found(registration) = transport::find(store, enrollment, user, device).await? {
            registrations.push(registration);
            ensure!(registrations.len() <= 32, "device listing limit exceeded");
        }
    }
    Ok(Body::Devices(registrations))
}
pub async fn list(client: &async_nats::Client, user: &str) -> Result<Vec<DeviceRegistration>> {
    wire::validate_id(user)?;
    let response = client
        .request(
            wire::DEVICES,
            wire::encode(Body::ListDevices { user: user.into() })?.into(),
        )
        .await?;
    let Body::Devices(registrations) = wire::decode(&response.payload)? else {
        anyhow::bail!("device listing rejected or unsupported by service");
    };
    validate_list(user, &registrations)?;
    Ok(registrations)
}
fn validate_list(user: &str, registrations: &[DeviceRegistration]) -> Result<()> {
    ensure!(registrations.len() <= 32, "too many devices in response");
    let mut devices = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for registration in registrations {
        verify(registration)?;
        ensure!(
            registration.payload.user_id == user,
            "directory returned a different user"
        );
        ensure!(
            devices.insert(&registration.payload.device_id)
                && keys.insert(&registration.payload.nats_public_key),
            "directory returned duplicate device identity"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityStore;

    #[test]
    fn lists_validate_binding_duplicates_and_wire_abi() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut laptop = IdentityStore::open(&root.path().join("laptop"))?;
        let mut desktop = IdentityStore::open(&root.path().join("desktop"))?;
        let a = laptop.init("alice", "laptop")?;
        let b = desktop.init("alice", "desktop")?;
        validate_list("alice", &[a.clone(), b.clone()])?;
        assert!(validate_list("bob", std::slice::from_ref(&a)).is_err());
        assert!(validate_list("alice", &[a.clone(), a.clone()]).is_err());
        let mut altered = b.clone();
        altered.payload.device_id = "replacement".into();
        assert!(validate_list("alice", &[altered]).is_err());
        for (body, discriminant) in [
            (
                Body::ListDevices {
                    user: "alice".into(),
                },
                8,
            ),
            (Body::Devices(vec![a, b]), 9),
        ] {
            let encoded = wire::encode(body)?;
            assert_eq!(&encoded[..2], &[1, discriminant]);
            assert_eq!(wire::encode(wire::decode(&encoded)?)?, encoded);
        }
        Ok(())
    }
}
