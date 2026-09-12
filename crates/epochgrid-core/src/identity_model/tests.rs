use super::*;
#[test]
fn canonical_users_tokens_device_binding_and_restart() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut registry = AuthRegistry::open(&root.path().join("registry"))?;
    let token = registry.invite("alice", 60)?;
    let user = token_user(&token)?;
    crate::wire::validate_id(user.as_str())?;
    assert!(UserId::try_from("alice".to_owned()).is_err());
    assert!(UserId::try_from("egusr-aaaaaaaaaaaaaaaaaaaaaaaaab".to_owned()).is_err());
    let again = registry.invite("alice", 60)?;
    assert_eq!(token_user(&again)?, user);
    let bob = registry.invite("bob", 60)?;
    assert_ne!(token_user(&bob)?, user);
    let mut device = identity::IdentityStore::open(&root.path().join("device"))?;
    let registration = device.init(user.as_str(), "laptop")?;
    let key = &registration.payload.nats_public_key;
    assert!(registry.authorize(key).is_err());
    assert!(registry.enroll(&bob, &registration).is_err());
    registry.enroll(&token, &registration)?;
    assert!(registry.authorize(key).is_err());
    registry.activate(key)?;
    assert_eq!(registry.authorize(key)?.user, user);
    registry.db.execute(
        "UPDATE devices SET device_id='changed' WHERE nkey=?1",
        [key],
    )?;
    assert!(registry.authorize(key).is_err());
    registry
        .db
        .execute("UPDATE devices SET device_id='laptop' WHERE nkey=?1", [key])?;
    let encoded = crate::wire::encode(crate::wire::Body::Enroll {
        token: crate::wire::EnrollmentToken::new(&token),
        registration: registration.clone(),
    })?;
    assert_eq!(&encoded[..2], &[1, 17]);
    assert!(matches!(
        crate::wire::decode(&encoded)?,
        crate::wire::Body::Enroll { .. }
    ));
    registry.enroll(&token, &registration)?;
    assert!(
        LocalIdentityProvider
            .authenticate(&registry, &token)
            .is_err()
    );
    let mut other = identity::IdentityStore::open(&root.path().join("other"))?;
    let other = other.init(user.as_str(), "desktop")?;
    assert!(registry.enroll(&token, &other).is_err());
    registry
        .db
        .execute("UPDATE users SET enabled=0 WHERE id=?1", [user.as_str()])?;
    assert!(registry.authorize(key).is_err());
    registry
        .db
        .execute("UPDATE users SET enabled=1 WHERE id=?1", [user.as_str()])?;
    registry.revoke(key)?;
    drop(registry);
    let registry = AuthRegistry::open(&root.path().join("registry"))?;
    assert!(registry.authorize(key).is_err());
    assert!(registry.enrollment()?.is_empty());
    let tokenbytes = std::fs::read(root.path().join("registry/auth.sqlite"))?;
    assert!(
        !tokenbytes
            .windows(token.len())
            .any(|w| w == token.as_bytes())
    );
    Ok(())
}
#[test]
fn expired_tokens_fail_without_rebinding() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut registry = AuthRegistry::open(root.path())?;
    let token = registry.invite("alice", 1)?;
    registry
        .db
        .execute("UPDATE enrollment_tokens SET expires=0", [])?;
    assert!(
        LocalIdentityProvider
            .authenticate(&registry, &token)
            .is_err()
    );
    assert!(registry.invite("alice", 3601).is_err());
    Ok(())
}
