use super::*;
use crate::identity::IdentityStore;

#[test]
fn signed_policy_replay_removal_revocation_and_restart() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut registry = AuthRegistry::open(&root.path().join("registry"))?;
    let mut keys = Vec::new();
    for user in ["alice", "bob", "mallory"] {
        let token = registry.invite(user, 60)?;
        let mut store = IdentityStore::open(&root.path().join(user))?;
        let registration = store.init(
            crate::identity_model::token_user(&token)?.as_str(),
            "laptop",
        )?;
        registry.enroll(&token, &registration)?;
        let key = store.nkey()?;
        registry.activate(&key.public_key())?;
        keys.push(key);
    }
    let gid = "a".repeat(32);
    let alice = keys[0].public_key();
    let bob = keys[1].public_key();
    let member = |index: usize| Member {
        nkey: keys[index].public_key(),
        leaf: index as u32,
    };
    let create = PolicyUpdate {
        version: 1,
        gid: gid.clone(),
        expected_generation: 0,
        epoch: 0,
        signer: alice.clone(),
        members: vec![member(0)],
    }
    .sign(&keys[0])?;
    assert_eq!(registry.apply_policy(&create)?, 1);
    let generation = registry.authorize(&alice)?.generation;
    assert_eq!(registry.apply_policy(&create)?, 1);
    assert_eq!(registry.authorize(&alice)?.generation, generation);
    let mut add = create.update.clone();
    add.expected_generation = 1;
    add.epoch = 1;
    add.members.push(member(1));
    let signed = add.clone().sign(&keys[0])?;
    let mut forged = signed.clone();
    forged.signature[0] ^= 1;
    assert!(registry.apply_policy(&forged).is_err());
    let mut stranger = add.clone();
    stranger.signer = keys[2].public_key();
    stranger.members.push(member(2));
    assert!(registry.apply_policy(&stranger.sign(&keys[2])?).is_err());
    assert_eq!(registry.apply_policy(&signed)?, 2);
    assert_eq!(registry.authorized_groups(&bob)?, vec![gid.clone()]);
    assert!(
        registry
            .authorized_groups(&keys[2].public_key())?
            .is_empty()
    );
    assert!(registry.apply_policy(&create).is_err());
    let mut remove = add.clone();
    remove.expected_generation = 2;
    remove.epoch = 2;
    remove.members.pop();
    registry.apply_policy(&remove.clone().sign(&keys[0])?)?;
    assert!(registry.authorized_groups(&bob)?.is_empty());
    assert!(registry.apply_policy(&signed).is_err());
    add.expected_generation = 3;
    add.epoch = 3;
    let readd = add.sign(&keys[0])?;
    registry.apply_policy(&readd)?;
    registry.revoke(&alice)?;
    assert!(registry.authorized_groups(&alice).is_err());
    assert!(registry.apply_policy(&readd).is_err());
    let (generation, coordinator): (u64, String) = registry.db.query_row(
        "SELECT generation,coordinator FROM authorization_groups WHERE gid=?1",
        [&gid],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    assert_eq!(generation, 5);
    assert_eq!(coordinator, bob);
    // Revocation retry is idempotent and cannot continually invalidate remaining grants.
    registry.revoke(&alice)?;
    let successor = PolicyUpdate {
        version: 1,
        gid: gid.clone(),
        expected_generation: generation,
        epoch: 4,
        signer: bob.clone(),
        members: vec![member(1)],
    }
    .sign(&keys[1])?;
    assert_eq!(registry.apply_policy(&successor)?, 6);
    drop(registry);
    let registry = AuthRegistry::open(&root.path().join("registry"))?;
    assert!(registry.authorize(&alice).is_err());
    assert_eq!(registry.authorized_groups(&bob)?, vec![gid]);
    Ok(())
}

#[test]
fn migration_preserves_existing_registry_and_rejects_invalid_groups() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut registry = AuthRegistry::open(root.path())?;
    let token = registry.invite("alice", 60)?;
    let user = crate::identity_model::token_user(&token)?;
    // Reconstruct the version-1 schema with actual pre-existing identity data.
    registry.db.execute_batch("DROP TABLE authorization_members; DROP TABLE authorization_groups; DELETE FROM auth_migrations WHERE version=2;")?;
    drop(registry);
    let registry = AuthRegistry::open(root.path())?;
    assert_eq!(
        registry.resolve(&crate::identity_model::IdentityBinding {
            provider: "local".into(),
            subject: "alice".into()
        })?,
        user
    );
    assert_eq!(
        registry
            .db
            .query_row("SELECT MAX(version) FROM auth_migrations", [], |r| r
                .get::<_, i64>(0))?,
        2
    );
    for gid in [
        "",
        "*",
        "group.>",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag",
    ] {
        assert!(validate_gid(gid).is_err());
    }
    Ok(())
}
