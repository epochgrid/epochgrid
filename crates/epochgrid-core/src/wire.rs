use serde::{Deserialize, Serialize};

pub const VERSION: u16 = 1;
pub const KEYPACKAGE: &str = "epochgrid.v1.identity.keypackage";
pub const REVOCATIONS: &str = "epochgrid.v1.identity.revocations";
pub const REVOKE: &str = "epochgrid.v1.identity.revoke";
pub const AUDIT: &str = "epochgrid.v1.identity.audit";
pub const DEVICES: &str = "epochgrid.v1.identity.devices";
pub const LOOKUP: &str = "epochgrid.v1.identity.lookup";
pub const REGISTER: &str = "epochgrid.v1.identity.register";
pub const MAX_WIRE: usize = 65_536;

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("invalid subject identifier: use 1–32 lowercase ASCII letters, digits or hyphens")]
    InvalidId,
    #[error("unsupported protocol version")]
    Version,
    #[error("wire payload too large")]
    Size,
    #[error("invalid wire encoding")]
    Encoding(#[from] postcard::Error),
}

pub fn validate_id(id: &str) -> Result<(), ProtocolError> {
    if id.is_empty()
        || id.len() > 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(ProtocolError::InvalidId);
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistrationPayload {
    pub protocol_version: u16,
    pub user_id: String,
    pub device_id: String,
    pub nats_public_key: String,
    pub mls_credential: Vec<u8>,
    pub mls_key_package: Vec<u8>,
    pub generation: u64,
    pub created_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRegistration {
    pub payload: RegistrationPayload,
    pub signature: Vec<u8>,
}
impl RegistrationPayload {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut bytes = b"EpochGrid device registration v1\0".to_vec();
        bytes.extend(postcard::to_allocvec(self)?);
        Ok(bytes)
    }
    pub fn key(&self) -> String {
        format!("users.{}.devices.{}", self.user_id, self.device_id)
    }
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Body {
    Register(DeviceRegistration),
    Registered,
    Rejected,
    Lookup {
        user: String,
        device: String,
    },
    Found(DeviceRegistration),
    NotFound,
    ClaimKeyPackage {
        user: String,
        device: String,
        group: String,
    },
    Welcome {
        payload: Vec<u8>,
    },
    ListDevices {
        user: String,
    },
    Devices(Vec<DeviceRegistration>),
    Audit,
    AuditLog(crate::transparency::Snapshot),
    RegistrationAudit,
    RevocationAudit,
    RevocationLog(crate::revocation::RevocationLog),
    Revoke(crate::revocation::RevokeRequest),
    Revoked,
    Enroll {
        token: EnrollmentToken,
        registration: DeviceRegistration,
    },
    GroupPolicy(crate::authorization::SignedPolicy),
    PolicyApplied {
        generation: u64,
    },
    PolicyQuery {
        gid: String,
    },
    PolicyState(Option<crate::authorization::PolicyState>),
    RelayWelcome(crate::authorization::WelcomeRelay),
    WelcomeRelayed,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub version: u16,
    pub body: Body,
}
pub fn encode(body: Body) -> Result<Vec<u8>, ProtocolError> {
    let bytes = postcard::to_allocvec(&Envelope {
        version: VERSION,
        body,
    })?;
    if bytes.len() > MAX_WIRE {
        return Err(ProtocolError::Size);
    }
    Ok(bytes)
}
pub fn decode(bytes: &[u8]) -> Result<Body, ProtocolError> {
    if bytes.len() > MAX_WIRE {
        return Err(ProtocolError::Size);
    }
    let (envelope, remaining): (Envelope, _) = postcard::take_from_bytes(bytes)?;
    if !remaining.is_empty() {
        return Err(ProtocolError::Encoding(
            postcard::Error::DeserializeBadEncoding,
        ));
    }
    if envelope.version != VERSION {
        return Err(ProtocolError::Version);
    }
    Ok(envelope.body)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_seeded_wire_mutations() {
        // Fixed xorshift64 corpus: no dependency on OS randomness or elapsed time.
        // The unit runner provides a 180s deadline. Panics are never caught.
        let seeds = [
            encode(Body::Registered).unwrap(),
            encode(Body::Lookup {
                user: "alice".into(),
                device: "laptop".into(),
            })
            .unwrap(),
            encode(Body::Welcome {
                payload: vec![0x55; 256],
            })
            .unwrap(),
            encode(Body::Devices(vec![])).unwrap(),
            vec![1, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 1],
        ];
        let corpus: Vec<u8> = seeds
            .iter()
            .flat_map(|seed| {
                (seed.len() as u64)
                    .to_le_bytes()
                    .into_iter()
                    .chain(seed.iter().copied())
            })
            .collect();
        println!(
            "AQ-PARSER-01 seed=0x3520261112 mutations=4096 corpus_sha256={}",
            data_encoding::HEXLOWER.encode(&crate::transparency::hash(&corpus).unwrap())
        );
        for seed in &seeds[..4] {
            for end in 0..seed.len() {
                assert!(
                    decode(&seed[..end]).is_err(),
                    "accepted truncated seed at {end}"
                );
            }
            let mut trailing = seed.clone();
            trailing.push(0);
            assert!(decode(&trailing).is_err());
        }
        let mut state = 0x35_2026_1112_u64;
        for iteration in 0..4096 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut bytes = seeds[iteration % seeds.len()].clone();
            let position = state as usize % bytes.len();
            match iteration % 4 {
                0 => bytes[position] ^= (state >> 32) as u8 | 1,
                1 => bytes.truncate(position),
                2 => bytes.extend_from_slice(&state.to_le_bytes()),
                _ => bytes.splice(position..=position, [0xff; 10]).for_each(drop),
            }
            if let Ok(body) = decode(&bytes) {
                // Syntax acceptance cannot be confused with authentication; only
                // assert stable semantic round-trip for accepted mutations.
                let encoded = encode(body).unwrap();
                assert_eq!(encode(decode(&encoded).unwrap()).unwrap(), encoded);
            }
        }
        for size in [MAX_WIRE + 1, MAX_WIRE * 2] {
            assert!(matches!(
                decode(&vec![0xff; size]),
                Err(ProtocolError::Size)
            ));
        }
    }

    #[test]
    fn ids_and_wire() {
        for id in ["", "Alice", "a.b", "*", ">", "a b", "é"] {
            assert!(validate_id(id).is_err());
        }
        assert!(validate_id("alice-1").is_ok());
        assert_eq!(encode(Body::Registered).unwrap(), vec![1, 1]);
        assert_eq!(
            decode(&encode(Body::Registered).unwrap()).unwrap(),
            Body::Registered
        );
        assert!(
            decode(
                &postcard::to_allocvec(&Envelope {
                    version: 2,
                    body: Body::Registered
                })
                .unwrap()
            )
            .is_err()
        );
        assert!(decode(&[0; MAX_WIRE + 1]).is_err());
        let mut bytes = encode(Body::Registered).unwrap();
        bytes.push(0);
        assert!(decode(&bytes).is_err());
    }
}

/// Enrollment secrets serialize only inside the protected enrollment exchange.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnrollmentToken(zeroize::Zeroizing<String>);
impl EnrollmentToken {
    pub fn new(value: &str) -> Self {
        Self(zeroize::Zeroizing::new(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
impl std::fmt::Debug for EnrollmentToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
