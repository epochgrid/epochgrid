use serde::{Deserialize, Serialize};

pub const VERSION: u16 = 1;
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
