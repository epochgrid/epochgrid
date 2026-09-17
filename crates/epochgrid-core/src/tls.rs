//! Shared, fail-closed transport policy for every EpochGrid NATS connection.
use anyhow::{Context, Result, ensure};
use async_nats::{ConnectOptions, ServerAddr};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::{path::PathBuf, sync::Arc};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Profile {
    #[default]
    Production,
    Development,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MinimumVersion {
    Tls12,
    #[default]
    Tls13,
}
#[derive(Clone, Debug, Default)]
pub struct TlsConfig {
    pub profile: Profile,
    pub ca_path: Option<PathBuf>,
    pub minimum: MinimumVersion,
    pub first: bool,
}
impl TlsConfig {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => anyhow::bail!("{name} must be valid UTF-8"),
        })
    }
    fn from_lookup(get: impl Fn(&str) -> Result<Option<String>>) -> Result<Self> {
        let profile = match get("EPOCHGRID_PROFILE")?.as_deref().unwrap_or("production") {
            "production" => Profile::Production,
            "development" => Profile::Development,
            _ => anyhow::bail!("EPOCHGRID_PROFILE must be production or development"),
        };
        let minimum = match get("EPOCHGRID_TLS_MIN_VERSION")?
            .as_deref()
            .unwrap_or("1.3")
        {
            "1.2" => MinimumVersion::Tls12,
            "1.3" => MinimumVersion::Tls13,
            _ => anyhow::bail!("EPOCHGRID_TLS_MIN_VERSION must be 1.2 or 1.3"),
        };
        let first = match get("EPOCHGRID_TLS_FIRST")?.as_deref().unwrap_or("false") {
            "true" => true,
            "false" => false,
            _ => anyhow::bail!("EPOCHGRID_TLS_FIRST must be true or false"),
        };
        let ca_path = get("EPOCHGRID_TLS_CA_PATH")?.map(PathBuf::from);
        ensure!(
            ca_path.as_ref().is_none_or(|p| !p.as_os_str().is_empty()),
            "EPOCHGRID_TLS_CA_PATH cannot be empty"
        );
        Ok(Self {
            profile,
            ca_path,
            minimum,
            first,
        })
    }
    /// Printed before entering the TUI, whose normal logging is intentionally off.
    pub fn warn_development(&self) {
        if self.profile == Profile::Development {
            eprintln!(
                "EpochGrid DEVELOPMENT profile: plaintext NATS is permitted; not supported for production."
            );
        }
    }
    pub fn validate_endpoint(&self, url: &str) -> Result<bool> {
        ensure!(
            url.starts_with("tls://") || url.starts_with("nats://"),
            "use an explicit tls:// endpoint (nats:// only in development)"
        );
        let endpoint: ServerAddr = url.parse().context("invalid NATS endpoint")?;
        ensure!(
            endpoint.username().is_none() && endpoint.password().is_none(),
            "endpoint URLs must not contain credentials"
        );
        let tls = endpoint.tls_required();
        ensure!(
            tls || self.profile == Profile::Development,
            "production requires tls://; EPOCHGRID_PROFILE=development is only for explicit development fixtures"
        );
        ensure!(tls || !self.first, "TLS-first requires a tls:// endpoint");
        ensure!(
            tls || self.ca_path.is_none(),
            "a CA bundle requires a tls:// endpoint"
        );
        Ok(tls)
    }
    fn client_config(&self) -> Result<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        if let Some(path) = &self.ca_path {
            let bytes = std::fs::read(path).context("read EPOCHGRID_TLS_CA_PATH")?;
            for certificate in CertificateDer::pem_slice_iter(&bytes) {
                roots
                    .add(certificate.context("invalid CA PEM")?)
                    .context("invalid CA certificate")?;
            }
        } else {
            let native = rustls_native_certs::load_native_certs();
            ensure!(
                native.errors.is_empty(),
                "platform trust store could not be loaded"
            );
            for certificate in native.certs {
                roots
                    .add(certificate)
                    .context("invalid platform CA certificate")?;
            }
        }
        ensure!(
            !roots.is_empty(),
            "TLS trust store contains no certificates"
        );
        let versions: &[&rustls::SupportedProtocolVersion] = match self.minimum {
            MinimumVersion::Tls12 => &[&rustls::version::TLS13, &rustls::version::TLS12],
            MinimumVersion::Tls13 => &[&rustls::version::TLS13],
        };
        Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(versions)?
        .with_root_certificates(roots)
        .with_no_client_auth())
    }
    pub fn apply(&self, url: &str, options: ConnectOptions) -> Result<ConnectOptions> {
        if !self.validate_endpoint(url)? {
            return Ok(options);
        }
        let options = options
            .require_tls(true)
            .tls_client_config(self.client_config()?);
        Ok(if self.first {
            options.tls_first()
        } else {
            options
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_and_invalid_configuration_fail_closed() -> Result<()> {
        let config = TlsConfig::from_lookup(|_| Ok(None))?;
        assert_eq!(config.profile, Profile::Production);
        assert_eq!(config.minimum, MinimumVersion::Tls13);
        for url in [
            "nats://localhost:4222",
            "localhost:4222",
            "ws://localhost",
            "tls://user:secret@localhost",
        ] {
            assert!(config.validate_endpoint(url).is_err());
        }
        assert!(config.validate_endpoint("tls://localhost:4222")?);
        for (name, value) in [
            ("EPOCHGRID_PROFILE", "prodution"),
            ("EPOCHGRID_PROFILE", ""),
            ("EPOCHGRID_TLS_MIN_VERSION", "1.1"),
            ("EPOCHGRID_TLS_FIRST", "1"),
            ("EPOCHGRID_TLS_CA_PATH", ""),
        ] {
            assert!(
                TlsConfig::from_lookup(|key| Ok((name == key).then(|| value.to_owned()))).is_err()
            );
        }
        let development = TlsConfig {
            profile: Profile::Development,
            ..Default::default()
        };
        assert!(!development.validate_endpoint("nats://localhost:4222")?);
        assert!(development.validate_endpoint("tls://localhost:4222")?);
        Ok(())
    }
    #[test]
    fn missing_empty_and_malformed_ca_are_rejected() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("ca.pem");
        let config = TlsConfig {
            ca_path: Some(path.clone()),
            ..Default::default()
        };
        assert!(config.client_config().is_err());
        for bytes in [
            b"".as_slice(),
            b"not a certificate",
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        ] {
            std::fs::write(&path, bytes)?;
            assert!(config.client_config().is_err());
        }
        assert!(config.validate_endpoint("nats://localhost:4222").is_err());
        Ok(())
    }
}
