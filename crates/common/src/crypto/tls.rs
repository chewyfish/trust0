use anyhow::Result;

use crate::error::AppError;

/// Make a vector of ciphersuites named in `suites`
pub fn lookup_suites(suite_names: &[String]) -> Result<Vec<rustls::SupportedCipherSuite>, AppError> {

    let mut suites = Vec::new();

    for suite_name in suite_names {
        let scs = lookup_suite(suite_name);
        match scs {
            Ok(s) => suites.push(s),
            Err(err) => return Err(err)
        }
    }

    Ok(suites)
}

/// Find a ciphersuite with the given name
pub fn lookup_suite(name: &str) -> Result<rustls::SupportedCipherSuite, AppError> {

    for suite in rustls::crypto::ring::ALL_CIPHER_SUITES {
        let sname = format!("{:?}", suite.suite()).to_lowercase();

        if sname == name.to_string().to_lowercase() {
            return Ok(*suite);
        }
    }

    Err(AppError::General(format!("Invalid cipher suite: suite={}", name)))
}

/// Make a vector of protocol versions named in `versions`
pub fn lookup_versions(version_names: &[String]) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, AppError> {

    let mut versions = Vec::new();

    for version_name in version_names {
        versions.push(lookup_version(version_name)?);
    }

    Ok(versions)
}

/// Determine protocol version
pub fn lookup_version(version: &str) -> Result<&'static rustls::SupportedProtocolVersion, AppError> {

    match version {
        "1.2" => Ok(&rustls::version::TLS12),
        "1.3" => Ok(&rustls::version::TLS13),
        _ => Err(AppError::General(format!("Invalid protocol version (valid values: '1.2', '1.3'): ver={}", version)))
    }
}

/// Convert ALPN protocol list to byte vectors
pub fn parse_alpn_protocols(alpn_protocols: &[String]) -> Result<Vec<Vec<u8>>, AppError> {

    alpn_protocols
        .iter()
        .map(|proto| parse_alpn_protocol(proto))
        .collect()
}

/// Convert ALPN protocol to byte vector
pub fn parse_alpn_protocol(alpn_protocol: &str) -> Result<Vec<u8>, AppError> {

    Ok(alpn_protocol.as_bytes().into())
}
