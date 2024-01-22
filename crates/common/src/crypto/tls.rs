use anyhow::Result;

use crate::error::AppError;

/// Make a vector of cipher suites named in `suites`
///
/// # Arguments
///
/// * `suite_names` - Cipher suite names array in accordance to those in [`rustls::crypto::ring::ALL_CIPHER_SUITES`]
///
/// # Returns
///
/// A [`Result`] containing a vector of [`rustls::SupportedCipherSuite`] respective to given names
/// If any of the given suite names is not found, an error is returned.
///
pub fn lookup_suites(
    suite_names: &[String],
) -> Result<Vec<rustls::SupportedCipherSuite>, AppError> {
    let mut suites = Vec::new();

    for suite_name in suite_names {
        let scs = lookup_suite(suite_name);
        match scs {
            Ok(s) => suites.push(s),
            Err(err) => return Err(err),
        }
    }

    Ok(suites)
}

/// Find a cipher suite with the given name
///
/// # Arguments
///
/// * `name` - Cipher suite name in accordance to those in [`rustls::crypto::ring::ALL_CIPHER_SUITES`]
///
/// # Returns
///
/// A [`Result`] containing a [`rustls::SupportedCipherSuite`] respective to given name
/// If the name is not found, an error is returned.
///
pub fn lookup_suite(name: &str) -> Result<rustls::SupportedCipherSuite, AppError> {
    for suite in rustls::crypto::ring::ALL_CIPHER_SUITES {
        let sname = format!("{:?}", suite.suite()).to_lowercase();

        if sname == name.to_string().to_lowercase() {
            return Ok(*suite);
        }
    }

    Err(AppError::General(format!(
        "Invalid cipher suite: suite={}",
        name
    )))
}

/// Verify a cipher suite with the given name
///
/// # Arguments
///
/// * `name` - Cipher suite name in accordance to those in [`rustls::crypto::ring::ALL_CIPHER_SUITES`]
///
/// # Returns
///
/// A [`Result`] containing given suite name, if valid.
/// If the name is not found, an error is returned.
///
pub fn verify_suite(name: &str) -> Result<String, AppError> {
    lookup_suite(name)?;
    Ok(name.to_string())
}

/// Make a vector of protocol versions named in `versions`
///
/// * `version names` - Protocol version names array. Valid values: `1.2`, `1.3`
///
/// # Returns
///
/// A [`Result`] containing a vector of [`rustls::SupportedProtocolVersion`] respective to given names
/// If any of the given protocol names is not found, an error is returned.
///
pub fn lookup_versions(
    version_names: &[String],
) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, AppError> {
    let mut versions = Vec::new();

    for version_name in version_names {
        versions.push(lookup_version(version_name)?);
    }

    Ok(versions)
}

/// Determine protocol version
///
/// * `name` - Protocol name. Valid values: `1.2`, `1.3`
///
/// # Returns
///
/// A [`Result`] containing a [`rustls::SupportedProtocolVersion`] respective to given name
/// If the name is not found, an error is returned.
///
pub fn lookup_version(
    version: &str,
) -> Result<&'static rustls::SupportedProtocolVersion, AppError> {
    match version {
        "1.2" => Ok(&rustls::version::TLS12),
        "1.3" => Ok(&rustls::version::TLS13),
        _ => Err(AppError::General(format!(
            "Invalid protocol version (valid values: '1.2', '1.3'): ver={}",
            version
        ))),
    }
}

/// Verify protocol version
///
/// # Arguments
///
/// * `name` - Protocol name. Valid values:  `1.2`, `1.3`
///
/// # Returns
///
/// A [`Result`] containing given protocol name, if valid.
/// If the name is not found, an error is returned.
///
pub fn verify_version(version: &str) -> Result<String, AppError> {
    lookup_version(version)?;
    Ok(version.to_string())
}

/// Convert ALPN protocol list to byte vectors
///
/// # Arguments
///
/// * `alpn_protocols`: - ALPN protocol names array
///
/// # Returns
///
/// A [`Result`] containing a vector of protocol names (as byte vectors) from the given list
/// Currently this will always return `Ok` (no validation is performed).
///
pub fn parse_alpn_protocols(alpn_protocols: &[String]) -> Result<Vec<Vec<u8>>, AppError> {
    alpn_protocols
        .iter()
        .map(|proto| parse_alpn_protocol(proto))
        .collect()
}

/// Convert ALPN protocol to byte vector
///
/// # Arguments
///
/// * `alpn_protocol`: - ALPN protocol name
///
/// # Returns
///
/// A [`Result`] containing a protocol name (as a byte vector) from the given name
/// Currently this will always return `Ok` (no validation is performed).
///
pub fn parse_alpn_protocol(alpn_protocol: &str) -> Result<Vec<u8>, AppError> {
    Ok(alpn_protocol.as_bytes().into())
}

/// Unit tests
#[cfg(test)]
mod crl_tests {
    use super::*;
    use rustls::{SupportedCipherSuite, SupportedProtocolVersion};

    #[test]
    fn tls_lookup_suites_when_no_match() {
        let all_suites = rustls::crypto::ring::ALL_CIPHER_SUITES;
        assert!(all_suites.len() >= 2);

        let query_suite_strs = vec!["INVALID1".to_string(), "INVALID2".to_string()];

        let result = lookup_suites(query_suite_strs.as_slice());

        if let Ok(suites) = result {
            panic!("Unexpected successful result: suites={:?}", &suites);
        }
    }

    #[test]
    fn tls_lookup_suites_when_all_match() {
        let all_suites = rustls::crypto::ring::ALL_CIPHER_SUITES;
        assert!(all_suites.len() >= 2);

        let query_suites: Vec<&SupportedCipherSuite> = all_suites.iter().take(2).collect();
        let query_suite_strs: Vec<String> = query_suites
            .iter()
            .map(|s| format!("{:?}", s.suite()).to_lowercase())
            .collect();

        let result = lookup_suites(query_suite_strs.as_slice());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let suites = result.unwrap();
        assert_eq!(suites.len(), 2);

        assert!(suites.contains(query_suites.get(0).unwrap()));
        assert!(suites.contains(query_suites.get(1).unwrap()));
    }

    #[test]
    fn tls_verify_suite_when_no_match() {
        let query_suite_str = "INVALID1";

        let result = verify_suite(query_suite_str);

        if let Ok(suite_str) = result {
            panic!("Unexpected successful result: suite={}", &suite_str);
        }
    }

    #[test]
    fn tls_verify_suite_when_match() {
        let all_suites = rustls::crypto::ring::ALL_CIPHER_SUITES;
        assert!(all_suites.len() >= 2);

        let query_suites: Vec<&SupportedCipherSuite> = all_suites.iter().take(1).collect();
        let query_suite_str: String =
            format!("{:?}", query_suites.first().unwrap().suite()).to_lowercase();

        let result = verify_suite(query_suite_str.as_str());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let suite_str = result.unwrap();

        assert_eq!(suite_str, query_suite_str);
    }

    #[test]
    fn tls_lookup_versions_when_no_match() {
        let query_version_strs = vec!["INVALID1".to_string(), "INVALID2".to_string()];

        let result = lookup_versions(query_version_strs.as_slice());

        if let Ok(versions) = result {
            panic!("Unexpected successful result: versions={:?}", &versions);
        }
    }

    #[test]
    fn tls_lookup_versions_when_all_match() {
        let query_versions: Vec<&SupportedProtocolVersion> =
            vec![&rustls::version::TLS12, &rustls::version::TLS13];
        let query_version_strs: Vec<String> = vec!["1.2".to_string(), "1.3".to_string()];

        let result = lookup_versions(query_version_strs.as_slice());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let versions = result.unwrap();
        assert_eq!(versions.len(), 2);

        assert!(versions.contains(query_versions.get(0).unwrap()));
        assert!(versions.contains(query_versions.get(1).unwrap()));
    }

    #[test]
    fn tls_verify_version_when_no_match() {
        let query_version_str = "INVALID1";

        let result = verify_version(query_version_str);

        if let Ok(version_str) = result {
            panic!("Unexpected successful result: version={}", &version_str);
        }
    }

    #[test]
    fn tls_verify_version_when_match() {
        let query_version_str = "1.2";

        let result = verify_version(query_version_str);

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let version_str = result.unwrap();
        assert_eq!(version_str, query_version_str);
    }

    #[test]
    fn tls_parse_alpn_protocols() {
        let unparsed_protocols = vec!["PROTOCOL1".to_string(), "PROTOCOL2".to_string()];

        let result = parse_alpn_protocols(unparsed_protocols.as_slice());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err);
        }

        let parsed_protocols = result.unwrap();
        assert_eq!(parsed_protocols.len(), 2);

        assert!(parsed_protocols.contains(&unparsed_protocols.get(0).unwrap().as_bytes().to_vec()));
        assert!(parsed_protocols.contains(&unparsed_protocols.get(1).unwrap().as_bytes().to_vec()));
    }
}
