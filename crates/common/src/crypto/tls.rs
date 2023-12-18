use anyhow::Result;

use crate::error::AppError;

/// Make a vector of ciphersuites named in `suites`
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

/// Find a ciphersuite with the given name
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

/// Make a vector of protocol versions named in `versions`
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
