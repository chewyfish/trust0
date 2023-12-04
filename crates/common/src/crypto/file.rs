use std::fs;
use std::io::{BufReader, Read};

use anyhow::Result;
use rustls::{Certificate, PrivateKey};
use rustls::server::UnparsedCertRevocationList;

use crate::error::AppError;

pub fn verify_certificates(filename: &str) -> Result<String, AppError> {
    match load_certificates(filename) {
        Ok(_) => Ok(filename.to_string()),
        Err(err) => Err(err)
    }
}

pub fn load_certificates(filename: &str) -> Result<Vec<Certificate>, AppError> {

    match fs::File::open(filename).or_else(
        |err| Err(AppError::GenWithMsgAndErr(format!("failed to open certificates file: file={:?}", filename), Box::new(err)))) {

        Ok(cert_file) => {
            let mut reader = BufReader::new(cert_file);
            let certs = rustls_pemfile::certs(&mut reader).map_err(|err|
                AppError::IoWithMsg(format!("Failed reading certificates file: file={:?}", filename), err))?;

            return Ok(certs.into_iter().map(Certificate).collect());
        }
        Err(err) => Err(err.into())
    }
}

pub fn verify_private_key_file(filename: &str) -> Result<String, AppError> {
    match load_private_key(filename) {
        Ok(_) => Ok(filename.to_string()),
        Err(err) => Err(err)
    }
}

pub fn load_private_key(filename: &str) -> Result<PrivateKey, AppError> {

    match fs::File::open(filename).or_else(
        |err| Err(AppError::IoWithMsg(format!("failed to open private key file: file={:?}", filename), err))) {

        Ok(key_file) => {
            let mut reader = BufReader::new(key_file);
            let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader).map_err(|err|
                AppError::IoWithMsg(format!("error reading private key file): file={:?}", filename), err))?;

            match keys.len() {
                0 => return Err(AppError::General(format!("No PKCS8-encoded private key: file={}", filename))),
                1 => return Ok(PrivateKey(keys.remove(0))),
                _ => return Err(AppError::General(format!("More than one PKCS8-encoded private key: file={}", filename)))
            }
        },

        Err(err) => Err(err)
    }
}

pub fn load_ocsp_response(filename: &str) -> Result<Vec<u8>, AppError> {

    match fs::File::open(filename).or_else(
        |err| Err(AppError::IoWithMsg(format!("failed to open OCSP response file: file={:?}", filename), err))) {

        Ok(mut ocsp_file) => {
            let mut ocsp = Vec::new();
            if let Err(err) = ocsp_file.read_to_end(&mut ocsp) {
                return Err(AppError::IoWithMsg(format!("failed parsing OCSP response file: file={:?}", filename), err));
            }
            Ok(ocsp)
        },

        Err(err) => Err(err)
    }
}

pub fn load_crl_files(filenames: &[String]) -> Result<Vec<UnparsedCertRevocationList>, AppError> {

    filenames
        .iter()
        .map(|filename| {
            load_crl_list(filename)
        })
        .collect()
}

pub fn verify_crl_list(filename: &str) -> Result<String, AppError> {
    match load_crl_list(filename) {
        Ok(_) => Ok(filename.to_string()),
        Err(err) => Err(err)
    }
}

pub fn load_crl_list(filename: &str) -> Result<UnparsedCertRevocationList, AppError> {

    match fs::File::open(filename).or_else(
        |err| Err(AppError::IoWithMsg(format!("failed to open CRL file: file={:?}", filename), err))) {
        Ok(mut crl_file) => {
            let mut crl = Vec::new();
            if let Err(crl_err) = crl_file.read_to_end(&mut crl) {
                Err(AppError::IoWithMsg(format!("failed parsing CRL file: file={:?}", filename), crl_err))
            } else {
                Ok(UnparsedCertRevocationList(crl))
            }
        },

        Err(err) => Err(err)
    }
}
