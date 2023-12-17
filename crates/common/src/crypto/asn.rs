use std::fmt::Write;

use oid_registry::{format_oid, Oid as DerOid, OidRegistry};
use x509_parser::der_parser::asn1_rs::{Any, Tag};

use crate::error::AppError;

pub fn stringify_asn_value(asn_attr: &Any<'_>) -> Result<String, AppError> {

    let convert_err_fn = |err|
        Err(AppError::GenWithMsgAndErr("Failed ASN value conversion".to_string(), Box::new(err)));

    match asn_attr.header.tag() {
        Tag::Boolean => {
            asn_attr.clone().bool().map(|v| v.to_string()).or_else(convert_err_fn)
        }
        Tag::Enumerated => {
            asn_attr.clone().enumerated().map(|v| v.0.to_string()).or_else(convert_err_fn)
        }
        Tag::GeneralizedTime => {
            asn_attr.clone().generalizedtime().map(|v| v.to_string()).or_else(convert_err_fn)
        }
        Tag::GeneralString => {
            asn_attr.clone().generalstring().map(|v| v.string()).or_else(convert_err_fn)
        }
        Tag::Ia5String => {
            asn_attr.clone().ia5string().map(|v| v.string()).or_else(convert_err_fn)
        }
        Tag::Integer => {
            asn_attr.clone().integer().map(|v| v.as_i64()).map(|v| v.unwrap().to_string()).or_else(convert_err_fn)
        }
        Tag::OctetString => {
            match asn_attr.clone().octetstring() {
                Ok(octet_str) => Ok(octet_str.as_ref().iter()
                    .fold(String::new(), |mut output, byteval| {
                        let _ = write!(output, "{byteval:02X}");
                        output
                    })),
                Err(err) => convert_err_fn(err)
            }
        }
        Tag::Oid => {
            asn_attr.clone().oid()
                .map(|v| {
                    let der_oid = DerOid::new(v.as_bytes().into());
                    format_oid(&der_oid, &OidRegistry::default())
                })
                .or_else(convert_err_fn)
        }
        Tag::PrintableString => {
            asn_attr.clone().printablestring().map(|v| v.string()).or_else(convert_err_fn)
        }
        Tag::RelativeOid => {
            asn_attr.clone().oid()
                .map(|v| {
                    let der_oid = DerOid::new(v.as_bytes().into());
                    format_oid(&der_oid, &OidRegistry::default())
                })
                .or_else(convert_err_fn)
        }
        Tag::UtcTime => {
            asn_attr.clone().utctime().map(|v| v.to_string()).or_else(convert_err_fn)
        }
        Tag::Utf8String => {
            asn_attr.clone().utf8string().map(|v| v.string()).or_else(convert_err_fn)
        }
        _ => Err(AppError::General(format!("unsupported tag {}", asn_attr.clone().header.tag())))
    }
}
