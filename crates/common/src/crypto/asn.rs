use x509_parser::der_parser::asn1_rs::{Any, Tag};

use crate::error::AppError;

/// Serialize `BER`/`DER` header tag value
///
/// # Arguments
///
/// * `asn_attr` - an `ASN.1` type for a `BER`/`DER` attribute
///
/// # Returns
///
/// The serialized string value for `ASN.1` attribute header tag value (if supported).
///
pub fn stringify_asn_value(asn_attr: &Any<'_>) -> Result<String, AppError> {
    let convert_err_fn = |err| {
        Err(AppError::General(format!(
            "Failed ASN value conversion: err={:?}",
            &err
        )))
    };

    match asn_attr.header.tag() {
        Tag::GeneralString => asn_attr
            .clone()
            .generalstring()
            .map(|v| v.string())
            .or_else(convert_err_fn),
        Tag::PrintableString => asn_attr
            .clone()
            .printablestring()
            .map(|v| v.string())
            .or_else(convert_err_fn),
        Tag::Utf8String => asn_attr
            .clone()
            .utf8string()
            .map(|v| v.string())
            .or_else(convert_err_fn),
        _ => Err(AppError::General(format!(
            "unsupported tag {}",
            asn_attr.clone().header.tag()
        ))),
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use oid_registry::asn1_rs::{Class, Header, Length};

    fn create_asn<'a>(tag: Tag, data: &'a [u8]) -> Any<'a> {
        Any {
            header: Header::new(Class::Universal, false, tag, Length::Definite(data.len())),
            data,
        }
    }

    #[test]
    fn asn_stringify_asn_value_when_supported_asn_values() {
        assert_eq!(
            stringify_asn_value(&create_asn(Tag::GeneralString, &[0x41])).unwrap(),
            "A".to_string()
        );
        assert_eq!(
            stringify_asn_value(&create_asn(Tag::PrintableString, &[0x41])).unwrap(),
            "A".to_string()
        );
        assert_eq!(
            stringify_asn_value(&create_asn(Tag::Utf8String, &[0x41])).unwrap(),
            "A".to_string()
        );
    }

    #[test]
    fn asn_stringify_asn_value_when_failed_asn_value_conversion() {
        assert!(stringify_asn_value(&create_asn(Tag::PrintableString, &[0x01])).is_err());
    }

    #[test]
    fn asn_stringify_asn_value_when_unsupported_asn_value() {
        assert!(stringify_asn_value(&create_asn(Tag::Integer, &[0x41])).is_err());
    }
}
