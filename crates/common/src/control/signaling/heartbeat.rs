use std::borrow::Borrow;

use serde_derive::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::AppError;

/// Active service proxy connections for connected mTLS device user
#[derive(Serialize, Deserialize, Clone, PartialEq, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProxyConnectionEvent {
    /// Service key name value
    pub service_name: String,
    /// List of current connection bind address pairs
    pub binds: Vec<Vec<String>>,
}

impl ProxyConnectionEvent {
    /// ProxyConnection constructor
    ///
    /// # Arguments
    ///
    /// * `service_name` - Service key name value
    /// * `binds` - List of current connection bind address pairs
    ///
    /// # Returns
    ///
    /// A newly constructed [`ProxyConnectionEvent`] object.
    ///
    pub fn new(service_name: &str, binds: &[Vec<String>]) -> Self {
        Self {
            service_name: service_name.to_string(),
            binds: binds.to_vec(),
        }
    }

    /// Construct proxy connection(s) from serde Value
    ///
    /// # Arguments
    ///
    /// * `value` - A JSON object representing either a JSON array of [`ProxyConnectionEvent`] or a single [`ProxyConnectionEvent`]
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a vector of corresponding [`ProxyConnectionEvent`] objects.
    ///
    pub fn from_serde_value(value: &Value) -> Result<Vec<ProxyConnectionEvent>, AppError> {
        if let Value::Array(values) = &value {
            Ok(values
                .iter()
                .map(|v| {
                    serde_json::from_value(v.clone()).map_err(|err| {
                        AppError::GenWithMsgAndErr(
                            "Error converting serde Value to ProxyConnectionEvent".to_string(),
                            Box::new(err),
                        )
                    })
                })
                .collect::<Result<Vec<ProxyConnectionEvent>, AppError>>()?)
        } else {
            Ok(vec![serde_json::from_value(value.clone()).map_err(
                |err| {
                    AppError::GenWithMsgAndErr(
                        "Error converting serde Value to ProxyConnectionEvent".to_string(),
                        Box::new(err),
                    )
                },
            )?])
        }
    }
}

unsafe impl Send for ProxyConnectionEvent {}

impl TryInto<Value> for ProxyConnectionEvent {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        self.borrow().try_into()
    }
}

impl TryInto<Value> for &ProxyConnectionEvent {
    type Error = AppError;

    fn try_into(self) -> Result<Value, Self::Error> {
        serde_json::to_value(self).map_err(|err| {
            AppError::GenWithMsgAndErr(
                "Error converting Connection to serde Value".to_string(),
                Box::new(err),
            )
        })
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn proxyconnevt_new() {
        let proxy_conn = ProxyConnectionEvent::new(
            "svc1",
            &vec![
                vec!["b0".to_string(), "b1".to_string()],
                vec!["b2".to_string(), "b3".to_string()],
            ],
        );

        assert_eq!(proxy_conn.service_name, "svc1");
        assert_eq!(proxy_conn.binds.len(), 2);
        assert_eq!(
            proxy_conn.binds[0],
            vec!["b0".to_string(), "b1".to_string()]
        );
        assert_eq!(
            proxy_conn.binds[1],
            vec!["b2".to_string(), "b3".to_string()]
        );
    }
    #[test]
    fn proxyconnevt_from_serde_value_when_invalid() {
        let conn_json = json!({"serviceNameINVALID": "svc1", "binds": [["b0","b1"],["b2","b3"]]});

        match ProxyConnectionEvent::from_serde_value(&conn_json) {
            Ok(proxies) => panic!("Unexpected successful result: conns={:?}", proxies),
            _ => {}
        }
    }

    #[test]
    fn proxyconnevt_from_serde_value_when_valid_connections_list() {
        let proxy_conns_json = json!([{"serviceName": "svc1", "binds": [["b0","b1"],["b2","b3"]]}]);

        match ProxyConnectionEvent::from_serde_value(&proxy_conns_json) {
            Ok(proxy_conns) => {
                assert_eq!(proxy_conns.len(), 1);
                let proxy_conn = ProxyConnectionEvent::new(
                    "svc1",
                    &vec![
                        vec!["b0".to_string(), "b1".to_string()],
                        vec!["b2".to_string(), "b3".to_string()],
                    ],
                );
                assert_eq!(proxy_conns, vec![proxy_conn]);
            }
            _ => {}
        }
    }

    #[test]
    fn proxyconnevt_from_serde_value_when_valid_connections_object() {
        let proxy_conns_json = json!({"serviceName": "svc1", "binds": [["b0","b1"],["b2","b3"]]});

        match ProxyConnectionEvent::from_serde_value(&proxy_conns_json) {
            Ok(proxy_conns) => {
                assert_eq!(proxy_conns.len(), 1);
                let proxy_conn = ProxyConnectionEvent::new(
                    "svc1",
                    &vec![
                        vec!["b0".to_string(), "b1".to_string()],
                        vec!["b2".to_string(), "b3".to_string()],
                    ],
                );
                assert_eq!(proxy_conns, vec![proxy_conn]);
            }
            _ => {}
        }
    }

    #[test]
    fn proxyconnevt_try_into_value() {
        let proxy_conn = ProxyConnectionEvent::new(
            "svc1",
            &vec![
                vec!["b0".to_string(), "b1".to_string()],
                vec!["b2".to_string(), "b3".to_string()],
            ],
        );

        let result: Result<Value, AppError> = proxy_conn.try_into();
        match result {
            Ok(value) => {
                assert_eq!(
                    value,
                    json!({"serviceName": "svc1", "binds": [["b0","b1"],["b2","b3"]]})
                );
            }
            Err(err) => panic!("Unexpected result: err={:?}", err),
        }
    }
}
