use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct ServiceAccess {
    pub user_id: u64,
    pub service_id: u64,
}

impl ServiceAccess {
    /// ServiceAccess constructor
    pub fn new(user_id: u64, service_id: u64) -> Self {
        Self {
            user_id,
            service_id,
        }
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn serviceaccess_new() {
        let access = ServiceAccess::new(100, 200);
        assert_eq!(access.user_id, 100);
        assert_eq!(access.service_id, 200);
    }
}
