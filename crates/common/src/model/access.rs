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
