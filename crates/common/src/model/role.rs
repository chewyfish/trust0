use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    pub role_id: u64,
    pub name: String,
}

impl Role {
    /// Role constructor
    pub fn new(role_id: u64, name: &str) -> Self {
        Self {
            role_id,
            name: name.to_string(),
        }
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn role_new() {
        let role = Role::new(100, "role100");
        assert_eq!(role.role_id, 100);
        assert_eq!(role.name, "role100");
    }
}
