use serde_derive::{Deserialize, Serialize};

/// RBAC Role model struct
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    /// Role ID (unique across roles)
    pub role_id: i64,
    /// Friendly name for role
    pub name: String,
}

impl Role {
    /// Role constructor
    ///
    /// # Arguments
    ///
    /// * `role_id` - Role ID (unique across roles)
    /// * `name` - Friendly name for role
    ///
    /// # Returns
    ///
    /// A newly constructed [`Role`] object.
    ///
    pub fn new(role_id: i64, name: &str) -> Self {
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
