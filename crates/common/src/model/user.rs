use serde_derive::{Deserialize, Serialize};

/// User model struct
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// User ID (unique across users)
    pub user_id: i64,
    /// Friendly name for user
    pub name: String,
    /// User account status
    pub status: Status,
    /// RBAC roles associated to user account
    pub roles: Vec<i64>,
    /// (optional) Username used in secondary authentication
    pub user_name: Option<String>,
    /// (optional) Password used in secondary authentication
    pub password: Option<String>,
}

/// User acccount status
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    /// Active account status
    #[default]
    Active,
    /// Inactive account status
    Inactive,
}

impl User {
    /// User constructor
    ///
    /// # Arguments
    ///
    /// * `user_id` - User ID (unique across users)
    /// * `user_name` - (optional) Username used in secondary authentication
    /// * `password` - (optional) Password used in secondary authentication
    /// * `name` - Friendly name for user
    /// * `status` - User account status
    /// * `roles` - RBAC roles associated to user account
    ///
    /// # Returns
    ///
    /// A newly constructed [`User`] object.
    ///
    pub fn new(
        user_id: i64,
        user_name: Option<&str>,
        password: Option<&str>,
        name: &str,
        status: &Status,
        roles: &[i64],
    ) -> Self {
        Self {
            user_id,
            user_name: user_name.map(|u| u.to_string()),
            password: password.map(|p| p.to_string()),
            name: name.to_string(),
            status: status.clone(),
            roles: roles.to_owned(),
        }
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn user_new() {
        let roles = vec![60, 61];
        let user = User::new(
            100,
            Some("uname100"),
            Some("pass100"),
            "user100",
            &Status::Active,
            &roles,
        );
        assert_eq!(user.user_id, 100);
        assert!(user.user_name.is_some());
        assert_eq!(user.user_name.unwrap(), "uname100");
        assert!(user.password.is_some());
        assert_eq!(user.password.unwrap(), "pass100");
        assert_eq!(user.name, "user100");
        assert_eq!(user.status, Status::Active);
        assert_eq!(user.roles, roles);
    }
}
