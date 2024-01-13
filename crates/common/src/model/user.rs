use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub user_id: u64,
    pub name: String,
    pub status: Status,
    pub roles: Vec<u64>,
    pub user_name: Option<String>,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    #[default]
    Active,
    Inactive,
}

impl User {
    /// User constructor
    pub fn new(
        user_id: u64,
        user_name: Option<&str>,
        password: Option<&str>,
        name: &str,
        status: Status,
        roles: &[u64],
    ) -> Self {
        Self {
            user_id,
            user_name: user_name.map(|u| u.to_string()),
            password: password.map(|p| p.to_string()),
            name: name.to_string(),
            status,
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
            Status::Active,
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
