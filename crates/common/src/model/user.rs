use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct User {
    pub user_id: u64,
    pub name: String,
    pub status: Status,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub enum Status {
    #[default]
    Active,
    Inactive,
}

impl User {
    /// User constructor
    pub fn new(user_id: u64, name: &str, status: Status) -> Self {
        Self {
            user_id,
            name: name.to_string(),
            status,
        }
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn user_new() {
        let user = User::new(100, "user100", Status::Active);
        assert_eq!(user.user_id, 100);
        assert_eq!(user.name, "user100");
        assert_eq!(user.status, Status::Active);
    }
}
