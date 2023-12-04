use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct User {
    pub user_id: u64,
    pub name: String,
    pub status: Status
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub enum Status {
    Active,
    Inactive
}

impl Default for Status {
    fn default() -> Self { Status::Active }
}

impl User {

    /// User constructor
    pub fn new(
        user_id: u64,
        name: &str,
        status: Status) -> Self {

        Self {
            user_id,
            name: name.to_string(),
            status
        }
    }
}
