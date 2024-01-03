use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default, Hash, Eq, PartialEq)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub enum EntityType {
    #[default]
    None,
    Role,
    User,
}

#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
#[serde(rename_all(serialize = "snake_case", deserialize = "camelCase"))]
pub struct ServiceAccess {
    pub service_id: u64,
    pub entity_type: EntityType,
    pub entity_id: u64,
}

impl ServiceAccess {
    /// ServiceAccess constructor
    pub fn new(service_id: u64, entity_type: EntityType, entity_id: u64) -> Self {
        Self {
            service_id,
            entity_type,
            entity_id,
        }
    }
}

/// Unit tests
#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn serviceaccess_new_when_entity_is_role() {
        let access = ServiceAccess::new(200, EntityType::Role, 300);
        assert_eq!(access.service_id, 200);
        assert_eq!(access.entity_type, EntityType::Role);
        assert_eq!(access.entity_id, 300);
    }

    #[test]
    fn serviceaccess_new_when_entity_is_user() {
        let access = ServiceAccess::new(200, EntityType::User, 400);
        assert_eq!(access.service_id, 200);
        assert_eq!(access.entity_type, EntityType::User);
        assert_eq!(access.entity_id, 400);
    }
}
