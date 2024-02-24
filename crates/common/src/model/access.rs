use serde_derive::{Deserialize, Serialize};

/// RBAC entity type
#[derive(Serialize, Deserialize, Clone, Debug, Default, Hash, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum EntityType {
    /// No type specified
    #[default]
    None,
    /// Role-based entity
    Role,
    /// User-based entity
    User,
}

/// Service access model struct
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccess {
    /// Service ID (unique across services)
    pub service_id: i64,
    /// RBAC entity type
    pub entity_type: EntityType,
    /// Entity ID (either role ID or user ID)
    pub entity_id: i64,
}

impl ServiceAccess {
    /// ServiceAccess constructor
    ///
    /// # Arguments
    ///
    /// * `service_id` - Service ID (unique across services)
    /// * `entity_type` - RBAC entity type
    /// * `entity_id` - Entity ID (either role ID or user ID)
    ///
    /// # Returns
    ///
    /// A newly constructed [`ServiceAccess`] object.
    ///
    pub fn new(service_id: i64, entity_type: &EntityType, entity_id: i64) -> Self {
        Self {
            service_id,
            entity_type: entity_type.clone(),
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
        let access = ServiceAccess::new(200, &EntityType::Role, 300);
        assert_eq!(access.service_id, 200);
        assert_eq!(access.entity_type, EntityType::Role);
        assert_eq!(access.entity_id, 300);
    }

    #[test]
    fn serviceaccess_new_when_entity_is_user() {
        let access = ServiceAccess::new(200, &EntityType::User, 400);
        assert_eq!(access.service_id, 200);
        assert_eq!(access.entity_type, EntityType::User);
        assert_eq!(access.entity_id, 400);
    }
}
