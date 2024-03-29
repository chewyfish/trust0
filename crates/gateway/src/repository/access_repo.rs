use trust0_common::error::AppError;
use trust0_common::model::access::{EntityType, ServiceAccess};
use trust0_common::model::user::User;

/// Access data repository trait
pub trait AccessRepository: Sync + Send {
    /// Process given datasource connect string (meaning depends on implementation)
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError>;

    /// Creates/updates a service access.
    ///
    /// Returns a updated service (included any new field values auto-generated), otherwise it returns an error.
    fn put(&self, access: ServiceAccess) -> Result<ServiceAccess, AppError>;

    /// Gets a service access.
    ///
    /// Returns access or None on success, otherwise it returns an error.
    fn get(
        &self,
        service_id: i64,
        entity_type: &EntityType,
        entity_id: i64,
    ) -> Result<Option<ServiceAccess>, AppError>;

    /// Returns a service access for a user if it is accessible.
    ///
    /// Returns access or None on success, otherwise it returns an error.
    fn get_for_user(&self, service_id: i64, user: &User)
        -> Result<Option<ServiceAccess>, AppError>;

    /// Returns the list of all accessible service accesses for a user (either directly or based on associated role)
    ///
    /// Returns a copy of the list of service accesses on success, otherwise it returns an error.
    fn get_all_for_user(&self, user: &User) -> Result<Vec<ServiceAccess>, AppError>;

    /// Deletes a service access.
    ///
    /// Returns previous service access or None on success, otherwise it returns an error.
    fn delete(
        &self,
        service_id: i64,
        entity_type: &EntityType,
        entity_id: i64,
    ) -> Result<Option<ServiceAccess>, AppError>;
}

/// Unit tests
#[cfg(test)]
pub mod tests {

    use super::*;
    use mockall::mock;

    // mocks
    // =====

    mock! {
        pub AccessRepo {}
        impl AccessRepository for AccessRepo {
            fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError>;
            fn put(&self, access: ServiceAccess) -> Result<ServiceAccess, AppError>;
            fn get(&self, service_id: i64, entity_type: &EntityType, entity_id: i64) -> Result<Option<ServiceAccess>, AppError>;
            fn get_for_user(&self, service_id: i64, user: &User) -> Result<Option<ServiceAccess>, AppError>;
            fn get_all_for_user(&self, user: &User) -> Result<Vec<ServiceAccess>, AppError>;
            fn delete(&self, service_id: i64, entity_type: &EntityType, entity_id: i64) -> Result<Option<ServiceAccess>, AppError>;
        }
    }
}
