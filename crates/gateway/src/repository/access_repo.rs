pub mod in_memory_repo;

use trust0_common::error::AppError;
use trust0_common::model::access::ServiceAccess;

/// Access data repository trait
pub trait AccessRepository: Sync + Send {

    /// Process given datasource connect string (meaning depends on implementation)
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError>;

    /// Creates/updates a service access.
    ///
    /// Returns a previous service access for this id or None on success, otherwise it returns an error.
    fn put(&self, access: ServiceAccess) -> Result<Option<ServiceAccess>, AppError>;

    /// Gets a service access.
    ///
    /// Returns access or None on success, otherwise it returns an error.
    fn get(&self, user_id: u64, service_id: u64) -> Result<Option<ServiceAccess>, AppError>;

    /// Returns the list of all service accesses that belong to a user.
    ///
    /// Returns a copy of the list of service accesses on success, otherwise it returns an error.
    fn get_all_for_user(&self, user_id: u64) -> Result<Vec<ServiceAccess>, AppError>;

    /// Deletes a service access.
    ///
    /// Returns previous service access or None on success, otherwise it returns an error.
    fn delete(&self, user_id: u64, service_id: u64) -> Result<Option<ServiceAccess>, AppError>;
}

/// Unit tests
#[cfg(test)]
pub mod tests {

    use mockall::mock;
    use super::*;

    // mocks
    // =====

    mock! {
        pub AccessRepo {}
        impl AccessRepository for AccessRepo {
            fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError>;
            fn put(&self, access: ServiceAccess) -> Result<Option<ServiceAccess>, AppError>;
            fn get(&self, user_id: u64, service_id: u64) -> Result<Option<ServiceAccess>, AppError>;
            fn get_all_for_user(&self, user_id: u64) -> Result<Vec<ServiceAccess>, AppError>;
            fn delete(&self, user_id: u64, service_id: u64) -> Result<Option<ServiceAccess>, AppError>;
        }
    }
}