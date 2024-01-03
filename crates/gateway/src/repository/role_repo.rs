pub mod in_memory_repo;

use trust0_common::error::AppError;
use trust0_common::model::role::Role;

/// Role data repository trait
pub trait RoleRepository: Sync + Send {
    /// Process given datasource connect string (meaning depends on implementation)
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError>;

    /// Creates/updates a role.
    ///
    /// Returns a previous role for this id or None on success, otherwise it returns an error.
    fn put(&self, role: Role) -> Result<Option<Role>, AppError>;

    /// Gets a role.
    ///
    /// Returns role or None on success, otherwise it returns an error.
    fn get(&self, role_id: u64) -> Result<Option<Role>, AppError>;

    /// Returns the list of all roles.
    ///
    /// Returns a copy of the list of role on success, otherwise it returns an error.
    fn get_all(&self) -> Result<Vec<Role>, AppError>;

    /// Deletes a role.
    ///
    /// Returns previous role or None on success, otherwise it returns an error.
    fn delete(&self, role_id: u64) -> Result<Option<Role>, AppError>;
}

/// Unit tests
#[cfg(test)]
pub mod tests {

    use super::*;
    use mockall::mock;

    // mocks
    // =====

    mock! {
        pub RoleRepo {}
        impl RoleRepository for RoleRepo {
            fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError>;
            fn put(&self, role: Role) -> Result<Option<Role>, AppError>;
            fn get(&self, role_id: u64) -> Result<Option<Role>, AppError>;
            fn get_all(&self) -> Result<Vec<Role>, AppError>;
            fn delete(&self, role_id: u64) -> Result<Option<Role>, AppError>;
        }
    }
}
