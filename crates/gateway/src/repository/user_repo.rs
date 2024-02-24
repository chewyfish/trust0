use trust0_common::error::AppError;
use trust0_common::model::user::User;

/// User data repository trait
pub trait UserRepository: Sync + Send {
    /// Process given datasource connect string (meaning depends on implementation)
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError>;

    /// Creates/updates a user.
    ///
    /// Returns a previous user for this id or None on success, otherwise it returns an error.
    fn put(&self, user: User) -> Result<Option<User>, AppError>;

    /// Gets an user.
    ///
    /// Returns user or None on success, otherwise it returns an error.
    fn get(&self, user_id: u64) -> Result<Option<User>, AppError>;

    /// Returns the list of all users.
    ///
    /// Returns a copy of the list of users on success, otherwise it returns an error.
    fn get_all(&self) -> Result<Vec<User>, AppError>;

    /// Deletes a user.
    ///
    /// Returns previous user or None on success, otherwise it returns an error.
    fn delete(&self, user_id: u64) -> Result<Option<User>, AppError>;
}

/// Unit tests
#[cfg(test)]
pub mod tests {

    use super::*;
    use mockall::mock;

    // mocks
    // =====

    mock! {
        pub UserRepo {}
        impl UserRepository for UserRepo {
            fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError>;
            fn put(&self, user: User) -> Result<Option<User>, AppError>;
            fn get(&self, user_id: u64) -> Result<Option<User>, AppError>;
            fn get_all(&self) -> Result<Vec<User>, AppError>;
            fn delete(&self, user_id: u64) -> Result<Option<User>, AppError>;
        }
    }
}
