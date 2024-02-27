use trust0_common::error::AppError;
use trust0_common::model::service::Service;

/// Service data repository trait
pub trait ServiceRepository: Sync + Send {
    /// Process given datasource connect string (meaning depends on implementation)
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError>;

    /// Creates/updates a service.
    ///
    /// Returns a updated service (included any new field values auto-generated), otherwise it returns an error.
    fn put(&self, service: Service) -> Result<Service, AppError>;

    /// Gets a service.
    ///
    /// Returns service or None on success, otherwise it returns an error.
    fn get(&self, service_id: i64) -> Result<Option<Service>, AppError>;

    /// Returns the list of all services.
    ///
    /// Returns a copy of the list of service on success, otherwise it returns an error.
    fn get_all(&self) -> Result<Vec<Service>, AppError>;

    /// Deletes a service.
    ///
    /// Returns previous service or None on success, otherwise it returns an error.
    fn delete(&self, service_id: i64) -> Result<Option<Service>, AppError>;
}

/// Unit tests
#[cfg(test)]
pub mod tests {

    use super::*;
    use mockall::mock;

    // mocks
    // =====

    mock! {
        pub ServiceRepo {}
        impl ServiceRepository for ServiceRepo {
            fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError>;
            fn put(&self, service: Service) -> Result<Service, AppError>;
            fn get(&self, service_id: i64) -> Result<Option<Service>, AppError>;
            fn get_all(&self) -> Result<Vec<Service>, AppError>;
            fn delete(&self, service_id: i64) -> Result<Option<Service>, AppError>;
        }
    }
}
