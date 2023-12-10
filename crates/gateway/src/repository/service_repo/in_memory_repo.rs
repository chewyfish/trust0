use std::collections::HashMap;
use std::fs;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use trust0_common::error::AppError;
use trust0_common::model::service::Service;
use crate::repository::service_repo::ServiceRepository;

pub struct InMemServiceRepo {
    services: RwLock<HashMap<u64, Service>>,
}

impl InMemServiceRepo {

    /// Creates a new in-memory service store.
    pub fn new() -> InMemServiceRepo {
        InMemServiceRepo {
            services: RwLock::new(HashMap::new())
        }
    }

    fn access_data_for_write(&self) -> Result<RwLockWriteGuard<HashMap<u64, Service>>, AppError> {
        self.services.write().map_err(|err|
            AppError::General(format!("Failed to access write lock to DB: err={}", err)))
    }

    fn access_data_for_read(&self) -> Result<RwLockReadGuard<HashMap<u64, Service>>, AppError> {
        self.services.read().map_err(|err|
            AppError::General(format!("Failed to access read lock to DB: err={}", err)))
    }
}

impl ServiceRepository for InMemServiceRepo {

    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError> {

        let data = fs::read_to_string(connect_spec).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed to read file: path={}", connect_spec), Box::new(err)))?;
        let services: Vec<Service> = serde_json::from_str(&data).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed to parse JSON: path={}", connect_spec), Box::new(err)))?;

        for service in services.iter().as_ref() {
            self.put(service.clone())?;
        }

        Ok(())
    }

    fn put(&self, service: Service) -> Result<Option<Service>, AppError> {
        let mut data = self.access_data_for_write()?;
        Ok(data.insert(service.service_id, service.clone()))
    }

    fn get(&self, service_id: u64) -> Result<Option<Service>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data.get(&service_id).map(|service| service.clone()))
    }

    fn get_all(&self) -> Result<Vec<Service>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data.iter()
            .map(|entry| entry.1)
            .cloned()
            .collect::<Vec<Service>>())
    }

    fn delete(&self, service_id: u64) -> Result<Option<Service>, AppError> {
        let mut data = self.access_data_for_write()?;
        Ok(data.remove(&service_id))
    }
}
