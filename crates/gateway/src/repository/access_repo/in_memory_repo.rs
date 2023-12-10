use std::collections::HashMap;
use std::fs;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use trust0_common::error::AppError;
use trust0_common::model::access::ServiceAccess;
use crate::repository::access_repo::AccessRepository;

pub struct InMemAccessRepo {
    accesses: RwLock<HashMap<(u64,u64), ServiceAccess>>,
}

impl InMemAccessRepo {

    /// Creates a new in-memory service access store.
    pub fn new() -> InMemAccessRepo {
        InMemAccessRepo {
            accesses: RwLock::new(HashMap::new())
        }
    }

    fn access_data_for_write(&self) -> Result<RwLockWriteGuard<HashMap<(u64,u64), ServiceAccess>>, AppError> {
        self.accesses.write().map_err(|err|
            AppError::General(format!("Failed to access write lock to DB: err={}", err)))
    }

    fn access_data_for_read(&self) -> Result<RwLockReadGuard<HashMap<(u64,u64), ServiceAccess>>, AppError> {
        self.accesses.read().map_err(|err|
            AppError::General(format!("Failed to access read lock to DB: err={}", err)))
    }
}

impl AccessRepository for InMemAccessRepo {

    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError> {

        let data = fs::read_to_string(connect_spec).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed to read file: path={}", connect_spec), Box::new(err)))?;
        let accesses: Vec<ServiceAccess> = serde_json::from_str(&data).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed to parse JSON: path={}", connect_spec), Box::new(err)))?;

        for access in accesses.iter().as_ref() {
            self.put(access.clone())?;
        }

        Ok(())
    }

    fn put(&self, access: ServiceAccess) -> Result<Option<ServiceAccess>, AppError> {
        let mut data = self.access_data_for_write()?;
        Ok(data.insert((access.user_id,access.service_id), access.clone()))
    }

    fn get(&self, user_id: u64, service_id: u64) -> Result<Option<ServiceAccess>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data.get(&(user_id, service_id)).map(|access| access.clone()))
    }

    fn get_all_for_user(&self, user_id: u64) -> Result<Vec<ServiceAccess>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data.iter()
            .filter(|entry| entry.0.0 == user_id)
            .map(|entry| entry.1)
            .cloned()
            .collect::<Vec<ServiceAccess>>())
    }

    fn delete(&self, user_id: u64, service_id: u64) -> Result<Option<ServiceAccess>, AppError> {
        let mut data = self.access_data_for_write()?;
        Ok(data.remove(&(user_id, service_id)))
    }
}
