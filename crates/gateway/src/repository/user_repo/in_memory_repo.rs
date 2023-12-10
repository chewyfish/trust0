use std::collections::HashMap;
use std::fs;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use trust0_common::error::AppError;
use trust0_common::model::user::User;
use crate::repository::user_repo::UserRepository;

pub struct InMemUserRepo {
    users: RwLock<HashMap<u64, User>>,
}

impl InMemUserRepo {

    /// Creates a new in-memory user store.
    pub fn new() -> InMemUserRepo {
        InMemUserRepo {
            users: RwLock::new(HashMap::new())
        }
    }

    fn access_data_for_write(&self) -> Result<RwLockWriteGuard<HashMap<u64, User>>, AppError> {
        self.users.write().map_err(|err|
            AppError::General(format!("Failed to access write lock to DB: err={}", err)))
    }

    fn access_data_for_read(&self) -> Result<RwLockReadGuard<HashMap<u64, User>>, AppError> {
        self.users.read().map_err(|err|
            AppError::General(format!("Failed to access read lock to DB: err={}", err)))
    }
}

impl UserRepository for InMemUserRepo {

    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError> {

        let data = fs::read_to_string(connect_spec).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed to read file: path={}", connect_spec), Box::new(err)))?;
        let users: Vec<User> = serde_json::from_str(&data).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed to parse JSON: path={}", connect_spec), Box::new(err)))?;

        for user in users.iter().as_ref() {
            self.put(user.clone())?;
        }

        Ok(())
    }

    fn put(&self, user: User) -> Result<Option<User>, AppError> {
        let mut data = self.access_data_for_write()?;
        Ok(data.insert(user.user_id, user.clone()))
    }

    fn get(&self, user_id: u64) -> Result<Option<User>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data.get(&user_id).map(|user| user.clone()))
    }

    fn get_all(&self) -> Result<Vec<User>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data.iter()
            .map(|entry| entry.1)
            .cloned()
            .collect::<Vec<User>>())
    }

    fn delete(&self, user_id: u64) -> Result<Option<User>, AppError> {
        let mut data = self.access_data_for_write()?;
        Ok(data.remove(&user_id))
    }
}
