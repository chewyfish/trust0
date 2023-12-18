use std::collections::HashMap;
use std::fs;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::repository::user_repo::UserRepository;
use trust0_common::error::AppError;
use trust0_common::model::user::User;

pub struct InMemUserRepo {
    users: RwLock<HashMap<u64, User>>,
}

impl InMemUserRepo {
    /// Creates a new in-memory user store.
    pub fn new() -> InMemUserRepo {
        InMemUserRepo {
            users: RwLock::new(HashMap::new()),
        }
    }

    fn access_data_for_write(&self) -> Result<RwLockWriteGuard<HashMap<u64, User>>, AppError> {
        self.users.write().map_err(|err| {
            AppError::General(format!("Failed to access write lock to DB: err={}", err))
        })
    }

    fn access_data_for_read(&self) -> Result<RwLockReadGuard<HashMap<u64, User>>, AppError> {
        self.users.read().map_err(|err| {
            AppError::General(format!("Failed to access read lock to DB: err={}", err))
        })
    }
}

impl UserRepository for InMemUserRepo {
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError> {
        let data = fs::read_to_string(connect_spec).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Failed to read file: path={}", connect_spec),
                Box::new(err),
            )
        })?;
        let users: Vec<User> = serde_json::from_str(&data).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Failed to parse JSON: path={}", connect_spec),
                Box::new(err),
            )
        })?;

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
        Ok(data.get(&user_id).cloned())
    }

    fn get_all(&self) -> Result<Vec<User>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data
            .iter()
            .map(|entry| entry.1)
            .cloned()
            .collect::<Vec<User>>())
    }

    fn delete(&self, user_id: u64) -> Result<Option<User>, AppError> {
        let mut data = self.access_data_for_write()?;
        Ok(data.remove(&user_id))
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::user_repo::in_memory_repo::InMemUserRepo;
    use std::path::PathBuf;
    use trust0_common::model::user::{Status, User};

    const VALID_USER_DB_FILE_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "db-user.json"];
    const INVALID_USER_DB_FILE_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "db-user-INVALID.json",
    ];

    #[test]
    fn inmemuserrepo_connect_to_datasource_when_invalid_filepath() {
        let invalid_user_db_path: PathBuf = INVALID_USER_DB_FILE_PATHPARTS.iter().collect();
        let invalid_user_db_pathstr = invalid_user_db_path.to_str().unwrap();

        let mut user_repo = InMemUserRepo::new();

        if let Ok(()) = user_repo.connect_to_datasource(invalid_user_db_pathstr) {
            panic!("Unexpected result: file={}", invalid_user_db_pathstr);
        }
    }

    #[test]
    fn inmemuserrepo_connect_to_datasource_when_valid_filepath() {
        let valid_user_db_path: PathBuf = VALID_USER_DB_FILE_PATHPARTS.iter().collect();
        let valid_user_db_pathstr = valid_user_db_path.to_str().unwrap();

        let mut user_repo = InMemUserRepo::new();

        if let Err(err) = user_repo.connect_to_datasource(valid_user_db_pathstr) {
            panic!(
                "Unexpected result: file={}, err={:?}",
                valid_user_db_pathstr, &err
            );
        }

        let expected_user_db_map: HashMap<u64, User> = HashMap::from([
            (
                100,
                User {
                    user_id: 100,
                    name: "User100".to_string(),
                    status: Status::Active,
                },
            ),
            (
                101,
                User {
                    user_id: 101,
                    name: "User101".to_string(),
                    status: Status::Active,
                },
            ),
        ]);

        let actual_user_db_map: HashMap<u64, User> = HashMap::from_iter(
            user_repo
                .users
                .into_inner()
                .unwrap()
                .iter()
                .map(|e| (e.0.clone(), e.1.clone()))
                .collect::<Vec<(u64, User)>>(),
        );

        assert_eq!(actual_user_db_map.len(), expected_user_db_map.len());
        assert_eq!(
            actual_user_db_map
                .iter()
                .filter(|entry| !expected_user_db_map.contains_key(entry.0))
                .count(),
            0
        );
    }

    #[test]
    fn inmemuserrepo_put() {
        let user_repo = InMemUserRepo::new();
        let user_key = 1;
        let user = User {
            user_id: 1,
            name: "user1".to_string(),
            status: Status::Active,
        };

        if let Err(err) = user_repo.put(user.clone()) {
            panic!("Unexpected result: err={:?}", &err)
        }

        let stored_map = user_repo.users.read().unwrap();
        let stored_entry = stored_map.get(&user_key);

        assert!(stored_entry.is_some());
        assert_eq!(*stored_entry.unwrap(), user);
    }

    #[test]
    fn inmemuserrepo_get_when_invalid_user() {
        let user_repo = InMemUserRepo::new();
        let user_key = 1;
        let user = User {
            user_id: 1,
            name: "user1".to_string(),
            status: Status::Active,
        };

        user_repo.users.write().unwrap().insert(user_key, user);

        let result = user_repo.get(10);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        assert!(result.unwrap().is_none());
    }

    #[test]
    fn inmemuserrepo_get_when_valid_user() {
        let user_repo = InMemUserRepo::new();
        let user_keys = [1, 2, 3];
        let users = [
            User {
                user_id: 1,
                name: "user1".to_string(),
                status: Status::Active,
            },
            User {
                user_id: 2,
                name: "user2".to_string(),
                status: Status::Active,
            },
            User {
                user_id: 3,
                name: "user3".to_string(),
                status: Status::Inactive,
            },
        ];

        user_repo
            .users
            .write()
            .unwrap()
            .insert(user_keys[0], users[0].clone());
        user_repo
            .users
            .write()
            .unwrap()
            .insert(user_keys[1], users[1].clone());
        user_repo
            .users
            .write()
            .unwrap()
            .insert(user_keys[2], users[2].clone());

        let result = user_repo.get(2);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let actual_user = result.unwrap();

        assert!(actual_user.is_some());
        assert_eq!(actual_user.unwrap(), users[1]);
    }

    #[test]
    fn inmemuserrepo_get_all() {
        let user_repo = InMemUserRepo::new();
        let user_keys = [1, 2, 3];
        let users = [
            User {
                user_id: 1,
                name: "user1".to_string(),
                status: Status::Active,
            },
            User {
                user_id: 2,
                name: "user2".to_string(),
                status: Status::Active,
            },
            User {
                user_id: 3,
                name: "user3".to_string(),
                status: Status::Inactive,
            },
        ];

        user_repo
            .users
            .write()
            .unwrap()
            .insert(user_keys[0], users[0].clone());
        user_repo
            .users
            .write()
            .unwrap()
            .insert(user_keys[1], users[1].clone());
        user_repo
            .users
            .write()
            .unwrap()
            .insert(user_keys[2], users[2].clone());

        let result = user_repo.get_all();

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let actual_users = result.unwrap();
        assert_eq!(actual_users.len(), 3);

        let expected_access_db_map: HashMap<u64, User> = HashMap::from([
            (
                1,
                User {
                    user_id: 1,
                    name: "user1".to_string(),
                    status: Status::Active,
                },
            ),
            (
                2,
                User {
                    user_id: 2,
                    name: "user2".to_string(),
                    status: Status::Active,
                },
            ),
            (
                3,
                User {
                    user_id: 3,
                    name: "user3".to_string(),
                    status: Status::Inactive,
                },
            ),
        ]);

        assert_eq!(
            actual_users
                .iter()
                .filter(|entry| !expected_access_db_map.contains_key(&entry.user_id))
                .count(),
            0
        );
    }

    #[test]
    fn inmemuserrepo_delete_when_invalid_user() {
        let user_repo = InMemUserRepo::new();
        let user_key = 1;
        let user = User {
            user_id: 1,
            name: "user1".to_string(),
            status: Status::Active,
        };

        user_repo.users.write().unwrap().insert(user_key, user);

        let result = user_repo.delete(10);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        assert!(result.unwrap().is_none());
    }

    #[test]
    fn inmemuserrepo_delete_when_valid_user() {
        let user_repo = InMemUserRepo::new();
        let user_key = 1;
        let user = User {
            user_id: 1,
            name: "user1".to_string(),
            status: Status::Active,
        };

        user_repo
            .users
            .write()
            .unwrap()
            .insert(user_key, user.clone());

        let result = user_repo.delete(1);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let actual_prev_user = result.unwrap();

        assert!(actual_prev_user.is_some());
        assert_eq!(actual_prev_user.unwrap(), user);
    }
}
