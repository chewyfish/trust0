use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::repository::user_repo::UserRepository;
use trust0_common::error::AppError;
use trust0_common::file::{ReloadableFile, ReloadableTextFile};
use trust0_common::logging::error;
use trust0_common::model::user::User;
use trust0_common::target;

pub struct InMemUserRepo {
    users: RwLock<HashMap<i64, User>>,
    source_file: Option<String>,
    reloader_loading: Arc<Mutex<bool>>,
    reloader_new_data: Arc<Mutex<String>>,
}

impl InMemUserRepo {
    /// Creates a new in-memory user store.
    pub fn new() -> InMemUserRepo {
        let reloader_loading = Arc::new(Mutex::new(false));
        let reloader_new_data = Arc::new(Mutex::new(String::new()));
        InMemUserRepo {
            users: RwLock::new(HashMap::new()),
            source_file: None,
            reloader_loading,
            reloader_new_data,
        }
    }

    fn access_data_for_write(&self) -> Result<RwLockWriteGuard<'_, HashMap<i64, User>>, AppError> {
        if let Err(err) = self.process_source_data_updates() {
            error(
                &target!(),
                &format!("Error processing updates: err={:?}", &err),
            );
        }
        self.users.write().map_err(|err| {
            AppError::General(format!("Failed to access write lock to DB: err={}", err))
        })
    }

    fn access_data_for_read(&self) -> Result<RwLockReadGuard<'_, HashMap<i64, User>>, AppError> {
        if let Err(err) = self.process_source_data_updates() {
            error(
                &target!(),
                &format!("Error processing updates: err={:?}", &err),
            );
        }
        self.users.read().map_err(|err| {
            AppError::General(format!("Failed to access read lock to DB: err={}", err))
        })
    }

    /// If new (unparsed JSON) data has been queued by the reloader, replace DB accordingly
    fn process_source_data_updates(&self) -> Result<(), AppError> {
        // Check if new data is pending
        if self.reloader_new_data.lock().unwrap().is_empty() {
            return Ok(());
        }

        // Parse new (JSON) data
        let users: Vec<User> = serde_json::from_str(
            self.reloader_new_data.lock().unwrap().as_str(),
        )
        .map_err(|err| {
            AppError::General(format!(
                "Failed to parse JSON: path={}, err={:?}",
                &self.source_file.as_ref().unwrap(),
                &err
            ))
        })?;

        // Update database
        let mut data = self.users.write().map_err(|err| {
            AppError::General(format!(
                "Failed to access write lock to DB: path={}, err={}",
                self.source_file.as_ref().unwrap(),
                err
            ))
        })?;

        data.clear();
        for user in users.iter().as_ref() {
            data.insert(user.user_id, user.clone());
        }

        self.reloader_new_data.lock().unwrap().clear();

        Ok(())
    }
}

impl UserRepository for InMemUserRepo {
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError> {
        // Load DB from JSON file
        self.source_file = Some(connect_spec.to_string());

        let data = fs::read_to_string(connect_spec).map_err(|err| {
            AppError::General(format!(
                "Failed to read file: path={}, err={:?}",
                connect_spec, &err
            ))
        })?;
        let users: Vec<User> = serde_json::from_str(&data).map_err(|err| {
            AppError::General(format!(
                "Failed to parse JSON: path={}, err={:?}",
                connect_spec, &err
            ))
        })?;

        for user in users.iter().as_ref() {
            self.put(user.clone())?;
        }

        // Spawn DB reload thread
        let reloadable_file = ReloadableTextFile::new(
            connect_spec,
            &self.reloader_new_data,
            &self.reloader_loading,
        )?;

        <ReloadableTextFile as ReloadableFile>::spawn_reloader(reloadable_file, None);

        Ok(())
    }

    fn put(&self, user: User) -> Result<User, AppError> {
        let mut data = self.access_data_for_write()?;
        let mut user = user.clone();

        if user.user_id == 0 {
            let next_id = data.values().map(|r| r.user_id + 1).max();
            user.user_id = next_id.unwrap_or(1);
        }

        _ = data.insert(user.user_id, user.clone());
        Ok(user)
    }

    fn get(&self, user_id: i64) -> Result<Option<User>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data.get(&user_id).cloned())
    }

    fn delete(&self, user_id: i64) -> Result<Option<User>, AppError> {
        let mut data = self.access_data_for_write()?;
        Ok(data.remove(&user_id))
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use trust0_common::model::user::{Status, User};

    const VALID_USER_DB_FILE_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "trust0-db-user.json",
    ];
    const INVALID_USER_DB_FILE_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "trust0-db-user-INVALID.json",
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

        let expected_user_db_map: HashMap<i64, User> = HashMap::from([
            (
                100,
                User {
                    user_id: 100,
                    user_name: Some("uname100".to_string()),
                    password: Some("pass100".to_string()),
                    name: "User100".to_string(),
                    status: Status::Active,
                    roles: vec![60, 61],
                },
            ),
            (
                101,
                User {
                    user_id: 101,
                    user_name: Some("uname101".to_string()),
                    password: Some("pass101".to_string()),
                    name: "User101".to_string(),
                    status: Status::Active,
                    roles: vec![],
                },
            ),
        ]);

        let actual_user_db_map: HashMap<i64, User> = HashMap::from_iter(
            user_repo
                .users
                .into_inner()
                .unwrap()
                .iter()
                .map(|e| (e.0.clone(), e.1.clone()))
                .collect::<Vec<(i64, User)>>(),
        );

        assert_eq!(actual_user_db_map.len(), expected_user_db_map.len());
        assert_eq!(
            actual_user_db_map
                .iter()
                .filter(|entry| !expected_user_db_map.contains_key(entry.0))
                .count(),
            0
        );

        *user_repo.reloader_loading.lock().unwrap() = false;
    }

    #[test]
    fn inmemuserrepo_process_source_data_updates_when_valid_json() {
        let valid_user_db_path: PathBuf = VALID_USER_DB_FILE_PATHPARTS.iter().collect();
        let valid_user_db_pathstr = valid_user_db_path.to_str().unwrap();

        let mut user_repo = InMemUserRepo::new();

        if let Err(err) = user_repo.connect_to_datasource(valid_user_db_pathstr) {
            panic!(
                "Unexpected result: file={}, err={:?}",
                valid_user_db_pathstr, &err
            );
        }

        assert_eq!(user_repo.users.read().unwrap().len(), 2);

        *user_repo.reloader_new_data.lock().unwrap() =
            "[{\"userId\": 800, \"userName\": \"user800\", \"password\": \"pass800\", \"name\": \"User800\", \"status\": \"inactive\", \"roles\": [600]}]".to_string();

        if let Err(err) = user_repo.process_source_data_updates() {
            panic!("Unexpected process updates result: err={:?}", &err);
        }

        let expected_user_db_map: HashMap<i64, User> = HashMap::from([(
            800,
            User {
                user_id: 800,
                user_name: Some("uname800".to_string()),
                password: Some("pass800".to_string()),
                name: "User800".to_string(),
                status: Status::Inactive,
                roles: vec![600],
            },
        )]);

        let actual_user_db_map: HashMap<i64, User> = HashMap::from_iter(
            user_repo
                .users
                .into_inner()
                .unwrap()
                .iter()
                .map(|e| (e.0.clone(), e.1.clone()))
                .collect::<Vec<(i64, User)>>(),
        );

        assert_eq!(actual_user_db_map.len(), expected_user_db_map.len());
        assert_eq!(
            actual_user_db_map
                .iter()
                .filter(|entry| !expected_user_db_map.contains_key(entry.0))
                .count(),
            0
        );

        *user_repo.reloader_loading.lock().unwrap() = false;
    }

    #[test]
    fn inmemuserrepo_process_source_data_updates_when_invalid_json() {
        let valid_user_db_path: PathBuf = VALID_USER_DB_FILE_PATHPARTS.iter().collect();
        let valid_user_db_pathstr = valid_user_db_path.to_str().unwrap();

        let mut user_repo = InMemUserRepo::new();

        if let Err(err) = user_repo.connect_to_datasource(valid_user_db_pathstr) {
            panic!(
                "Unexpected result: file={}, err={:?}",
                valid_user_db_pathstr, &err
            );
        }

        assert_eq!(user_repo.users.read().unwrap().len(), 2);

        *user_repo.reloader_new_data.lock().unwrap() =
            "[{\"userId\": 800, \"userName\": \"user800\", \"password\": \"pass800\", \"name\": \"User800\", \"status\": \"inactive\", \"roles\": [600]}"
                .to_string();

        if let Ok(()) = user_repo.process_source_data_updates() {
            panic!(
                "Unexpected successful process updates result: file={}",
                valid_user_db_pathstr
            );
        }

        assert_eq!(user_repo.users.read().unwrap().len(), 2);

        *user_repo.reloader_loading.lock().unwrap() = false;
    }

    #[test]
    fn inmemuserrepo_put() {
        let user_repo = InMemUserRepo::new();
        let user_key = 1;
        let user = User {
            user_id: 1,
            user_name: Some("uname1".to_string()),
            password: Some("pass1".to_string()),
            name: "user1".to_string(),
            status: Status::Active,
            roles: vec![60, 61],
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
    fn inmemuserrepo_put_when_existing_role() {
        let user_repo = InMemUserRepo::new();
        let user_key = 1;
        let mut user = User {
            user_id: 1,
            user_name: Some("uname1".to_string()),
            password: Some("pass1".to_string()),
            name: "user1".to_string(),
            status: Status::Active,
            roles: vec![60, 61],
        };
        user_repo
            .users
            .write()
            .unwrap()
            .insert(user_key, user.clone());
        user.name = "user1.1".to_string();

        let result = user_repo.put(user.clone());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let returned_user = result.unwrap();

        let stored_map = user_repo.users.read().unwrap();
        let stored_entry = stored_map.get(&user_key);

        assert!(stored_entry.is_some());
        assert_eq!(*stored_entry.unwrap(), user);
        assert_eq!(returned_user, user);
    }

    #[test]
    fn inmemuserrepo_put_when_new_role_and_given_id() {
        let user_repo = InMemUserRepo::new();
        let user_key = 1;
        let user = User {
            user_id: 1,
            user_name: Some("uname1".to_string()),
            password: Some("pass1".to_string()),
            name: "user1".to_string(),
            status: Status::Active,
            roles: vec![60, 61],
        };

        let result = user_repo.put(user.clone());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let returned_user = result.unwrap();

        let stored_map = user_repo.users.read().unwrap();
        let stored_entry = stored_map.get(&user_key);

        assert!(stored_entry.is_some());
        assert_eq!(*stored_entry.unwrap(), user);
        assert_eq!(returned_user, user);
    }

    #[test]
    fn inmemuserrepo_put_when_new_role_and_not_given_id_and_empty_db() {
        let user_repo = InMemUserRepo::new();
        let mut user = User {
            user_id: 0,
            user_name: Some("unameXX".to_string()),
            password: Some("passXX".to_string()),
            name: "userXX".to_string(),
            status: Status::Active,
            roles: vec![60, 61],
        };

        let result = user_repo.put(user.clone());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let returned_user = result.unwrap();

        let stored_map = user_repo.users.read().unwrap();
        let stored_entry = stored_map.iter().map(|e| e.1).cloned().next();

        user.user_id = 1;

        assert!(stored_entry.is_some());
        assert_eq!(stored_entry.unwrap(), user);
        assert_eq!(returned_user, user);
    }

    #[test]
    fn inmemuserrepo_put_when_new_role_and_not_given_id_and_non_empty_db() {
        let user_repo = InMemUserRepo::new();
        let user1 = User {
            user_id: 1,
            user_name: Some("uname1".to_string()),
            password: Some("pass1".to_string()),
            name: "user1".to_string(),
            status: Status::Active,
            roles: vec![60, 61],
        };
        let user2 = User {
            user_id: 2,
            user_name: Some("uname2".to_string()),
            password: Some("pass2".to_string()),
            name: "user2".to_string(),
            status: Status::Active,
            roles: vec![160, 161],
        };
        user_repo.users.write().unwrap().insert(60, user1.clone());
        user_repo.users.write().unwrap().insert(61, user2.clone());

        let mut user = User {
            user_id: 0,
            user_name: Some("unameXX".to_string()),
            password: Some("passXX".to_string()),
            name: "userXX".to_string(),
            status: Status::Active,
            roles: vec![60, 61],
        };

        let result = user_repo.put(user.clone());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let returned_user = result.unwrap();

        user.user_id = 3;

        assert_eq!(returned_user, user);
    }

    #[test]
    fn inmemuserrepo_get_when_invalid_user() {
        let user_repo = InMemUserRepo::new();
        let user_key = 1;
        let user = User {
            user_id: 1,
            user_name: Some("uname1".to_string()),
            password: Some("pass1".to_string()),
            name: "user1".to_string(),
            status: Status::Active,
            roles: vec![60, 61],
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
                user_name: Some("uname1".to_string()),
                password: Some("pass1".to_string()),
                name: "user1".to_string(),
                status: Status::Active,
                roles: vec![60],
            },
            User {
                user_id: 2,
                user_name: Some("uname2".to_string()),
                password: Some("pass2".to_string()),
                name: "user2".to_string(),
                status: Status::Active,
                roles: vec![],
            },
            User {
                user_id: 3,
                user_name: Some("uname3".to_string()),
                password: Some("pass3".to_string()),
                name: "user3".to_string(),
                status: Status::Inactive,
                roles: vec![61, 62],
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
    fn inmemuserrepo_delete_when_invalid_user() {
        let user_repo = InMemUserRepo::new();
        let user_key = 1;
        let user = User {
            user_id: 1,
            user_name: Some("uname1".to_string()),
            password: Some("pass1".to_string()),
            name: "user1".to_string(),
            status: Status::Active,
            roles: vec![],
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
            user_name: Some("uname1".to_string()),
            password: Some("pass1".to_string()),
            name: "user1".to_string(),
            status: Status::Active,
            roles: vec![60, 61],
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
