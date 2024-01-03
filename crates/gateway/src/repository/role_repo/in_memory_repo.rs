use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::repository::role_repo::RoleRepository;
use trust0_common::error::AppError;
use trust0_common::file::{ReloadableFile, ReloadableTextFile};
use trust0_common::logging::error;
use trust0_common::model::role::Role;
use trust0_common::target;

pub struct InMemRoleRepo {
    roles: RwLock<HashMap<u64, Role>>,
    source_file: Option<String>,
    reloader_loading: Arc<Mutex<bool>>,
    reloader_new_data: Arc<Mutex<String>>,
}

impl InMemRoleRepo {
    /// Creates a new in-memory role store.
    #[allow(dead_code)]
    pub fn new() -> InMemRoleRepo {
        let reloader_loading = Arc::new(Mutex::new(false));
        let reloader_new_data = Arc::new(Mutex::new(String::new()));
        InMemRoleRepo {
            roles: RwLock::new(HashMap::new()),
            source_file: None,
            reloader_loading,
            reloader_new_data,
        }
    }

    fn access_data_for_write(&self) -> Result<RwLockWriteGuard<HashMap<u64, Role>>, AppError> {
        if let Err(err) = self.process_source_data_updates() {
            error(
                &target!(),
                &format!("Error processing updates: err={:?}", &err),
            );
        }
        self.roles.write().map_err(|err| {
            AppError::General(format!("Failed to access write lock to DB: err={}", err))
        })
    }

    fn access_data_for_read(&self) -> Result<RwLockReadGuard<HashMap<u64, Role>>, AppError> {
        if let Err(err) = self.process_source_data_updates() {
            error(
                &target!(),
                &format!("Error processing updates: err={:?}", &err),
            );
        }
        self.roles.read().map_err(|err| {
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
        let roles: Vec<Role> = serde_json::from_str(
            self.reloader_new_data.lock().unwrap().as_str(),
        )
        .map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!(
                    "Failed to parse JSON: path={}",
                    &self.source_file.as_ref().unwrap()
                ),
                Box::new(err),
            )
        })?;

        // Update database
        let mut data = self.roles.write().map_err(|err| {
            AppError::General(format!(
                "Failed to access write lock to DB: path={}, err={}",
                self.source_file.as_ref().unwrap(),
                err
            ))
        })?;

        data.clear();
        for role in roles.iter().as_ref() {
            data.insert(role.role_id, role.clone());
        }

        self.reloader_new_data.lock().unwrap().clear();

        Ok(())
    }
}

impl RoleRepository for InMemRoleRepo {
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError> {
        // Load DB from JSON file
        self.source_file = Some(connect_spec.to_string());

        let data = fs::read_to_string(connect_spec).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Failed to read file: path={}", connect_spec),
                Box::new(err),
            )
        })?;
        let roles: Vec<Role> = serde_json::from_str(&data).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Failed to parse JSON: path={}", connect_spec),
                Box::new(err),
            )
        })?;

        for role in roles.iter().as_ref() {
            self.put(role.clone())?;
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

    fn put(&self, role: Role) -> Result<Option<Role>, AppError> {
        let mut data = self.access_data_for_write()?;
        Ok(data.insert(role.role_id, role.clone()))
    }

    fn get(&self, role_id: u64) -> Result<Option<Role>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data.get(&role_id).cloned())
    }

    fn get_all(&self) -> Result<Vec<Role>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data
            .iter()
            .map(|entry| entry.1)
            .cloned()
            .collect::<Vec<Role>>())
    }

    fn delete(&self, role_id: u64) -> Result<Option<Role>, AppError> {
        let mut data = self.access_data_for_write()?;
        Ok(data.remove(&role_id))
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const VALID_ROLE_DB_FILE_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "db-role.json"];
    const INVALID_ROLE_DB_FILE_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "db-role-INVALID.json",
    ];

    #[test]
    fn inmemsvcrepo_connect_to_datasource_when_invalid_filepath() {
        let invalid_role_db_path: PathBuf = INVALID_ROLE_DB_FILE_PATHPARTS.iter().collect();
        let invalid_role_db_pathstr = invalid_role_db_path.to_str().unwrap();

        let mut role_repo = InMemRoleRepo::new();

        if let Ok(()) = role_repo.connect_to_datasource(invalid_role_db_pathstr) {
            panic!("Unexpected result: file={}", invalid_role_db_pathstr);
        }
    }

    #[test]
    fn inmemsvcrepo_connect_to_datasource_when_valid_filepath() {
        let valid_role_db_path: PathBuf = VALID_ROLE_DB_FILE_PATHPARTS.iter().collect();
        let valid_role_db_pathstr = valid_role_db_path.to_str().unwrap();

        let mut role_repo = InMemRoleRepo::new();

        if let Err(err) = role_repo.connect_to_datasource(valid_role_db_pathstr) {
            panic!(
                "Unexpected result: file={}, err={:?}",
                valid_role_db_pathstr, &err
            );
        }

        let expected_role_db_map: HashMap<u64, Role> = HashMap::from([
            (
                50,
                Role {
                    role_id: 50,
                    name: "Role51".to_string(),
                },
            ),
            (
                51,
                Role {
                    role_id: 51,
                    name: "Role51".to_string(),
                },
            ),
        ]);

        let actual_role_db_map: HashMap<u64, Role> = HashMap::from_iter(
            role_repo
                .roles
                .into_inner()
                .unwrap()
                .iter()
                .map(|e| (e.0.clone(), e.1.clone()))
                .collect::<Vec<(u64, Role)>>(),
        );

        assert_eq!(actual_role_db_map.len(), expected_role_db_map.len());
        assert_eq!(
            actual_role_db_map
                .iter()
                .filter(|entry| !expected_role_db_map.contains_key(entry.0))
                .count(),
            0
        );

        *role_repo.reloader_loading.lock().unwrap() = false;
    }

    #[test]
    fn inmemsvcrepo_process_source_data_updates_when_valid_json() {
        let valid_role_db_path: PathBuf = VALID_ROLE_DB_FILE_PATHPARTS.iter().collect();
        let valid_role_db_pathstr = valid_role_db_path.to_str().unwrap();

        let mut role_repo = InMemRoleRepo::new();

        if let Err(err) = role_repo.connect_to_datasource(valid_role_db_pathstr) {
            panic!(
                "Unexpected result: file={}, err={:?}",
                valid_role_db_pathstr, &err
            );
        }

        assert_eq!(role_repo.roles.read().unwrap().len(), 2);

        *role_repo.reloader_new_data.lock().unwrap() =
            "[{\"roleId\": 60, \"name\":  \"Role60\"}]".to_string();

        if let Err(err) = role_repo.process_source_data_updates() {
            panic!("Unexpected process updates result: err={:?}", &err);
        }

        let expected_role_db_map: HashMap<u64, Role> = HashMap::from([(
            60,
            Role {
                role_id: 60,
                name: "Role60".to_string(),
            },
        )]);

        let actual_role_db_map: HashMap<u64, Role> = HashMap::from_iter(
            role_repo
                .roles
                .into_inner()
                .unwrap()
                .iter()
                .map(|e| (e.0.clone(), e.1.clone()))
                .collect::<Vec<(u64, Role)>>(),
        );

        assert_eq!(actual_role_db_map.len(), expected_role_db_map.len());
        assert_eq!(
            actual_role_db_map
                .iter()
                .filter(|entry| !expected_role_db_map.contains_key(entry.0))
                .count(),
            0
        );

        *role_repo.reloader_loading.lock().unwrap() = false;
    }

    #[test]
    fn inmemsvcrepo_process_source_data_updates_when_invalid_json() {
        let valid_role_db_path: PathBuf = VALID_ROLE_DB_FILE_PATHPARTS.iter().collect();
        let valid_role_db_pathstr = valid_role_db_path.to_str().unwrap();

        let mut role_repo = InMemRoleRepo::new();

        if let Err(err) = role_repo.connect_to_datasource(valid_role_db_pathstr) {
            panic!(
                "Unexpected result: file={}, err={:?}",
                valid_role_db_pathstr, &err
            );
        }

        assert_eq!(role_repo.roles.read().unwrap().len(), 2);

        *role_repo.reloader_new_data.lock().unwrap() =
            "[{\"roleId\": 60, \"name\":  \"Role60\"}".to_string();

        if let Ok(()) = role_repo.process_source_data_updates() {
            panic!(
                "Unexpected successful process updates result: file={}",
                valid_role_db_pathstr
            );
        }

        assert_eq!(role_repo.roles.read().unwrap().len(), 2);

        *role_repo.reloader_loading.lock().unwrap() = false;
    }

    #[test]
    fn inmemsvcrepo_put() {
        let role_repo = InMemRoleRepo::new();
        let role_key = 60;
        let role = Role {
            role_id: 60,
            name: "Role60".to_string(),
        };

        if let Err(err) = role_repo.put(role.clone()) {
            panic!("Unexpected result: err={:?}", &err)
        }

        let stored_map = role_repo.roles.read().unwrap();
        let stored_entry = stored_map.get(&role_key);

        assert!(stored_entry.is_some());
        assert_eq!(*stored_entry.unwrap(), role);
    }

    #[test]
    fn inmemsvcrepo_get_when_invalid_role() {
        let role_repo = InMemRoleRepo::new();
        let role_key = 60;
        let role = Role {
            role_id: 60,
            name: "Role60".to_string(),
        };

        role_repo.roles.write().unwrap().insert(role_key, role);

        let result = role_repo.get(600);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        assert!(result.unwrap().is_none());
    }

    #[test]
    fn inmemsvcrepo_get_when_valid_role() {
        let role_repo = InMemRoleRepo::new();
        let role_keys = [60, 61, 62];
        let roles = [
            Role {
                role_id: 60,
                name: "Role60".to_string(),
            },
            Role {
                role_id: 61,
                name: "Role61".to_string(),
            },
            Role {
                role_id: 62,
                name: "Role62".to_string(),
            },
        ];

        role_repo
            .roles
            .write()
            .unwrap()
            .insert(role_keys[0], roles[0].clone());
        role_repo
            .roles
            .write()
            .unwrap()
            .insert(role_keys[1], roles[1].clone());
        role_repo
            .roles
            .write()
            .unwrap()
            .insert(role_keys[2], roles[2].clone());

        let result = role_repo.get(61);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let actual_role = result.unwrap();

        assert!(actual_role.is_some());
        assert_eq!(actual_role.unwrap(), roles[1]);
    }

    #[test]
    fn inmemsvcrepo_get_all() {
        let role_repo = InMemRoleRepo::new();
        let role_keys = [60, 61, 62];
        let roles = [
            Role {
                role_id: 60,
                name: "Role60".to_string(),
            },
            Role {
                role_id: 61,
                name: "Role61".to_string(),
            },
            Role {
                role_id: 62,
                name: "Role62".to_string(),
            },
        ];

        role_repo
            .roles
            .write()
            .unwrap()
            .insert(role_keys[0], roles[0].clone());
        role_repo
            .roles
            .write()
            .unwrap()
            .insert(role_keys[1], roles[1].clone());
        role_repo
            .roles
            .write()
            .unwrap()
            .insert(role_keys[2], roles[2].clone());

        let result = role_repo.get_all();

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let actual_roles = result.unwrap();
        assert_eq!(actual_roles.len(), 3);

        let expected_access_db_map: HashMap<u64, Role> = HashMap::from([
            (
                60,
                Role {
                    role_id: 60,
                    name: "Role60".to_string(),
                },
            ),
            (
                61,
                Role {
                    role_id: 61,
                    name: "Role61".to_string(),
                },
            ),
            (
                62,
                Role {
                    role_id: 62,
                    name: "Role62".to_string(),
                },
            ),
        ]);

        assert_eq!(
            actual_roles
                .iter()
                .filter(|entry| !expected_access_db_map.contains_key(&entry.role_id))
                .count(),
            0
        );
    }

    #[test]
    fn inmemsvcrepo_delete_when_invalid_role() {
        let role_repo = InMemRoleRepo::new();
        let role_key = 60;
        let role = Role {
            role_id: 60,
            name: "Role60".to_string(),
        };

        role_repo.roles.write().unwrap().insert(role_key, role);

        let result = role_repo.delete(600);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        assert!(result.unwrap().is_none());
    }

    #[test]
    fn inmemsvcrepo_delete_when_valid_role() {
        let role_repo = InMemRoleRepo::new();
        let role_key = 60;
        let role = Role {
            role_id: 60,
            name: "Role60".to_string(),
        };

        role_repo
            .roles
            .write()
            .unwrap()
            .insert(role_key, role.clone());

        let result = role_repo.delete(60);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let actual_prev_role = result.unwrap();

        assert!(actual_prev_role.is_some());
        assert_eq!(actual_prev_role.unwrap(), role);
    }
}
