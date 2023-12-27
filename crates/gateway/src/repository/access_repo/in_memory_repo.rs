use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::repository::access_repo::AccessRepository;
use trust0_common::error::AppError;
use trust0_common::file::{ReloadableFile, ReloadableTextFile};
use trust0_common::logging::error;
use trust0_common::model::access::ServiceAccess;
use trust0_common::target;

pub struct InMemAccessRepo {
    accesses: RwLock<HashMap<(u64, u64), ServiceAccess>>,
    source_file: Option<String>,
    reloader_loading: Arc<Mutex<bool>>,
    reloader_new_data: Arc<Mutex<String>>,
}

impl InMemAccessRepo {
    /// Creates a new in-memory service access store.
    pub fn new() -> InMemAccessRepo {
        let reloader_loading = Arc::new(Mutex::new(false));
        let reloader_new_data = Arc::new(Mutex::new(String::new()));
        InMemAccessRepo {
            accesses: RwLock::new(HashMap::new()),
            source_file: None,
            reloader_loading,
            reloader_new_data,
        }
    }

    #[allow(clippy::type_complexity)]
    fn access_data_for_write(
        &self,
    ) -> Result<RwLockWriteGuard<HashMap<(u64, u64), ServiceAccess>>, AppError> {
        if let Err(err) = self.process_source_data_updates() {
            error(
                &target!(),
                &format!("Error processing updates: err={:?}", &err),
            );
        }
        self.accesses.write().map_err(|err| {
            AppError::General(format!("Failed to access write lock to DB: err={}", err))
        })
    }

    #[allow(clippy::type_complexity)]
    fn access_data_for_read(
        &self,
    ) -> Result<RwLockReadGuard<HashMap<(u64, u64), ServiceAccess>>, AppError> {
        if let Err(err) = self.process_source_data_updates() {
            error(
                &target!(),
                &format!("Error processing updates: err={:?}", &err),
            );
        }
        self.accesses.read().map_err(|err| {
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
        let accesses: Vec<ServiceAccess> = serde_json::from_str(
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
        let mut data = self.accesses.write().map_err(|err| {
            AppError::General(format!(
                "Failed to access write lock to DB: path={}, err={}",
                self.source_file.as_ref().unwrap(),
                err
            ))
        })?;

        data.clear();
        for access in accesses.iter().as_ref() {
            data.insert((access.user_id, access.service_id), access.clone());
        }

        self.reloader_new_data.lock().unwrap().clear();

        Ok(())
    }
}

impl AccessRepository for InMemAccessRepo {
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError> {
        // Load DB from JSON file
        self.source_file = Some(connect_spec.to_string());

        let data = fs::read_to_string(connect_spec).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Failed to read file: path={}", connect_spec),
                Box::new(err),
            )
        })?;
        let accesses: Vec<ServiceAccess> = serde_json::from_str(&data).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Failed to parse JSON: path={}", connect_spec),
                Box::new(err),
            )
        })?;

        for access in accesses.iter().as_ref() {
            self.put(access.clone())?;
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

    fn put(&self, access: ServiceAccess) -> Result<Option<ServiceAccess>, AppError> {
        let mut data = self.access_data_for_write()?;
        Ok(data.insert((access.user_id, access.service_id), access.clone()))
    }

    fn get(&self, user_id: u64, service_id: u64) -> Result<Option<ServiceAccess>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data.get(&(user_id, service_id)).cloned())
    }

    fn get_all_for_user(&self, user_id: u64) -> Result<Vec<ServiceAccess>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data
            .iter()
            .filter(|entry| entry.0 .0 == user_id)
            .map(|entry| entry.1)
            .cloned()
            .collect::<Vec<ServiceAccess>>())
    }

    fn delete(&self, user_id: u64, service_id: u64) -> Result<Option<ServiceAccess>, AppError> {
        let mut data = self.access_data_for_write()?;
        Ok(data.remove(&(user_id, service_id)))
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const VALID_ACCESS_DB_FILE_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "testdata", "db-access.json"];
    const INVALID_ACCESS_DB_FILE_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "db-access-INVALID.json",
    ];

    #[test]
    fn inmemaccessrepo_connect_to_datasource_when_invalid_filepath() {
        let invalid_access_db_path: PathBuf = INVALID_ACCESS_DB_FILE_PATHPARTS.iter().collect();
        let invalid_access_db_pathstr = invalid_access_db_path.to_str().unwrap();

        let mut access_repo = InMemAccessRepo::new();

        if let Ok(()) = access_repo.connect_to_datasource(invalid_access_db_pathstr) {
            panic!("Unexpected result: file={}", invalid_access_db_pathstr);
        }
    }

    #[test]
    fn inmemaccessrepo_connect_to_datasource_when_valid_filepath() {
        let valid_access_db_path: PathBuf = VALID_ACCESS_DB_FILE_PATHPARTS.iter().collect();
        let valid_access_db_pathstr = valid_access_db_path.to_str().unwrap();

        let mut access_repo = InMemAccessRepo::new();

        if let Err(err) = access_repo.connect_to_datasource(valid_access_db_pathstr) {
            panic!(
                "Unexpected result: file={}, err={:?}",
                valid_access_db_pathstr, &err
            );
        }

        let expected_access_db_map: HashMap<(u64, u64), ServiceAccess> = HashMap::from([
            (
                (100, 200),
                ServiceAccess {
                    user_id: 100,
                    service_id: 200,
                },
            ),
            (
                (100, 203),
                ServiceAccess {
                    user_id: 100,
                    service_id: 203,
                },
            ),
            (
                (100, 204),
                ServiceAccess {
                    user_id: 100,
                    service_id: 204,
                },
            ),
            (
                (101, 202),
                ServiceAccess {
                    user_id: 101,
                    service_id: 202,
                },
            ),
            (
                (101, 203),
                ServiceAccess {
                    user_id: 101,
                    service_id: 203,
                },
            ),
        ]);

        let actual_access_db_map: HashMap<(u64, u64), ServiceAccess> = HashMap::from_iter(
            access_repo
                .accesses
                .into_inner()
                .unwrap()
                .iter()
                .map(|e| (e.0.clone(), e.1.clone()))
                .collect::<Vec<((u64, u64), ServiceAccess)>>(),
        );

        assert_eq!(actual_access_db_map.len(), expected_access_db_map.len());
        assert_eq!(
            actual_access_db_map
                .iter()
                .filter(|entry| !expected_access_db_map.contains_key(entry.0))
                .count(),
            0
        );

        *access_repo.reloader_loading.lock().unwrap() = false;
    }

    #[test]
    fn inmemaccessrepo_process_source_data_updates_when_valid_json() {
        let valid_access_db_path: PathBuf = VALID_ACCESS_DB_FILE_PATHPARTS.iter().collect();
        let valid_access_db_pathstr = valid_access_db_path.to_str().unwrap();

        let mut access_repo = InMemAccessRepo::new();

        if let Err(err) = access_repo.connect_to_datasource(valid_access_db_pathstr) {
            panic!(
                "Unexpected result: file={}, err={:?}",
                valid_access_db_pathstr, &err
            );
        }

        assert_eq!(access_repo.accesses.read().unwrap().len(), 5);

        *access_repo.reloader_new_data.lock().unwrap() =
            "[{\"userId\": 800, \"serviceId\": 900}]".to_string();

        if let Err(err) = access_repo.process_source_data_updates() {
            panic!("Unexpected process updates result: err={:?}", &err);
        }

        let expected_access_db_map: HashMap<(u64, u64), ServiceAccess> = HashMap::from([(
            (800, 900),
            ServiceAccess {
                user_id: 100,
                service_id: 200,
            },
        )]);

        let actual_access_db_map: HashMap<(u64, u64), ServiceAccess> = HashMap::from_iter(
            access_repo
                .accesses
                .into_inner()
                .unwrap()
                .iter()
                .map(|e| (e.0.clone(), e.1.clone()))
                .collect::<Vec<((u64, u64), ServiceAccess)>>(),
        );

        assert_eq!(actual_access_db_map.len(), expected_access_db_map.len());
        assert_eq!(
            actual_access_db_map
                .iter()
                .filter(|entry| !expected_access_db_map.contains_key(entry.0))
                .count(),
            0
        );

        *access_repo.reloader_loading.lock().unwrap() = false;
    }

    #[test]
    fn inmemaccessrepo_process_source_data_updates_when_invalid_json() {
        let valid_access_db_path: PathBuf = VALID_ACCESS_DB_FILE_PATHPARTS.iter().collect();
        let valid_access_db_pathstr = valid_access_db_path.to_str().unwrap();

        let mut access_repo = InMemAccessRepo::new();

        if let Err(err) = access_repo.connect_to_datasource(valid_access_db_pathstr) {
            panic!(
                "Unexpected result: file={}, err={:?}",
                valid_access_db_pathstr, &err
            );
        }

        assert_eq!(access_repo.accesses.read().unwrap().len(), 5);

        *access_repo.reloader_new_data.lock().unwrap() =
            "[{\"userId\": 800, \"serviceId\": 900}".to_string();

        if let Ok(()) = access_repo.process_source_data_updates() {
            panic!(
                "Unexpected successfule process updates result: file={}",
                valid_access_db_pathstr
            );
        }

        assert_eq!(access_repo.accesses.read().unwrap().len(), 5);

        *access_repo.reloader_loading.lock().unwrap() = false;
    }

    #[test]
    fn inmemaccessrepo_put() {
        let access_repo = InMemAccessRepo::new();
        let access_key = (1, 2);
        let access = ServiceAccess {
            user_id: 1,
            service_id: 2,
        };

        if let Err(err) = access_repo.put(access.clone()) {
            panic!("Unexpected result: err={:?}", &err)
        }

        let stored_map = access_repo.accesses.read().unwrap();
        let stored_entry = stored_map.get(&access_key);

        assert!(stored_entry.is_some());
        assert_eq!(*stored_entry.unwrap(), access);
    }

    #[test]
    fn inmemaccessrepo_get_when_invalid_user() {
        let access_repo = InMemAccessRepo::new();
        let access_key = (1, 2);
        let access = ServiceAccess {
            user_id: 1,
            service_id: 2,
        };

        access_repo
            .accesses
            .write()
            .unwrap()
            .insert(access_key, access);

        let result = access_repo.get(10, 2);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        assert!(result.unwrap().is_none());
    }

    #[test]
    fn inmemaccessrepo_get_when_invalid_service() {
        let access_repo = InMemAccessRepo::new();
        let access_key = (1, 2);
        let access = ServiceAccess {
            user_id: 1,
            service_id: 2,
        };

        access_repo
            .accesses
            .write()
            .unwrap()
            .insert(access_key, access);

        let result = access_repo.get(1, 20);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        assert!(result.unwrap().is_none());
    }

    #[test]
    fn inmemaccessrepo_get_when_valid_user_and_service() {
        let access_repo = InMemAccessRepo::new();
        let access_keys = [(1, 2), (3, 4)];
        let accesses = [
            ServiceAccess {
                user_id: 1,
                service_id: 2,
            },
            ServiceAccess {
                user_id: 3,
                service_id: 4,
            },
        ];

        access_repo
            .accesses
            .write()
            .unwrap()
            .insert(access_keys[0], accesses[0].clone());
        access_repo
            .accesses
            .write()
            .unwrap()
            .insert(access_keys[1], accesses[1].clone());

        let result = access_repo.get(1, 2);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let actual_access = result.unwrap();

        assert!(actual_access.is_some());
        assert_eq!(actual_access.unwrap(), accesses[0]);
    }

    #[test]
    fn inmemaccessrepo_get_all_for_user_when_invalid_user() {
        let access_repo = InMemAccessRepo::new();
        let access_keys = [(1, 2), (3, 4), (1, 5)];
        let accesses = [
            ServiceAccess {
                user_id: 1,
                service_id: 2,
            },
            ServiceAccess {
                user_id: 3,
                service_id: 4,
            },
            ServiceAccess {
                user_id: 1,
                service_id: 5,
            },
        ];

        access_repo
            .accesses
            .write()
            .unwrap()
            .insert(access_keys[0], accesses[0].clone());
        access_repo
            .accesses
            .write()
            .unwrap()
            .insert(access_keys[1], accesses[1].clone());
        access_repo
            .accesses
            .write()
            .unwrap()
            .insert(access_keys[2], accesses[2].clone());

        let result = access_repo.get_all_for_user(10);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn inmemaccessrepo_get_all_for_user_when_valid_user() {
        let access_repo = InMemAccessRepo::new();
        let access_keys = [(1, 2), (3, 4), (1, 5)];
        let accesses = [
            ServiceAccess {
                user_id: 1,
                service_id: 2,
            },
            ServiceAccess {
                user_id: 3,
                service_id: 4,
            },
            ServiceAccess {
                user_id: 1,
                service_id: 5,
            },
        ];

        access_repo
            .accesses
            .write()
            .unwrap()
            .insert(access_keys[0], accesses[0].clone());
        access_repo
            .accesses
            .write()
            .unwrap()
            .insert(access_keys[1], accesses[1].clone());
        access_repo
            .accesses
            .write()
            .unwrap()
            .insert(access_keys[2], accesses[2].clone());

        let result = access_repo.get_all_for_user(1);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let actual_accesses = result.unwrap();
        assert_eq!(actual_accesses.len(), 2);

        let expected_access_db_map: HashMap<(u64, u64), ServiceAccess> = HashMap::from([
            (
                (1, 2),
                ServiceAccess {
                    user_id: 1,
                    service_id: 2,
                },
            ),
            (
                (1, 5),
                ServiceAccess {
                    user_id: 1,
                    service_id: 5,
                },
            ),
        ]);

        assert_eq!(
            actual_accesses
                .iter()
                .filter(|entry| !expected_access_db_map
                    .contains_key(&(entry.user_id, entry.service_id)))
                .count(),
            0
        );
    }

    #[test]
    fn inmemaccessrepo_delete_when_invalid_user() {
        let access_repo = InMemAccessRepo::new();
        let access_key = (1, 2);
        let access = ServiceAccess {
            user_id: 1,
            service_id: 2,
        };

        access_repo
            .accesses
            .write()
            .unwrap()
            .insert(access_key, access);

        let result = access_repo.delete(10, 2);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        assert!(result.unwrap().is_none());
    }

    #[test]
    fn inmemaccessrepo_delete_when_invalid_service() {
        let access_repo = InMemAccessRepo::new();
        let access_key = (1, 2);
        let access = ServiceAccess {
            user_id: 1,
            service_id: 2,
        };

        access_repo
            .accesses
            .write()
            .unwrap()
            .insert(access_key, access);

        let result = access_repo.delete(1, 20);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        assert!(result.unwrap().is_none());
    }

    #[test]
    fn inmemaccessrepo_delete_when_valid_user_and_service() {
        let access_repo = InMemAccessRepo::new();
        let access_key = (1, 2);
        let access = ServiceAccess {
            user_id: 1,
            service_id: 2,
        };

        access_repo
            .accesses
            .write()
            .unwrap()
            .insert(access_key, access.clone());

        let result = access_repo.delete(1, 2);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let actual_prev_access = result.unwrap();

        assert!(actual_prev_access.is_some());
        assert_eq!(actual_prev_access.unwrap(), access);
    }
}
