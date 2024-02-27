use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::repository::service_repo::ServiceRepository;
use trust0_common::error::AppError;
use trust0_common::file::{ReloadableFile, ReloadableTextFile};
use trust0_common::logging::error;
use trust0_common::model::service::Service;
use trust0_common::target;

pub struct InMemServiceRepo {
    services: RwLock<HashMap<i64, Service>>,
    source_file: Option<String>,
    reloader_loading: Arc<Mutex<bool>>,
    reloader_new_data: Arc<Mutex<String>>,
}

impl InMemServiceRepo {
    /// Creates a new in-memory service store.
    pub fn new() -> InMemServiceRepo {
        let reloader_loading = Arc::new(Mutex::new(false));
        let reloader_new_data = Arc::new(Mutex::new(String::new()));
        InMemServiceRepo {
            services: RwLock::new(HashMap::new()),
            source_file: None,
            reloader_loading,
            reloader_new_data,
        }
    }

    fn access_data_for_write(&self) -> Result<RwLockWriteGuard<HashMap<i64, Service>>, AppError> {
        if let Err(err) = self.process_source_data_updates() {
            error(
                &target!(),
                &format!("Error processing updates: err={:?}", &err),
            );
        }
        self.services.write().map_err(|err| {
            AppError::General(format!("Failed to access write lock to DB: err={}", err))
        })
    }

    fn access_data_for_read(&self) -> Result<RwLockReadGuard<HashMap<i64, Service>>, AppError> {
        if let Err(err) = self.process_source_data_updates() {
            error(
                &target!(),
                &format!("Error processing updates: err={:?}", &err),
            );
        }
        self.services.read().map_err(|err| {
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
        let services: Vec<Service> = serde_json::from_str(
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
        let mut data = self.services.write().map_err(|err| {
            AppError::General(format!(
                "Failed to access write lock to DB: path={}, err={}",
                self.source_file.as_ref().unwrap(),
                err
            ))
        })?;

        data.clear();
        for service in services.iter().as_ref() {
            data.insert(service.service_id, service.clone());
        }

        self.reloader_new_data.lock().unwrap().clear();

        Ok(())
    }
}

impl ServiceRepository for InMemServiceRepo {
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError> {
        // Load DB from JSON file
        self.source_file = Some(connect_spec.to_string());

        let data = fs::read_to_string(connect_spec).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Failed to read file: path={}", connect_spec),
                Box::new(err),
            )
        })?;
        let services: Vec<Service> = serde_json::from_str(&data).map_err(|err| {
            AppError::GenWithMsgAndErr(
                format!("Failed to parse JSON: path={}", connect_spec),
                Box::new(err),
            )
        })?;

        for service in services.iter().as_ref() {
            self.put(service.clone())?;
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

    fn put(&self, service: Service) -> Result<Service, AppError> {
        let mut data = self.access_data_for_write()?;
        let mut service = service.clone();

        if service.service_id == 0 {
            let next_id = data.values().map(|s| s.service_id + 1).max();
            service.service_id = next_id.unwrap_or(1);
        }

        _ = data.insert(service.service_id, service.clone());
        Ok(service)
    }

    fn get(&self, service_id: i64) -> Result<Option<Service>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data.get(&service_id).cloned())
    }

    fn get_all(&self) -> Result<Vec<Service>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data
            .iter()
            .map(|entry| entry.1)
            .cloned()
            .collect::<Vec<Service>>())
    }

    fn delete(&self, service_id: i64) -> Result<Option<Service>, AppError> {
        let mut data = self.access_data_for_write()?;
        Ok(data.remove(&service_id))
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use trust0_common::model::service::Transport;

    const VALID_SERVICE_DB_FILE_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "trust0-db-service.json",
    ];
    const INVALID_SERVICE_DB_FILE_PATHPARTS: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "trust0-db-service-INVALID.json",
    ];

    #[test]
    fn inmemsvcrepo_connect_to_datasource_when_invalid_filepath() {
        let invalid_service_db_path: PathBuf = INVALID_SERVICE_DB_FILE_PATHPARTS.iter().collect();
        let invalid_service_db_pathstr = invalid_service_db_path.to_str().unwrap();

        let mut service_repo = InMemServiceRepo::new();

        if let Ok(()) = service_repo.connect_to_datasource(invalid_service_db_pathstr) {
            panic!("Unexpected result: file={}", invalid_service_db_pathstr);
        }
    }

    #[test]
    fn inmemsvcrepo_connect_to_datasource_when_valid_filepath() {
        let valid_service_db_path: PathBuf = VALID_SERVICE_DB_FILE_PATHPARTS.iter().collect();
        let valid_service_db_pathstr = valid_service_db_path.to_str().unwrap();

        let mut service_repo = InMemServiceRepo::new();

        if let Err(err) = service_repo.connect_to_datasource(valid_service_db_pathstr) {
            panic!(
                "Unexpected result: file={}, err={:?}",
                valid_service_db_pathstr, &err
            );
        }

        let expected_service_db_map: HashMap<i64, Service> = HashMap::from([
            (
                200,
                Service {
                    service_id: 200,
                    name: "Service200".to_string(),
                    transport: Transport::TCP,
                    host: "localhost".to_string(),
                    port: 8200,
                },
            ),
            (
                201,
                Service {
                    service_id: 201,
                    name: "Service201".to_string(),
                    transport: Transport::TCP,
                    host: "localhost".to_string(),
                    port: 8201,
                },
            ),
            (
                202,
                Service {
                    service_id: 202,
                    name: "Service202".to_string(),
                    transport: Transport::TCP,
                    host: "localhost".to_string(),
                    port: 8202,
                },
            ),
            (
                203,
                Service {
                    service_id: 203,
                    name: "chat-tcp".to_string(),
                    transport: Transport::TCP,
                    host: "localhost".to_string(),
                    port: 8500,
                },
            ),
            (
                204,
                Service {
                    service_id: 204,
                    name: "echo-udp".to_string(),
                    transport: Transport::UDP,
                    host: "localhost".to_string(),
                    port: 8600,
                },
            ),
        ]);

        let actual_service_db_map: HashMap<i64, Service> = HashMap::from_iter(
            service_repo
                .services
                .into_inner()
                .unwrap()
                .iter()
                .map(|e| (e.0.clone(), e.1.clone()))
                .collect::<Vec<(i64, Service)>>(),
        );

        assert_eq!(actual_service_db_map.len(), expected_service_db_map.len());
        assert_eq!(
            actual_service_db_map
                .iter()
                .filter(|entry| !expected_service_db_map.contains_key(entry.0))
                .count(),
            0
        );

        *service_repo.reloader_loading.lock().unwrap() = false;
    }

    #[test]
    fn inmemsvcrepo_process_source_data_updates_when_valid_json() {
        let valid_service_db_path: PathBuf = VALID_SERVICE_DB_FILE_PATHPARTS.iter().collect();
        let valid_service_db_pathstr = valid_service_db_path.to_str().unwrap();

        let mut service_repo = InMemServiceRepo::new();

        if let Err(err) = service_repo.connect_to_datasource(valid_service_db_pathstr) {
            panic!(
                "Unexpected result: file={}, err={:?}",
                valid_service_db_pathstr, &err
            );
        }

        assert_eq!(service_repo.services.read().unwrap().len(), 5);

        *service_repo.reloader_new_data.lock().unwrap() = "[{\"serviceId\": 800, \"name\":  \"Service800\", \"transport\": \"TCP\", \"host\": \"localhost\", \"port\":  8800}]".to_string();

        if let Err(err) = service_repo.process_source_data_updates() {
            panic!("Unexpected process updates result: err={:?}", &err);
        }

        let expected_service_db_map: HashMap<i64, Service> = HashMap::from([(
            800,
            Service {
                service_id: 800,
                name: "Service800".to_string(),
                transport: Transport::TCP,
                host: "localhost".to_string(),
                port: 8800,
            },
        )]);

        let actual_service_db_map: HashMap<i64, Service> = HashMap::from_iter(
            service_repo
                .services
                .into_inner()
                .unwrap()
                .iter()
                .map(|e| (e.0.clone(), e.1.clone()))
                .collect::<Vec<(i64, Service)>>(),
        );

        assert_eq!(actual_service_db_map.len(), expected_service_db_map.len());
        assert_eq!(
            actual_service_db_map
                .iter()
                .filter(|entry| !expected_service_db_map.contains_key(entry.0))
                .count(),
            0
        );

        *service_repo.reloader_loading.lock().unwrap() = false;
    }

    #[test]
    fn inmemsvcrepo_process_source_data_updates_when_invalid_json() {
        let valid_service_db_path: PathBuf = VALID_SERVICE_DB_FILE_PATHPARTS.iter().collect();
        let valid_service_db_pathstr = valid_service_db_path.to_str().unwrap();

        let mut service_repo = InMemServiceRepo::new();

        if let Err(err) = service_repo.connect_to_datasource(valid_service_db_pathstr) {
            panic!(
                "Unexpected result: file={}, err={:?}",
                valid_service_db_pathstr, &err
            );
        }

        assert_eq!(service_repo.services.read().unwrap().len(), 5);

        *service_repo.reloader_new_data.lock().unwrap() = "[{\"serviceId\": 800, \"name\":  \"Service800\", \"transport\": \"TCP\", \"host\": \"localhost\", \"port\":  8800}".to_string();

        if let Ok(()) = service_repo.process_source_data_updates() {
            panic!(
                "Unexpected successful process updates result: file={}",
                valid_service_db_pathstr
            );
        }

        assert_eq!(service_repo.services.read().unwrap().len(), 5);

        *service_repo.reloader_loading.lock().unwrap() = false;
    }

    #[test]
    fn inmemsvcrepo_put_when_existing_role() {
        let service_repo = InMemServiceRepo::new();
        let service_key = 1;
        let mut service = Service {
            service_id: 1,
            name: "svc1".to_string(),
            transport: Transport::TCP,
            host: "site1".to_string(),
            port: 100,
        };
        service_repo
            .services
            .write()
            .unwrap()
            .insert(service_key, service.clone());
        service.name = "svc1.1".to_string();

        let result = service_repo.put(service.clone());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let returned_service = result.unwrap();

        let stored_map = service_repo.services.read().unwrap();
        let stored_entry = stored_map.get(&service_key);

        assert!(stored_entry.is_some());
        assert_eq!(*stored_entry.unwrap(), service);
        assert_eq!(returned_service, service);
    }

    #[test]
    fn inmemsvcrepo_put_when_new_role_and_given_id() {
        let service_repo = InMemServiceRepo::new();
        let service_key = 1;
        let service = Service {
            service_id: 1,
            name: "svc1".to_string(),
            transport: Transport::TCP,
            host: "site1".to_string(),
            port: 100,
        };

        let result = service_repo.put(service.clone());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let returned_service = result.unwrap();

        let stored_map = service_repo.services.read().unwrap();
        let stored_entry = stored_map.get(&service_key);

        assert!(stored_entry.is_some());
        assert_eq!(*stored_entry.unwrap(), service);
        assert_eq!(returned_service, service);
    }

    #[test]
    fn inmemsvcrepo_put_when_new_role_and_not_given_id_and_empty_db() {
        let service_repo = InMemServiceRepo::new();
        let mut service = Service {
            service_id: 0,
            name: "svcXX".to_string(),
            transport: Transport::TCP,
            host: "siteXX".to_string(),
            port: 100,
        };

        let result = service_repo.put(service.clone());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let returned_service = result.unwrap();

        let stored_map = service_repo.services.read().unwrap();
        let stored_entry = stored_map.iter().map(|e| e.1).cloned().next();

        service.service_id = 1;

        assert!(stored_entry.is_some());
        assert_eq!(stored_entry.unwrap(), service);
        assert_eq!(returned_service, service);
    }

    #[test]
    fn inmemsvcrepo_put_when_new_role_and_not_given_id_and_non_empty_db() {
        let service_repo = InMemServiceRepo::new();
        let service1 = Service {
            service_id: 1,
            name: "svc1".to_string(),
            transport: Transport::TCP,
            host: "site1".to_string(),
            port: 100,
        };
        let service2 = Service {
            service_id: 2,
            name: "svc2".to_string(),
            transport: Transport::TCP,
            host: "site2".to_string(),
            port: 100,
        };
        service_repo
            .services
            .write()
            .unwrap()
            .insert(1, service1.clone());
        service_repo
            .services
            .write()
            .unwrap()
            .insert(2, service2.clone());

        let mut service = Service {
            service_id: 0,
            name: "svcXX".to_string(),
            transport: Transport::TCP,
            host: "siteXX".to_string(),
            port: 100,
        };

        let result = service_repo.put(service.clone());

        if let Err(err) = result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let returned_service = result.unwrap();

        service.service_id = 3;

        assert_eq!(returned_service, service);
    }

    #[test]
    fn inmemsvcrepo_get_when_invalid_service() {
        let service_repo = InMemServiceRepo::new();
        let service_key = 1;
        let service = Service {
            service_id: 1,
            name: "svc1".to_string(),
            transport: Transport::TCP,
            host: "site1".to_string(),
            port: 100,
        };

        service_repo
            .services
            .write()
            .unwrap()
            .insert(service_key, service);

        let result = service_repo.get(10);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        assert!(result.unwrap().is_none());
    }

    #[test]
    fn inmemsvcrepo_get_when_valid_service() {
        let service_repo = InMemServiceRepo::new();
        let service_keys = [1, 2, 3];
        let services = [
            Service {
                service_id: 1,
                name: "svc1".to_string(),
                transport: Transport::TCP,
                host: "site1".to_string(),
                port: 100,
            },
            Service {
                service_id: 2,
                name: "svc2".to_string(),
                transport: Transport::TCP,
                host: "site2".to_string(),
                port: 200,
            },
            Service {
                service_id: 3,
                name: "svc3".to_string(),
                transport: Transport::UDP,
                host: "site3".to_string(),
                port: 300,
            },
        ];

        service_repo
            .services
            .write()
            .unwrap()
            .insert(service_keys[0], services[0].clone());
        service_repo
            .services
            .write()
            .unwrap()
            .insert(service_keys[1], services[1].clone());
        service_repo
            .services
            .write()
            .unwrap()
            .insert(service_keys[2], services[2].clone());

        let result = service_repo.get(2);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let actual_service = result.unwrap();

        assert!(actual_service.is_some());
        assert_eq!(actual_service.unwrap(), services[1]);
    }

    #[test]
    fn inmemsvcrepo_get_all() {
        let service_repo = InMemServiceRepo::new();
        let service_keys = [1, 2, 3];
        let services = [
            Service {
                service_id: 1,
                name: "svc1".to_string(),
                transport: Transport::TCP,
                host: "site1".to_string(),
                port: 100,
            },
            Service {
                service_id: 2,
                name: "svc2".to_string(),
                transport: Transport::TCP,
                host: "site2".to_string(),
                port: 200,
            },
            Service {
                service_id: 3,
                name: "svc3".to_string(),
                transport: Transport::UDP,
                host: "site3".to_string(),
                port: 300,
            },
        ];

        service_repo
            .services
            .write()
            .unwrap()
            .insert(service_keys[0], services[0].clone());
        service_repo
            .services
            .write()
            .unwrap()
            .insert(service_keys[1], services[1].clone());
        service_repo
            .services
            .write()
            .unwrap()
            .insert(service_keys[2], services[2].clone());

        let result = service_repo.get_all();

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let actual_services = result.unwrap();
        assert_eq!(actual_services.len(), 3);

        let expected_service_db_map: HashMap<i64, Service> = HashMap::from([
            (
                1,
                Service {
                    service_id: 1,
                    name: "svc1".to_string(),
                    transport: Transport::TCP,
                    host: "site1".to_string(),
                    port: 100,
                },
            ),
            (
                2,
                Service {
                    service_id: 2,
                    name: "svc2".to_string(),
                    transport: Transport::TCP,
                    host: "site2".to_string(),
                    port: 200,
                },
            ),
            (
                3,
                Service {
                    service_id: 3,
                    name: "svc3".to_string(),
                    transport: Transport::UDP,
                    host: "site3".to_string(),
                    port: 300,
                },
            ),
        ]);

        assert_eq!(
            actual_services
                .iter()
                .filter(|entry| !expected_service_db_map.contains_key(&entry.service_id))
                .count(),
            0
        );
    }

    #[test]
    fn inmemsvcrepo_delete_when_invalid_service() {
        let service_repo = InMemServiceRepo::new();
        let service_key = 1;
        let service = Service {
            service_id: 1,
            name: "svc1".to_string(),
            transport: Transport::TCP,
            host: "site1".to_string(),
            port: 100,
        };

        service_repo
            .services
            .write()
            .unwrap()
            .insert(service_key, service);

        let result = service_repo.delete(10);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        assert!(result.unwrap().is_none());
    }

    #[test]
    fn inmemsvcrepo_delete_when_valid_service() {
        let service_repo = InMemServiceRepo::new();
        let service_key = 1;
        let service = Service {
            service_id: 1,
            name: "svc1".to_string(),
            transport: Transport::TCP,
            host: "site1".to_string(),
            port: 100,
        };

        service_repo
            .services
            .write()
            .unwrap()
            .insert(service_key, service.clone());

        let result = service_repo.delete(1);

        if let Err(err) = &result {
            panic!("Unexpected result: err={:?}", &err)
        }

        let actual_prev_service = result.unwrap();

        assert!(actual_prev_service.is_some());
        assert_eq!(actual_prev_service.unwrap(), service);
    }
}
