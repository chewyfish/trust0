#[cfg(not(feature = "postgres_db"))]
use chrono::NaiveDateTime;
use diesel::prelude::*;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};
#[cfg(feature = "postgres_db")]
use std::time::SystemTime;

use crate::repository::diesel_orm::db_schema::services::dsl::*;
use crate::repository::service_repo::ServiceRepository;
use trust0_common::error::AppError;
use trust0_common::model;

/// Service ORM model struct
#[derive(Debug, AsChangeset, Identifiable, Insertable, Queryable, Selectable, PartialEq)]
#[diesel(table_name = crate::repository::diesel_orm::db_schema::services)]
pub struct Service {
    /// Service ID (unique across services)
    pub id: i64,
    /// Service key name (unique across services)
    pub name: String,
    /// Service transport type
    pub transport: String,
    /// Service address host (used in gateway proxy connections)
    pub host: String,
    /// Service address port (used in gateway proxy connections)
    pub port: i32,
    /// Datetime record was created
    #[cfg(feature = "postgres_db")]
    pub created_at: Option<SystemTime>,
    #[cfg(not(feature = "postgres_db"))]
    pub created_at: Option<NaiveDateTime>,
    /// Datetime record was last updated
    #[cfg(feature = "postgres_db")]
    pub updated_at: Option<SystemTime>,
    #[cfg(not(feature = "postgres_db"))]
    pub updated_at: Option<NaiveDateTime>,
}

impl From<model::service::Service> for Service {
    fn from(service: model::service::Service) -> Self {
        Self {
            id: service.service_id,
            name: service.name,
            transport: match service.transport {
                model::service::Transport::TCP => "TCP".to_string(),
                model::service::Transport::UDP => "UDP".to_string(),
            },
            host: service.host,
            port: service.port as i32,
            created_at: None,
            updated_at: None,
        }
    }
}

impl From<Service> for model::service::Service {
    fn from(service: Service) -> Self {
        Self::from(&service)
    }
}

impl From<&Service> for model::service::Service {
    fn from(service: &Service) -> Self {
        Self {
            service_id: service.id,
            name: service.name.clone(),
            transport: match service.transport.as_str() {
                "TCP" => model::service::Transport::TCP,
                "UDP" => model::service::Transport::UDP,
                val => panic!("Invalid service transport: val={}", val),
            },
            host: service.host.clone(),
            port: service.port as u16,
        }
    }
}

/// Service Repository
pub struct DieselServiceRepo {
    /// An establish Diesel connection object
    #[cfg(not(feature = "postgres_db"))]
    connection: Arc<Mutex<MysqlConnection>>,
    #[cfg(feature = "postgres_db")]
    connection: Arc<Mutex<PgConnection>>,
}

impl DieselServiceRepo {
    /// Creates a new service repository.
    ///
    /// # Returns
    ///
    /// A newly constructed [`DieselServiceRepo`] object.
    ///
    #[cfg(not(feature = "postgres_db"))]
    pub fn new(db_conn: &Arc<Mutex<MysqlConnection>>) -> DieselServiceRepo {
        DieselServiceRepo {
            connection: db_conn.clone(),
        }
    }
    #[cfg(feature = "postgres_db")]
    pub fn new(db_conn: &Arc<Mutex<PgConnection>>) -> DieselServiceRepo {
        DieselServiceRepo {
            connection: db_conn.clone(),
        }
    }
}

impl ServiceRepository for DieselServiceRepo {
    fn connect_to_datasource(&mut self, _connect_spec: &str) -> Result<(), AppError> {
        Ok(())
    }

    fn put(&self, service: model::service::Service) -> Result<model::service::Service, AppError> {
        let service_entity: Service = service.clone().into();
        if service_entity.id != 0 {
            match diesel::update(services.filter(id.eq(service_entity.id)))
                .set((
                    id.eq(service_entity.id),
                    name.eq(service_entity.name.as_str()),
                    transport.eq(service_entity.transport.as_str()),
                    host.eq(service_entity.host.as_str()),
                    port.eq(service_entity.port),
                ))
                .execute(self.connection.lock().unwrap().deref_mut())
            {
                Ok(rows) if rows > 0 => return Ok(service),
                Ok(_) => {}
                Err(diesel::NotFound) => {}
                Err(err) => {
                    return Err(AppError::General(format!(
                        "Error putting Service: err={:?}",
                        &err
                    )));
                }
            }
        }

        let query_result = match service_entity.id == 0 {
            true => {
                #[cfg(not(feature = "postgres_db"))]
                {
                    diesel::insert_into(services)
                        .values((
                            name.eq(service_entity.name.as_str()),
                            transport.eq(service_entity.transport.as_str()),
                            host.eq(service_entity.host.as_str()),
                            port.eq(service_entity.port),
                        ))
                        .execute(self.connection.lock().unwrap().deref_mut())
                        .map(|_| 100_i64)
                }
                #[cfg(feature = "postgres_db")]
                {
                    diesel::insert_into(services)
                        .values((
                            name.eq(service_entity.name.as_str()),
                            transport.eq(service_entity.transport.as_str()),
                            host.eq(service_entity.host.as_str()),
                            port.eq(service_entity.port),
                        ))
                        .returning(id)
                        .get_result::<i64>(self.connection.lock().unwrap().deref_mut())
                }
            }
            false => diesel::insert_into(services)
                .values((
                    id.eq(service_entity.id),
                    name.eq(service_entity.name.as_str()),
                    transport.eq(service_entity.transport.as_str()),
                    host.eq(service_entity.host.as_str()),
                    port.eq(service_entity.port),
                ))
                .execute(self.connection.lock().unwrap().deref_mut())
                .map(|_| service_entity.id),
        };

        match query_result {
            Ok(service_id) => {
                let mut service = service.clone();
                service.service_id = service_id;
                Ok(service)
            }
            Err(err) => Err(AppError::General(format!(
                "Error putting Service: err={:?}",
                &err
            ))),
        }
    }

    fn get(&self, service_id: i64) -> Result<Option<model::service::Service>, AppError> {
        match services
            .find(service_id)
            .select(Service::as_select())
            .first(self.connection.lock().unwrap().deref_mut())
        {
            Ok(service) => Ok(Some(service.into())),
            Err(diesel::NotFound) => Ok(None),
            Err(err) => Err(AppError::General(format!(
                "Error getting Service: id={}, err={:?}",
                service_id, &err
            ))),
        }
    }

    fn get_all(&self) -> Result<Vec<model::service::Service>, AppError> {
        let services_list: Vec<Service> = services
            .select(Service::as_select())
            .load(self.connection.lock().unwrap().deref_mut())
            .map_err(|err| {
                AppError::General(format!("Error getting all Services: err={:?}", &err))
            })?;

        Ok(services_list
            .iter()
            .map(|service| service.into())
            .collect::<Vec<model::service::Service>>())
    }

    fn delete(&self, service_id: i64) -> Result<Option<model::service::Service>, AppError> {
        let curr_service = self.get(service_id)?;
        if curr_service.is_none() {
            return Ok(None);
        }

        match diesel::delete(services.filter(id.eq(service_id)))
            .execute(self.connection.lock().unwrap().deref_mut())
        {
            Ok(_) => Ok(Some(curr_service.unwrap())),
            Err(diesel::NotFound) => Ok(None),
            Err(err) => Err(AppError::General(format!(
                "Error deleting Service: id={}, err={:?}",
                service_id, &err
            ))),
        }
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::diesel_orm::db_conn;
    use crate::repository::postgres_db;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::path::PathBuf;

    pub const POSTGRES_DATABASE_DIR_PATHPARTS: [&str; 8] = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "target",
        "test-gateway",
        "postgres",
        "data",
        "service",
    ];

    // utils
    // =====

    fn create_service_repository(connect_spec: &str) -> DieselServiceRepo {
        DieselServiceRepo::new(
            &postgres_db::db_conn::INSTANCE
                .lock()
                .unwrap()
                .establish_connection(connect_spec)
                .unwrap(),
        )
    }

    // tests
    // =====

    #[test]
    fn diselsvcrepo_service_from_model() {
        let model_tcp_service = model::service::Service {
            service_id: 200,
            name: "Service200".to_string(),
            transport: model::service::Transport::TCP,
            host: "host200.com".to_string(),
            port: 8200,
        };
        let model_udp_service = model::service::Service {
            service_id: 201,
            name: "Service201".to_string(),
            transport: model::service::Transport::UDP,
            host: "host201.com".to_string(),
            port: 8201,
        };
        let expected_tcp_service = Service {
            id: 200,
            name: "Service200".to_string(),
            transport: "TCP".to_string(),
            host: "host200.com".to_string(),
            port: 8200,
            created_at: None,
            updated_at: None,
        };
        let expected_udp_service = Service {
            id: 201,
            name: "Service201".to_string(),
            transport: "UDP".to_string(),
            host: "host201.com".to_string(),
            port: 8201,
            created_at: None,
            updated_at: None,
        };
        assert_eq!(Service::from(model_tcp_service), expected_tcp_service);
        assert_eq!(Service::from(model_udp_service), expected_udp_service);
    }

    #[test]
    fn diselsvcrepo_service_to_model() {
        let tcp_service = Service {
            id: 200,
            name: "Service200".to_string(),
            transport: "TCP".to_string(),
            host: "host200.com".to_string(),
            port: 8200,
            created_at: None,
            updated_at: None,
        };
        let udp_service = Service {
            id: 201,
            name: "Service201".to_string(),
            transport: "UDP".to_string(),
            host: "host201.com".to_string(),
            port: 8201,
            created_at: None,
            updated_at: None,
        };
        let expected_model_tcp_service = model::service::Service {
            service_id: 200,
            name: "Service200".to_string(),
            transport: model::service::Transport::TCP,
            host: "host200.com".to_string(),
            port: 8200,
        };
        let expected_model_udp_service = model::service::Service {
            service_id: 201,
            name: "Service201".to_string(),
            transport: model::service::Transport::UDP,
            host: "host201.com".to_string(),
            port: 8201,
        };
        assert_eq!(
            model::service::Service::from(tcp_service),
            expected_model_tcp_service
        );
        assert_eq!(
            model::service::Service::from(udp_service),
            expected_model_udp_service
        );
    }

    #[test]
    #[serial(disel_service)]
    fn diselservicerepo_put_when_existing_service() {
        let expected_service = model::service::Service {
            service_id: 200,
            name: "Service200.1".to_string(),
            transport: model::service::Transport::TCP,
            host: "host200.com".to_string(),
            port: 8200,
        };

        let database_dir: PathBuf = POSTGRES_DATABASE_DIR_PATHPARTS.iter().collect();
        let (pg_embed, mut db_conn) = db_conn::tests::DB
            .lock()
            .unwrap()
            .setup_db(database_dir.clone())
            .unwrap();

        {
            let _transaction = db_conn::tests::EmbeddedDbTransaction {
                database_dir,
                pg_embed: pg_embed.clone(),
            };

            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_SERVICE_RECORDS)
                .unwrap();

            let service_repo = create_service_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = service_repo.put(expected_service.clone());

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let service = result.unwrap();

            assert_eq!(service, expected_service);
        }
    }

    #[test]
    #[serial(disel_service)]
    fn diselservicerepo_put_when_new_service_and_given_id() {
        let expected_service = model::service::Service {
            service_id: 301,
            name: "Service301".to_string(),
            transport: model::service::Transport::TCP,
            host: "host301.com".to_string(),
            port: 8301,
        };

        let database_dir: PathBuf = POSTGRES_DATABASE_DIR_PATHPARTS.iter().collect();
        let (pg_embed, mut db_conn) = db_conn::tests::DB
            .lock()
            .unwrap()
            .setup_db(database_dir.clone())
            .unwrap();

        {
            let _transaction = db_conn::tests::EmbeddedDbTransaction {
                database_dir,
                pg_embed: pg_embed.clone(),
            };

            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_SERVICE_RECORDS)
                .unwrap();

            let service_repo = create_service_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = service_repo.put(expected_service.clone());

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let service = result.unwrap();
            assert_eq!(service, expected_service);
        }
    }

    #[test]
    #[serial(disel_service)]
    fn diselservicerepo_put_when_new_service_and_not_given_id() {
        let expected_service = model::service::Service {
            service_id: 0,
            name: "ServiceXX".to_string(),
            transport: model::service::Transport::TCP,
            host: "hostXX.com".to_string(),
            port: 7200,
        };

        let database_dir: PathBuf = POSTGRES_DATABASE_DIR_PATHPARTS.iter().collect();
        let (pg_embed, _) = db_conn::tests::DB
            .lock()
            .unwrap()
            .setup_db(database_dir.clone())
            .unwrap();

        {
            let _transaction = db_conn::tests::EmbeddedDbTransaction {
                database_dir,
                pg_embed: pg_embed.clone(),
            };

            let service_repo = create_service_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = service_repo.put(expected_service.clone());

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let service = result.unwrap();
            assert!(service.service_id > 0);
            assert_eq!(service.name, expected_service.name);
        }
    }

    #[test]
    #[serial(disel_service)]
    fn diselservicerepo_get_when_invalid_service() {
        let database_dir: PathBuf = POSTGRES_DATABASE_DIR_PATHPARTS.iter().collect();
        let (pg_embed, mut db_conn) = db_conn::tests::DB
            .lock()
            .unwrap()
            .setup_db(database_dir.clone())
            .unwrap();

        {
            let _transaction = db_conn::tests::EmbeddedDbTransaction {
                database_dir,
                pg_embed: pg_embed.clone(),
            };

            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_SERVICE_RECORDS)
                .unwrap();

            let service_repo = create_service_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = service_repo.get(500);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_service = result.unwrap();

            assert!(actual_service.is_none());
        }
    }

    #[test]
    #[serial(disel_service)]
    fn diselservicerepo_get_when_valid_service() {
        let expected_service = model::service::Service {
            service_id: 200,
            name: "Service200".to_string(),
            transport: model::service::Transport::TCP,
            host: "host200.com".to_string(),
            port: 8200,
        };

        let database_dir: PathBuf = POSTGRES_DATABASE_DIR_PATHPARTS.iter().collect();
        let (pg_embed, mut db_conn) = db_conn::tests::DB
            .lock()
            .unwrap()
            .setup_db(database_dir.clone())
            .unwrap();

        {
            let _transaction = db_conn::tests::EmbeddedDbTransaction {
                database_dir,
                pg_embed: pg_embed.clone(),
            };

            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_SERVICE_RECORDS)
                .unwrap();

            let service_repo = create_service_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = service_repo.get(expected_service.service_id);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_service = result.unwrap();

            assert!(actual_service.is_some());
            assert_eq!(actual_service.unwrap(), expected_service);
        }
    }

    #[test]
    #[serial(disel_service)]
    fn diselservicerepo_get_all() {
        let database_dir: PathBuf = POSTGRES_DATABASE_DIR_PATHPARTS.iter().collect();
        let (pg_embed, mut db_conn) = db_conn::tests::DB
            .lock()
            .unwrap()
            .setup_db(database_dir.clone())
            .unwrap();

        {
            let _transaction = db_conn::tests::EmbeddedDbTransaction {
                database_dir,
                pg_embed: pg_embed.clone(),
            };

            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_SERVICE_RECORDS)
                .unwrap();

            let service_repo = create_service_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = service_repo.get_all();

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_services = result.unwrap();

            assert_eq!(actual_services.len(), 2);

            let expected_service_db_map: HashMap<i64, model::service::Service> = HashMap::from([
                (
                    200,
                    model::service::Service {
                        service_id: 200,
                        name: "Service200".to_string(),
                        transport: model::service::Transport::TCP,
                        host: "host200.com".to_string(),
                        port: 8200,
                    },
                ),
                (
                    201,
                    model::service::Service {
                        service_id: 201,
                        name: "Service201".to_string(),
                        transport: model::service::Transport::UDP,
                        host: "host201.com".to_string(),
                        port: 8201,
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
    }

    #[test]
    #[serial(disel_service)]
    fn diselservicerepo_delete_when_invalid_service() {
        let database_dir: PathBuf = POSTGRES_DATABASE_DIR_PATHPARTS.iter().collect();
        let (pg_embed, mut db_conn) = db_conn::tests::DB
            .lock()
            .unwrap()
            .setup_db(database_dir.clone())
            .unwrap();

        {
            let _transaction = db_conn::tests::EmbeddedDbTransaction {
                database_dir,
                pg_embed: pg_embed.clone(),
            };

            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_SERVICE_RECORDS)
                .unwrap();

            let service_repo = create_service_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = service_repo.delete(500);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_service = result.unwrap();

            assert!(actual_service.is_none());
        }
    }

    #[test]
    #[serial(disel_service)]
    fn diselservicerepo_delete_when_valid_service() {
        let expected_service = model::service::Service {
            service_id: 200,
            name: "Service200".to_string(),
            transport: model::service::Transport::TCP,
            host: "host200.com".to_string(),
            port: 8200,
        };

        let database_dir: PathBuf = POSTGRES_DATABASE_DIR_PATHPARTS.iter().collect();
        let (pg_embed, mut db_conn) = db_conn::tests::DB
            .lock()
            .unwrap()
            .setup_db(database_dir.clone())
            .unwrap();

        {
            let _transaction = db_conn::tests::EmbeddedDbTransaction {
                database_dir,
                pg_embed: pg_embed.clone(),
            };

            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_SERVICE_RECORDS)
                .unwrap();

            let service_repo = create_service_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = service_repo.delete(expected_service.service_id);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_service = result.unwrap();

            assert!(actual_service.is_some());
            assert_eq!(actual_service.unwrap(), expected_service);
        }
    }
}
