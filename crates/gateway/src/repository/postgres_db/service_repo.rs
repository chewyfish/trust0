use diesel::prelude::*;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};

use crate::repository::postgres_db::db_conn;
use crate::repository::postgres_db::db_schema::services::dsl::*;
use crate::repository::service_repo::ServiceRepository;
use trust0_common::error::AppError;
use trust0_common::model;

/// Service ORM model struct
#[derive(Debug, AsChangeset, Identifiable, Insertable, Queryable, Selectable, PartialEq)]
#[diesel(table_name = crate::repository::postgres_db::db_schema::services)]
#[diesel(check_for_backend(diesel::pg::Pg))]
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
pub struct PostgresServiceRepo {
    /// If connected, an establish Postgres connection object
    connection: Option<Arc<Mutex<PgConnection>>>,
}

impl PostgresServiceRepo {
    /// Creates a new service repository.
    ///
    /// # Returns
    ///
    /// A newly constructed [`PostgresServiceRepo`] object.
    ///
    pub fn new() -> PostgresServiceRepo {
        PostgresServiceRepo { connection: None }
    }
}

impl ServiceRepository for PostgresServiceRepo {
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError> {
        self.connection = Some(
            db_conn::INSTANCE
                .lock()
                .unwrap()
                .establish_connection(connect_spec)?,
        );
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
                .returning(id)
                .get_result::<i64>(
                    self.connection
                        .as_ref()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .deref_mut(),
                ) {
                Ok(_) => return Ok(service),
                Err(diesel::NotFound) => {}
                Err(err) => {
                    return Err(AppError::GenWithMsgAndErr(
                        "Error putting Service".to_string(),
                        Box::new(err),
                    ))
                }
            }
        }

        let query_result = match service_entity.id == 0 {
            true => diesel::insert_into(services)
                .values((
                    name.eq(service_entity.name.as_str()),
                    transport.eq(service_entity.transport.as_str()),
                    host.eq(service_entity.host.as_str()),
                    port.eq(service_entity.port),
                ))
                .returning(id)
                .get_result::<i64>(
                    self.connection
                        .as_ref()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .deref_mut(),
                ),
            false => diesel::insert_into(services)
                .values((
                    id.eq(service_entity.id),
                    name.eq(service_entity.name.as_str()),
                    transport.eq(service_entity.transport.as_str()),
                    host.eq(service_entity.host.as_str()),
                    port.eq(service_entity.port),
                ))
                .returning(id)
                .get_result::<i64>(
                    self.connection
                        .as_ref()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .deref_mut(),
                ),
        };

        match query_result {
            Ok(service_id) => {
                let mut service = service.clone();
                service.service_id = service_id;
                Ok(service)
            }
            Err(err) => Err(AppError::GenWithMsgAndErr(
                "Error putting Service".to_string(),
                Box::new(err),
            )),
        }
    }

    fn get(&self, service_id: i64) -> Result<Option<model::service::Service>, AppError> {
        match services
            .find(service_id)
            .select(Service::as_select())
            .first(
                self.connection
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .deref_mut(),
            ) {
            Ok(service) => Ok(Some(service.into())),
            Err(diesel::NotFound) => Ok(None),
            Err(err) => Err(AppError::GenWithMsgAndErr(
                format!("Error getting Service: id={}", service_id),
                Box::new(err),
            )),
        }
    }

    fn get_all(&self) -> Result<Vec<model::service::Service>, AppError> {
        let services_list: Vec<Service> = services
            .select(Service::as_select())
            .load(
                self.connection
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .deref_mut(),
            )
            .map_err(|err| {
                AppError::GenWithMsgAndErr("Error getting all Services".to_string(), Box::new(err))
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

        match diesel::delete(services.filter(id.eq(service_id))).execute(
            self.connection
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .deref_mut(),
        ) {
            Ok(_) => Ok(Some(curr_service.unwrap())),
            Err(diesel::NotFound) => Ok(None),
            Err(err) => Err(AppError::GenWithMsgAndErr(
                format!("Error deleting Service: id={}", service_id),
                Box::new(err),
            )),
        }
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn pgdbsvcrepo_service_from_model() {
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
        };
        let expected_udp_service = Service {
            id: 201,
            name: "Service201".to_string(),
            transport: "UDP".to_string(),
            host: "host201.com".to_string(),
            port: 8201,
        };
        assert_eq!(Service::from(model_tcp_service), expected_tcp_service);
        assert_eq!(Service::from(model_udp_service), expected_udp_service);
    }

    #[test]
    fn pgdbsvcrepo_service_to_model() {
        let tcp_service = Service {
            id: 200,
            name: "Service200".to_string(),
            transport: "TCP".to_string(),
            host: "host200.com".to_string(),
            port: 8200,
        };
        let udp_service = Service {
            id: 201,
            name: "Service201".to_string(),
            transport: "UDP".to_string(),
            host: "host201.com".to_string(),
            port: 8201,
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
    #[serial(pgdb_service)]
    fn pgdbservicerepo_put_when_existing_service() {
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

            let mut service_repo = PostgresServiceRepo::new();
            service_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = service_repo.put(expected_service.clone());

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let service = result.unwrap();

            assert_eq!(service, expected_service);
        }
    }

    #[test]
    #[serial(pgdb_service)]
    fn pgdbservicerepo_put_when_new_service_and_given_id() {
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

            let mut service_repo = PostgresServiceRepo::new();
            service_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = service_repo.put(expected_service.clone());

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let service = result.unwrap();
            assert_eq!(service, expected_service);
        }
    }

    #[test]
    #[serial(pgdb_service)]
    fn pgdbservicerepo_put_when_new_service_and_not_given_id() {
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

            let mut service_repo = PostgresServiceRepo::new();
            service_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

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
    #[serial(pgdb_service)]
    fn pgdbservicerepo_get_when_invalid_service() {
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

            let mut service_repo = PostgresServiceRepo::new();
            service_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = service_repo.get(500);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_service = result.unwrap();

            assert!(actual_service.is_none());
        }
    }

    #[test]
    #[serial(pgdb_service)]
    fn pgdbservicerepo_get_when_valid_service() {
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

            let mut service_repo = PostgresServiceRepo::new();
            service_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

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
    #[serial(pgdb_service)]
    fn pgdbservicerepo_get_all() {
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

            let mut service_repo = PostgresServiceRepo::new();
            service_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

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
    #[serial(pgdb_service)]
    fn pgdbservicerepo_delete_when_invalid_service() {
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

            let mut service_repo = PostgresServiceRepo::new();
            service_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = service_repo.delete(500);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_service = result.unwrap();

            assert!(actual_service.is_none());
        }
    }

    #[test]
    #[serial(pgdb_service)]
    fn pgdbservicerepo_delete_when_valid_service() {
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

            let mut service_repo = PostgresServiceRepo::new();
            service_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

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
