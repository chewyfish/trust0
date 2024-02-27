use diesel::prelude::*;
use diesel::sql_types;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};

use crate::repository::access_repo::AccessRepository;
use crate::repository::postgres_db::db_conn;
use crate::repository::postgres_db::db_schema::service_accesses::dsl;
use trust0_common::error::AppError;
use trust0_common::model;

/// Service access ORM model struct
#[derive(Clone, Debug, AsChangeset, Insertable, Queryable, Selectable, PartialEq)]
#[diesel(table_name = crate::repository::postgres_db::db_schema::service_accesses)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ServiceAccess {
    /// Service ID (unique across services)
    pub service_id: i64,
    /// RBAC entity type
    pub entity_type: String,
    /// Entity ID (either role ID or user ID)
    pub entity_id: i64,
}

fn entity_type_to_string(model_entity_type: &model::access::EntityType) -> String {
    match model_entity_type {
        model::access::EntityType::Role => "Role".to_string(),
        model::access::EntityType::User => "User".to_string(),
        _ => panic!("Invalid entity type: val={:?}", model_entity_type),
    }
}

impl From<model::access::ServiceAccess> for ServiceAccess {
    fn from(access: model::access::ServiceAccess) -> Self {
        Self {
            service_id: access.service_id,
            entity_type: entity_type_to_string(&access.entity_type),
            entity_id: access.entity_id,
        }
    }
}

impl From<ServiceAccess> for model::access::ServiceAccess {
    fn from(access: ServiceAccess) -> Self {
        Self::from(&access)
    }
}

impl From<&ServiceAccess> for model::access::ServiceAccess {
    fn from(access: &ServiceAccess) -> Self {
        Self {
            service_id: access.service_id,
            entity_type: match access.entity_type.as_str() {
                "Role" => model::access::EntityType::Role,
                "User" => model::access::EntityType::User,
                val => panic!("Invalid ServiceAccess entity type: val={}", val),
            },
            entity_id: access.entity_id,
        }
    }
}

/// ServiceAccess Repository
pub struct PostgresServiceAccessRepo {
    /// If connected, an establish Postgres connection object
    connection: Option<Arc<Mutex<PgConnection>>>,
}

impl PostgresServiceAccessRepo {
    /// Creates a new access repository.
    ///
    /// # Returns
    ///
    /// A newly constructed [`PostgresServiceAccessRepo`] object.
    ///
    pub fn new() -> PostgresServiceAccessRepo {
        PostgresServiceAccessRepo { connection: None }
    }
}

impl AccessRepository for PostgresServiceAccessRepo {
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError> {
        self.connection = Some(
            db_conn::INSTANCE
                .lock()
                .unwrap()
                .establish_connection(connect_spec)?,
        );
        Ok(())
    }

    fn put(
        &self,
        access: model::access::ServiceAccess,
    ) -> Result<model::access::ServiceAccess, AppError> {
        let access_entity: ServiceAccess = access.clone().into();

        // Delete (if necess)
        _ = self.delete(access.service_id, &access.entity_type, access.entity_id)?;

        // Insert
        diesel::insert_into(dsl::service_accesses)
            .values((
                dsl::service_id.eq(access_entity.service_id),
                dsl::entity_type.eq(access_entity.entity_type.as_str()),
                dsl::entity_id.eq(access_entity.entity_id),
            ))
            .returning(ServiceAccess::as_returning())
            .get_result::<ServiceAccess>(
                self.connection
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .deref_mut(),
            )
            .map_err(|err| {
                AppError::GenWithMsgAndErr("Error putting ServiceAccess".to_string(), Box::new(err))
            })?;

        Ok(access)
    }

    fn get(
        &self,
        service_id: i64,
        entity_type: &model::access::EntityType,
        entity_id: i64,
    ) -> Result<Option<model::access::ServiceAccess>, AppError> {
        let entity_type = entity_type_to_string(entity_type);
        match dsl::service_accesses
            .find((entity_type.as_str(), entity_id, service_id))
            .select(ServiceAccess::as_select())
            .first(
                self.connection
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .deref_mut(),
            ) {
            Ok(access) => {
                let access: model::access::ServiceAccess = access.into();
                Ok(Some(access))
            }
            Err(diesel::NotFound) => Ok(None),
            Err(err) => Err(AppError::GenWithMsgAndErr(
                format!(
                    "Error getting ServiceAccess: svc_id={}, type={:?}, ent_id={}",
                    service_id, entity_type, entity_id
                ),
                Box::new(err),
            )),
        }
    }

    fn get_for_user(
        &self,
        service_id: i64,
        user: &model::user::User,
    ) -> Result<Option<model::access::ServiceAccess>, AppError> {
        let f = false.into_sql::<sql_types::Bool>();
        let access_list: Vec<ServiceAccess> = dsl::service_accesses
            .filter(
                dsl::service_id.eq(service_id).and(
                    f.or(dsl::entity_type
                        .eq("User")
                        .and(dsl::entity_id.eq(user.user_id)))
                        .or(dsl::entity_type
                            .eq("Role")
                            .and(dsl::entity_id.eq_any(user.roles.as_slice()))),
                ),
            )
            .select(ServiceAccess::as_select())
            .load(
                self.connection
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .deref_mut(),
            )
            .map_err(|err| {
                AppError::GenWithMsgAndErr(
                    format!(
                        "Error getting ServiceAccess: svc_id={}, user_id={}",
                        service_id, user.user_id
                    ),
                    Box::new(err),
                )
            })?;

        Ok(access_list.first().map(|access| {
            let access: model::access::ServiceAccess = access.into();
            access
        }))
    }

    fn get_all_for_user(
        &self,
        user: &model::user::User,
    ) -> Result<Vec<model::access::ServiceAccess>, AppError> {
        let f = false.into_sql::<sql_types::Bool>();
        let access_list: Vec<ServiceAccess> = dsl::service_accesses
            .filter(
                f.or(dsl::entity_type
                    .eq("User")
                    .and(dsl::entity_id.eq(user.user_id)))
                    .or(dsl::entity_type
                        .eq("Role")
                        .and(dsl::entity_id.eq_any(user.roles.as_slice()))),
            )
            .select(ServiceAccess::as_select())
            .load(
                self.connection
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .deref_mut(),
            )
            .map_err(|err| {
                AppError::GenWithMsgAndErr(
                    format!("Error getting ServiceAccess: user_id={}", user.user_id),
                    Box::new(err),
                )
            })?;

        Ok(access_list
            .iter()
            .map(|access| access.into())
            .collect::<Vec<model::access::ServiceAccess>>())
    }

    fn delete(
        &self,
        service_id: i64,
        entity_type: &model::access::EntityType,
        entity_id: i64,
    ) -> Result<Option<model::access::ServiceAccess>, AppError> {
        let curr_access = self.get(service_id, entity_type, entity_id)?;
        if curr_access.is_none() {
            return Ok(None);
        }

        let entity_type = entity_type_to_string(entity_type);

        match diesel::delete(dsl::service_accesses)
            .filter(
                dsl::entity_type
                    .eq(entity_type.as_str())
                    .and(dsl::entity_id.eq(entity_id))
                    .and(dsl::service_id.eq(service_id)),
            )
            .execute(
                self.connection
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .deref_mut(),
            ) {
            Ok(_) => Ok(curr_access),
            Err(diesel::NotFound) => Ok(None),
            Err(err) => Err(AppError::GenWithMsgAndErr(
                format!(
                    "Error getting ServiceAccess: svc_id={}, type={:?}, ent_id={}",
                    service_id, entity_type, entity_id
                ),
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
        "access",
    ];

    #[test]
    fn pgdbaccessrepo_access_from_model() {
        let model_access1 = model::access::ServiceAccess {
            service_id: 200,
            entity_type: model::access::EntityType::Role,
            entity_id: 50,
        };
        let model_access2 = model::access::ServiceAccess {
            service_id: 201,
            entity_type: model::access::EntityType::User,
            entity_id: 100,
        };
        let expected_access1 = ServiceAccess {
            service_id: 200,
            entity_type: "Role".to_string(),
            entity_id: 50,
        };
        let expected_access2 = ServiceAccess {
            service_id: 201,
            entity_type: "User".to_string(),
            entity_id: 100,
        };
        assert_eq!(ServiceAccess::from(model_access1), expected_access1);
        assert_eq!(ServiceAccess::from(model_access2), expected_access2);
    }

    #[test]
    fn pgdbaccessrepo_access_to_model() {
        let access1 = ServiceAccess {
            service_id: 200,
            entity_type: "Role".to_string(),
            entity_id: 50,
        };
        let access2 = ServiceAccess {
            service_id: 201,
            entity_type: "User".to_string(),
            entity_id: 100,
        };
        let expected_model_access1 = model::access::ServiceAccess {
            service_id: 200,
            entity_type: model::access::EntityType::Role,
            entity_id: 50,
        };
        let expected_model_access2 = model::access::ServiceAccess {
            service_id: 201,
            entity_type: model::access::EntityType::User,
            entity_id: 100,
        };
        assert_eq!(
            model::access::ServiceAccess::from(access1),
            expected_model_access1
        );
        assert_eq!(
            model::access::ServiceAccess::from(access2),
            expected_model_access2
        );
    }

    #[test]
    #[serial(pgdb_access)]
    fn pgdbaccessrepo_put_when_existing_access() {
        let expected_access = model::access::ServiceAccess {
            service_id: 200,
            entity_type: model::access::EntityType::User,
            entity_id: 100,
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(
                    &mut db_conn,
                    &db_conn::tests::SQL_CREATE_SERVICE_ACCESS_RECORDS,
                )
                .unwrap();

            let mut access_repo = PostgresServiceAccessRepo::new();
            access_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = access_repo.put(expected_access.clone());

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let access = result.unwrap();

            assert_eq!(access, expected_access);
        }
    }

    #[test]
    #[serial(pgdb_access)]
    fn pgdbaccessrepo_put_when_new_access() {
        let expected_access = model::access::ServiceAccess {
            service_id: 201,
            entity_type: model::access::EntityType::Role,
            entity_id: 51,
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(
                    &mut db_conn,
                    &db_conn::tests::SQL_CREATE_SERVICE_ACCESS_RECORDS,
                )
                .unwrap();

            let mut access_repo = PostgresServiceAccessRepo::new();
            access_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = access_repo.put(expected_access.clone());

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let access = result.unwrap();
            assert_eq!(access, expected_access);
        }
    }

    #[test]
    #[serial(pgdb_access)]
    fn pgdbaccessrepo_get_when_invalid_user() {
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(
                    &mut db_conn,
                    &db_conn::tests::SQL_CREATE_SERVICE_ACCESS_RECORDS,
                )
                .unwrap();

            let mut access_repo = PostgresServiceAccessRepo::new();
            access_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = access_repo.get(200, &model::access::EntityType::User, 10);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            assert!(result.unwrap().is_none());
        }
    }

    #[test]
    #[serial(pgdb_access)]
    fn pgdbaccessrepo_get_when_invalid_service() {
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(
                    &mut db_conn,
                    &db_conn::tests::SQL_CREATE_SERVICE_ACCESS_RECORDS,
                )
                .unwrap();

            let mut access_repo = PostgresServiceAccessRepo::new();
            access_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = access_repo.get(20, &model::access::EntityType::Role, 50);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            assert!(result.unwrap().is_none());
        }
    }

    #[test]
    #[serial(pgdb_access)]
    fn pgdbaccessrepo_get_when_valid_user_and_service() {
        let expected_access = model::access::ServiceAccess {
            service_id: 200,
            entity_type: model::access::EntityType::User,
            entity_id: 100,
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(
                    &mut db_conn,
                    &db_conn::tests::SQL_CREATE_SERVICE_ACCESS_RECORDS,
                )
                .unwrap();

            let mut access_repo = PostgresServiceAccessRepo::new();
            access_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = access_repo.get(200, &model::access::EntityType::User, 100);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_access = result.unwrap();

            assert!(actual_access.is_some());
            assert_eq!(actual_access.unwrap(), expected_access);
        }
    }

    #[test]
    #[serial(pgdb_access)]
    fn pgdbaccessrepo_get_all_for_user_when_invalid_user() {
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(
                    &mut db_conn,
                    &db_conn::tests::SQL_CREATE_SERVICE_ACCESS_RECORDS,
                )
                .unwrap();

            let mut access_repo = PostgresServiceAccessRepo::new();
            access_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = access_repo.get_all_for_user(&model::user::User::new(
                10,
                Some("uname10"),
                Some("pass10"),
                "name10",
                &model::user::Status::Active,
                &vec![],
            ));

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            assert_eq!(result.unwrap().len(), 0);
        }
    }

    #[test]
    #[serial(pgdb_access)]
    fn pgdbaccessrepo_get_all_for_user_when_valid_user() {
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(
                    &mut db_conn,
                    &db_conn::tests::SQL_CREATE_SERVICE_ACCESS_RECORDS,
                )
                .unwrap();

            let mut access_repo = PostgresServiceAccessRepo::new();
            access_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = access_repo.get_all_for_user(&model::user::User::new(
                100,
                Some("uname1"),
                Some("pass1"),
                "name1",
                &model::user::Status::Active,
                &vec![50],
            ));

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_accesses = result.unwrap();
            assert_eq!(actual_accesses.len(), 2);

            let expected_access_db_map: HashMap<
                (i64, model::access::EntityType, i64),
                model::access::ServiceAccess,
            > = HashMap::from([
                (
                    (200, model::access::EntityType::User, 100),
                    model::access::ServiceAccess {
                        service_id: 200,
                        entity_type: model::access::EntityType::User,
                        entity_id: 100,
                    },
                ),
                (
                    (201, model::access::EntityType::Role, 50),
                    model::access::ServiceAccess {
                        service_id: 200,
                        entity_type: model::access::EntityType::User,
                        entity_id: 100,
                    },
                ),
            ]);

            assert_eq!(
                actual_accesses
                    .iter()
                    .filter(|entry| !expected_access_db_map.contains_key(&(
                        entry.service_id,
                        entry.entity_type.clone(),
                        entry.entity_id
                    )))
                    .count(),
                0
            );
        }
    }

    #[test]
    #[serial(pgdb_access)]
    fn pgdbaccessrepo_get_for_user_when_invalid_user() {
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(
                    &mut db_conn,
                    &db_conn::tests::SQL_CREATE_SERVICE_ACCESS_RECORDS,
                )
                .unwrap();

            let mut access_repo = PostgresServiceAccessRepo::new();
            access_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = access_repo.get_for_user(
                200,
                &model::user::User::new(
                    10,
                    Some("uname10"),
                    Some("pass10"),
                    "name10",
                    &model::user::Status::Active,
                    &vec![5],
                ),
            );

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            assert!(result.unwrap().is_none());
        }
    }

    #[test]
    #[serial(pgdb_access)]
    fn pgdbaccessrepo_get_for_user_when_valid_user() {
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(
                    &mut db_conn,
                    &db_conn::tests::SQL_CREATE_SERVICE_ACCESS_RECORDS,
                )
                .unwrap();

            let mut access_repo = PostgresServiceAccessRepo::new();
            access_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = access_repo.get_for_user(
                200,
                &model::user::User::new(
                    100,
                    Some("uname10"),
                    Some("pass10"),
                    "name10",
                    &model::user::Status::Active,
                    &vec![5],
                ),
            );

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }
            let actual_access = result.unwrap();

            assert!(actual_access.is_some());

            let expected_access = model::access::ServiceAccess {
                service_id: 200,
                entity_type: model::access::EntityType::User,
                entity_id: 100,
            };

            assert_eq!(actual_access.unwrap(), expected_access);
        }
    }

    #[test]
    #[serial(pgdb_access)]
    fn pgdbaccessrepo_get_for_user_when_valid_role() {
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(
                    &mut db_conn,
                    &db_conn::tests::SQL_CREATE_SERVICE_ACCESS_RECORDS,
                )
                .unwrap();

            let mut access_repo = PostgresServiceAccessRepo::new();
            access_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = access_repo.get_for_user(
                201,
                &model::user::User::new(
                    10,
                    Some("uname10"),
                    Some("pass10"),
                    "name10",
                    &model::user::Status::Active,
                    &vec![50],
                ),
            );

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }
            let actual_access = result.unwrap();

            assert!(actual_access.is_some());

            let expected_access = model::access::ServiceAccess {
                service_id: 201,
                entity_type: model::access::EntityType::Role,
                entity_id: 50,
            };

            assert_eq!(actual_access.unwrap(), expected_access);
        }
    }

    #[test]
    #[serial(pgdb_access)]
    fn pgdbaccessrepo_delete_when_invalid_access() {
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(
                    &mut db_conn,
                    &db_conn::tests::SQL_CREATE_SERVICE_ACCESS_RECORDS,
                )
                .unwrap();

            let mut access_repo = PostgresServiceAccessRepo::new();
            access_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = access_repo.delete(200, &model::access::EntityType::User, 10);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            assert!(result.unwrap().is_none());
        }
    }

    #[test]
    #[serial(pgdb_access)]
    fn pgdbaccessrepo_delete_when_valid_access() {
        let expected_prev_access = model::access::ServiceAccess {
            service_id: 200,
            entity_type: model::access::EntityType::User,
            entity_id: 100,
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(
                    &mut db_conn,
                    &db_conn::tests::SQL_CREATE_SERVICE_ACCESS_RECORDS,
                )
                .unwrap();

            let mut access_repo = PostgresServiceAccessRepo::new();
            access_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = access_repo.delete(200, &model::access::EntityType::User, 100);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_prev_access = result.unwrap();

            assert!(actual_prev_access.is_some());
            assert_eq!(actual_prev_access.unwrap(), expected_prev_access);
        }
    }
}
