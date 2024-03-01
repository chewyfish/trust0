#[cfg(not(feature = "postgres_db"))]
use chrono::NaiveDateTime;
use diesel::prelude::*;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};
#[cfg(feature = "postgres_db")]
use std::time::SystemTime;

use crate::repository::diesel_orm::db_schema::roles::dsl::*;
use crate::repository::role_repo::RoleRepository;
use trust0_common::error::AppError;
use trust0_common::model;

/// RBAC Role ORM model struct
#[derive(Debug, AsChangeset, Identifiable, Insertable, Queryable, Selectable, PartialEq)]
#[diesel(table_name = crate::repository::diesel_orm::db_schema::roles)]
pub struct Role {
    /// Role ID (unique across roles)
    pub id: i64,
    /// Friendly name for role
    pub name: String,
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

impl From<model::role::Role> for Role {
    fn from(role: model::role::Role) -> Self {
        Self {
            id: role.role_id,
            name: role.name,
            created_at: None,
            updated_at: None,
        }
    }
}

impl From<Role> for model::role::Role {
    fn from(role: Role) -> Self {
        Self::from(&role)
    }
}

impl From<&Role> for model::role::Role {
    fn from(role: &Role) -> Self {
        Self {
            role_id: role.id,
            name: role.name.clone(),
        }
    }
}

/// RBAC Role Repository
pub struct DieselRoleRepo {
    /// An establish Diesel connection object
    #[cfg(not(feature = "postgres_db"))]
    connection: Arc<Mutex<MysqlConnection>>,
    #[cfg(feature = "postgres_db")]
    connection: Arc<Mutex<PgConnection>>,
}

impl DieselRoleRepo {
    /// Creates a new role repository.
    ///
    /// # Returns
    ///
    /// A newly constructed [`DieselRoleRepo`] object.
    ///
    #[cfg(not(feature = "postgres_db"))]
    pub fn new(db_conn: &Arc<Mutex<MysqlConnection>>) -> DieselRoleRepo {
        DieselRoleRepo {
            connection: db_conn.clone(),
        }
    }
    #[cfg(feature = "postgres_db")]
    pub fn new(db_conn: &Arc<Mutex<PgConnection>>) -> DieselRoleRepo {
        DieselRoleRepo {
            connection: db_conn.clone(),
        }
    }
}

impl RoleRepository for DieselRoleRepo {
    fn connect_to_datasource(&mut self, _connect_spec: &str) -> Result<(), AppError> {
        Ok(())
    }

    fn put(&self, role: model::role::Role) -> Result<model::role::Role, AppError> {
        if role.role_id != 0 {
            match diesel::update(roles.filter(id.eq(role.role_id)))
                .set((id.eq(role.role_id), name.eq(role.name.as_str())))
                .execute(self.connection.lock().unwrap().deref_mut())
            {
                Ok(rows) if rows > 0 => return Ok(role),
                Ok(_) => {}
                Err(diesel::NotFound) => {}
                Err(err) => {
                    return Err(AppError::GenWithMsgAndErr(
                        "Error putting Role".to_string(),
                        Box::new(err),
                    ))
                }
            }
        }

        let query_result = match role.role_id == 0 {
            true => {
                #[cfg(not(feature = "postgres_db"))]
                {
                    diesel::insert_into(roles)
                        .values(name.eq(role.name.as_str()))
                        .execute(self.connection.lock().unwrap().deref_mut())
                        .map(|_| 100_i64)
                }
                #[cfg(feature = "postgres_db")]
                {
                    diesel::insert_into(roles)
                        .values(name.eq(role.name.as_str()))
                        .returning(id)
                        .get_result::<i64>(self.connection.lock().unwrap().deref_mut())
                }
            }
            false => diesel::insert_into(roles)
                .values((id.eq(role.role_id), name.eq(role.name.as_str())))
                .execute(self.connection.lock().unwrap().deref_mut())
                .map(|_| role.role_id),
        };

        match query_result {
            Ok(role_id) => {
                let mut role = role.clone();
                role.role_id = role_id;
                Ok(role)
            }
            Err(err) => Err(AppError::GenWithMsgAndErr(
                "Error putting Role".to_string(),
                Box::new(err),
            )),
        }
    }

    fn get(&self, role_id: i64) -> Result<Option<model::role::Role>, AppError> {
        match roles
            .find(role_id)
            .select(Role::as_select())
            .first(self.connection.lock().unwrap().deref_mut())
        {
            Ok(role) => Ok(Some(role.into())),
            Err(diesel::NotFound) => Ok(None),
            Err(err) => Err(AppError::GenWithMsgAndErr(
                format!("Error getting Role: id={}", role_id),
                Box::new(err),
            )),
        }
    }

    fn get_all(&self) -> Result<Vec<model::role::Role>, AppError> {
        let roles_list: Vec<Role> = roles
            .select(Role::as_select())
            .load(self.connection.lock().unwrap().deref_mut())
            .map_err(|err| {
                AppError::GenWithMsgAndErr("Error getting all Roles".to_string(), Box::new(err))
            })?;

        Ok(roles_list
            .iter()
            .map(|role| role.into())
            .collect::<Vec<model::role::Role>>())
    }

    fn delete(&self, role_id: i64) -> Result<Option<model::role::Role>, AppError> {
        let curr_role = self.get(role_id)?;
        if curr_role.is_none() {
            return Ok(None);
        }

        match diesel::delete(roles.filter(id.eq(role_id)))
            .execute(self.connection.lock().unwrap().deref_mut())
        {
            Ok(_) => Ok(Some(curr_role.unwrap())),
            Err(diesel::NotFound) => Ok(None),
            Err(err) => Err(AppError::GenWithMsgAndErr(
                format!("Error deleting Role: id={}", role_id),
                Box::new(err),
            )),
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
        "role",
    ];

    // utils
    // =====

    fn create_role_repository(connect_spec: &str) -> DieselRoleRepo {
        DieselRoleRepo::new(
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
    fn diselrolerepo_role_from_model() {
        let model_role = model::role::Role {
            role_id: 50,
            name: "Role50.1".to_string(),
        };
        let expected_role = Role {
            id: 50,
            name: "Role50.1".to_string(),
            created_at: None,
            updated_at: None,
        };
        assert_eq!(Role::from(model_role), expected_role);
    }

    #[test]
    fn diselrolerepo_role_to_model() {
        let role = Role {
            id: 50,
            name: "Role50.1".to_string(),
            created_at: None,
            updated_at: None,
        };
        let expected_model_role = model::role::Role {
            role_id: 50,
            name: "Role50.1".to_string(),
        };
        assert_eq!(model::role::Role::from(role), expected_model_role);
    }

    #[test]
    #[serial(disel_role)]
    fn diselrolerepo_put_when_existing_role() {
        let expected_role = model::role::Role {
            role_id: 50,
            name: "Role50.1".to_string(),
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
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_ROLE_RECORDS)
                .unwrap();

            let role_repo = create_role_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = role_repo.put(expected_role.clone());

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let role = result.unwrap();

            assert_eq!(role, expected_role);
        }
    }

    #[test]
    #[serial(disel_role)]
    fn diselrolerepo_put_when_new_role_and_given_id() {
        let expected_role = model::role::Role {
            role_id: 501,
            name: "Role501".to_string(),
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
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_ROLE_RECORDS)
                .unwrap();

            let role_repo = create_role_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = role_repo.put(expected_role.clone());

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let role = result.unwrap();
            assert_eq!(role, expected_role);
        }
    }

    #[test]
    #[serial(disel_role)]
    fn diselrolerepo_put_when_new_role_and_not_given_id() {
        let expected_role = model::role::Role {
            role_id: 0,
            name: "RoleXX".to_string(),
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

            let role_repo = create_role_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = role_repo.put(expected_role.clone());

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let role = result.unwrap();
            assert!(role.role_id > 0);
            assert_eq!(role.name, expected_role.name);
        }
    }

    #[test]
    #[serial(disel_role)]
    fn diselrolerepo_get_when_invalid_role() {
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
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_ROLE_RECORDS)
                .unwrap();

            let role_repo = create_role_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = role_repo.get(500);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_role = result.unwrap();

            assert!(actual_role.is_none());
        }
    }

    #[test]
    #[serial(disel_role)]
    fn diselrolerepo_get_when_valid_role() {
        let expected_role = model::role::Role {
            role_id: 50,
            name: "Role50".to_string(),
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
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_ROLE_RECORDS)
                .unwrap();

            let role_repo = create_role_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = role_repo.get(expected_role.role_id);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_role = result.unwrap();

            assert!(actual_role.is_some());
            assert_eq!(actual_role.unwrap(), expected_role);
        }
    }

    #[test]
    #[serial(disel_role)]
    fn diselrolerepo_get_all() {
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
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_ROLE_RECORDS)
                .unwrap();

            let role_repo = create_role_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = role_repo.get_all();

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_roles = result.unwrap();

            assert_eq!(actual_roles.len(), 2);

            let expected_role_db_map: HashMap<i64, model::role::Role> = HashMap::from([
                (
                    50,
                    model::role::Role {
                        role_id: 50,
                        name: "Role50".to_string(),
                    },
                ),
                (
                    51,
                    model::role::Role {
                        role_id: 51,
                        name: "Role51".to_string(),
                    },
                ),
            ]);

            assert_eq!(
                actual_roles
                    .iter()
                    .filter(|entry| !expected_role_db_map.contains_key(&entry.role_id))
                    .count(),
                0
            );
        }
    }

    #[test]
    #[serial(disel_role)]
    fn diselrolerepo_delete_when_invalid_role() {
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
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_ROLE_RECORDS)
                .unwrap();

            let role_repo = create_role_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = role_repo.delete(500);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_role = result.unwrap();

            assert!(actual_role.is_none());
        }
    }

    #[test]
    #[serial(disel_role)]
    fn diselrolerepo_delete_when_valid_role() {
        let expected_role = model::role::Role {
            role_id: 50,
            name: "Role50".to_string(),
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
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_ROLE_RECORDS)
                .unwrap();

            let role_repo = create_role_repository(
                &pg_embed
                    .lock()
                    .unwrap()
                    .full_db_uri(db_conn::tests::DB_NAME)
                    .as_str(),
            );

            let result = role_repo.delete(expected_role.role_id);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_role = result.unwrap();

            assert!(actual_role.is_some());
            assert_eq!(actual_role.unwrap(), expected_role);
        }
    }
}
