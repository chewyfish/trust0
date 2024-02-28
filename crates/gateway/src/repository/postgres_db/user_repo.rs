use diesel::prelude::*;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::repository::postgres_db::db_conn;
use crate::repository::postgres_db::db_schema::user_roles;
use crate::repository::postgres_db::db_schema::users::dsl::*;
use crate::repository::user_repo::UserRepository;
use trust0_common::error::AppError;
use trust0_common::model;

/// User ORM model struct
#[derive(Debug, AsChangeset, Identifiable, Insertable, Queryable, Selectable, PartialEq)]
#[diesel(table_name = crate::repository::postgres_db::db_schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    /// User ID (unique across users)
    pub id: i64,
    /// Friendly name for user
    pub name: String,
    /// User account status
    pub status: String,
    /// (optional) Username used in secondary authentication
    pub user_name: Option<String>,
    /// (optional) Password used in secondary authentication
    pub password: Option<String>,
    /// Datetime record was created
    pub created_at: Option<SystemTime>,
    /// Datetime record was last updated
    pub updated_at: Option<SystemTime>,
}

impl From<model::user::User> for User {
    fn from(user: model::user::User) -> Self {
        Self {
            id: user.user_id,
            name: user.name,
            status: match user.status {
                model::user::Status::Active => "Active".to_string(),
                model::user::Status::Inactive => "Inactive".to_string(),
            },
            user_name: user.user_name.clone(),
            password: user.password.clone(),
            created_at: None,
            updated_at: None,
        }
    }
}

impl From<User> for model::user::User {
    fn from(user: User) -> Self {
        Self::from(&user)
    }
}

impl From<&User> for model::user::User {
    fn from(user: &User) -> Self {
        Self {
            user_id: user.id,
            name: user.name.clone(),
            status: match user.status.as_str() {
                "Active" => model::user::Status::Active,
                "Inactive" => model::user::Status::Inactive,
                val => panic!("Invalid user status: val={}", val),
            },
            roles: vec![],
            user_name: user.user_name.clone(),
            password: user.password.clone(),
        }
    }
}

#[derive(Queryable, Selectable, Insertable, Identifiable, Associations, Debug, PartialEq)]
#[diesel(belongs_to(User))]
#[diesel(belongs_to(crate::repository::postgres_db::role_repo::Role))]
#[diesel(table_name = crate::repository::postgres_db::db_schema::user_roles)]
#[diesel(primary_key(user_id, role_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct UserRole {
    pub user_id: i64,
    pub role_id: i64,
}

/// User Repository
pub struct PostgresUserRepo {
    /// If connected, an establish Postgres connection object
    connection: Option<Arc<Mutex<PgConnection>>>,
}

impl PostgresUserRepo {
    /// Creates a new user repository.
    ///
    /// # Returns
    ///
    /// A newly constructed [`PostgresUserRepo`] object.
    ///
    pub fn new() -> PostgresUserRepo {
        PostgresUserRepo { connection: None }
    }

    /// Get all user role records
    ///
    /// # Arguments
    ///
    /// * `db_conn` - [`PgConnection`] object
    /// * `user_id` - User ID
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a vector of [`i64`] role IDs.
    ///
    fn get_all_user_records(
        &self,
        db_conn: &mut PgConnection,
        user_id: i64,
    ) -> Result<Vec<i64>, diesel::result::Error> {
        let user_roles_list: Vec<UserRole> = user_roles::dsl::user_roles
            .filter(user_roles::dsl::user_id.eq(user_id))
            .select(UserRole::as_select())
            .load(db_conn)?;

        Ok(user_roles_list
            .iter()
            .map(|user_role| user_role.role_id)
            .collect::<Vec<i64>>())
    }

    /// Delete user role records
    ///
    /// # Arguments
    ///
    /// * `db_conn` - [`PgConnection`] object
    /// * `user_id` - User ID
    ///
    /// # Returns
    ///
    /// A [`Result`] containing a boolean indicating if record was found and deleted.
    ///
    fn delete_user_roles(
        &self,
        db_conn: &mut PgConnection,
        user_id: i64,
    ) -> Result<bool, diesel::result::Error> {
        match diesel::delete(
            user_roles::dsl::user_roles.filter(user_roles::dsl::user_id.eq(user_id)),
        )
        .execute(db_conn)
        {
            Ok(_) => Ok(true),
            Err(diesel::NotFound) => Ok(false),
            Err(err) => Err(err),
        }
    }
}

impl UserRepository for PostgresUserRepo {
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError> {
        self.connection = Some(
            db_conn::INSTANCE
                .lock()
                .unwrap()
                .establish_connection(connect_spec)?,
        );
        Ok(())
    }

    fn put(&self, user: model::user::User) -> Result<model::user::User, AppError> {
        self.connection
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .deref_mut()
            .transaction::<model::user::User, diesel::result::Error, _>(|db_conn| {
                let user_entity: User = user.clone().into();
                let user_roles = user.roles.clone();
                let mut upserted_user = None;
                let mut is_new_record = false;

                // Update user record
                if user_entity.id != 0 {
                    match diesel::update(users.filter(id.eq(user_entity.id)))
                        .set((
                            id.eq(user_entity.id),
                            name.eq(user_entity.name.as_str()),
                            status.eq(user_entity.status.as_str()),
                            user_name.eq(user_entity.user_name.clone()),
                            password.eq(user_entity.password.clone()),
                        ))
                        .returning(id)
                        .get_result::<i64>(db_conn)
                    {
                        Ok(_) => upserted_user = Some(user.clone()),
                        Err(diesel::NotFound) => {}
                        Err(err) => return Err(err),
                    }
                }

                // Insert user record
                if upserted_user.is_none() {
                    let query_result = match user_entity.id == 0 {
                        true => diesel::insert_into(users)
                            .values((
                                name.eq(user_entity.name.as_str()),
                                status.eq(user_entity.status.as_str()),
                                user_name.eq(user_entity.user_name.clone()),
                                password.eq(user_entity.password.clone()),
                            ))
                            .returning(id)
                            .get_result::<i64>(db_conn),
                        false => diesel::insert_into(users)
                            .values((
                                id.eq(user_entity.id),
                                name.eq(user_entity.name.as_str()),
                                status.eq(user_entity.status.as_str()),
                                user_name.eq(user_entity.user_name.clone()),
                                password.eq(user_entity.password.clone()),
                            ))
                            .returning(id)
                            .get_result::<i64>(db_conn),
                    };

                    match query_result {
                        Ok(user_id) => {
                            let mut user = user.clone();
                            user.user_id = user_id;
                            upserted_user = Some(user);
                            is_new_record = true;
                        }
                        Err(err) => return Err(err),
                    }
                }

                // Delete current user role records
                if !is_new_record {
                    self.delete_user_roles(db_conn, user_entity.id)?;
                }

                // Insert user role records
                for user_role in &user_roles {
                    diesel::insert_into(user_roles::dsl::user_roles)
                        .values((
                            user_roles::dsl::user_id.eq(upserted_user.as_ref().unwrap().user_id),
                            user_roles::dsl::role_id.eq(user_role),
                        ))
                        .returning(UserRole::as_returning())
                        .get_result(db_conn)?;
                }

                upserted_user.as_mut().unwrap().roles = user_roles;

                Ok(upserted_user.unwrap())
            })
            .map_err(|err| {
                AppError::GenWithMsgAndErr("Error putting User".to_string(), Box::new(err))
            })
    }

    fn get(&self, user_id: i64) -> Result<Option<model::user::User>, AppError> {
        // Get user's roles
        let user_roles = self
            .get_all_user_records(
                self.connection
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .deref_mut(),
                user_id,
            )
            .map_err(|err| {
                AppError::GenWithMsgAndErr(
                    format!("Error getting user roles: user_id={}", user_id),
                    Box::new(err),
                )
            })?;

        // Get user
        match users.find(user_id).select(User::as_select()).first(
            self.connection
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .deref_mut(),
        ) {
            Ok(user) => {
                let mut user: model::user::User = user.into();
                user.roles = user_roles;
                Ok(Some(user))
            }
            Err(diesel::NotFound) => Ok(None),
            Err(err) => Err(AppError::GenWithMsgAndErr(
                format!("Error getting User: id={}", user_id),
                Box::new(err),
            )),
        }
    }

    fn delete(&self, user_id: i64) -> Result<Option<model::user::User>, AppError> {
        // Get current user (if avail)
        let curr_user = self.get(user_id)?;
        if curr_user.is_none() {
            return Ok(None);
        }

        // Delete user and user roles
        self.connection
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .deref_mut()
            .transaction::<(), diesel::result::Error, _>(|db_conn| {
                // Delete user roles
                self.delete_user_roles(db_conn, user_id)?;

                // Delete user
                match diesel::delete(users.filter(id.eq(user_id))).execute(db_conn) {
                    Ok(_) => Ok(()),
                    Err(diesel::NotFound) => Ok(()),
                    Err(err) => Err(err),
                }
            })
            .map_err(|err| {
                AppError::GenWithMsgAndErr("Error putting User".to_string(), Box::new(err))
            })?;

        Ok(curr_user)
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::path::PathBuf;

    pub const POSTGRES_DATABASE_DIR_PATHPARTS: [&str; 8] = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "target",
        "test-gateway",
        "postgres",
        "data",
        "user",
    ];

    #[test]
    fn pgdbuserrepo_user_from_model() {
        let model_user100 = model::user::User {
            user_id: 100,
            name: "User100".to_string(),
            status: model::user::Status::Active,
            roles: vec![],
            user_name: Some("uname100".to_string()),
            password: Some("pass100".to_string()),
        };
        let model_user101 = model::user::User {
            user_id: 101,
            name: "User101".to_string(),
            status: model::user::Status::Inactive,
            roles: vec![],
            user_name: None,
            password: None,
        };
        let expected_user100 = User {
            id: 100,
            name: "User100".to_string(),
            status: "Active".to_string(),
            user_name: Some("uname100".to_string()),
            password: Some("pass100".to_string()),
            created_at: None,
            updated_at: None,
        };
        let expected_user101 = User {
            id: 101,
            name: "User101".to_string(),
            status: "Inactive".to_string(),
            user_name: None,
            password: None,
            created_at: None,
            updated_at: None,
        };
        assert_eq!(User::from(model_user100), expected_user100);
        assert_eq!(User::from(model_user101), expected_user101);
    }

    #[test]
    fn pgdbuserrepo_user_to_model() {
        let user100 = User {
            id: 100,
            name: "User100".to_string(),
            status: "Active".to_string(),
            user_name: Some("uname100".to_string()),
            password: Some("pass100".to_string()),
            created_at: None,
            updated_at: None,
        };
        let user101 = User {
            id: 101,
            name: "User101".to_string(),
            status: "Inactive".to_string(),
            user_name: None,
            password: None,
            created_at: None,
            updated_at: None,
        };
        let expected_model_user100 = model::user::User {
            user_id: 100,
            name: "User100".to_string(),
            status: model::user::Status::Active,
            roles: vec![],
            user_name: Some("uname100".to_string()),
            password: Some("pass100".to_string()),
        };
        let expected_model_user101 = model::user::User {
            user_id: 101,
            name: "User101".to_string(),
            status: model::user::Status::Inactive,
            roles: vec![],
            user_name: None,
            password: None,
        };
        assert_eq!(model::user::User::from(user100), expected_model_user100);
        assert_eq!(model::user::User::from(user101), expected_model_user101);
    }

    #[test]
    #[serial(pgdb_user)]
    fn pgdbuserrepo_put_when_existing_user() {
        let expected_user = model::user::User {
            user_id: 100,
            name: "User100.1".to_string(),
            status: model::user::Status::Active,
            roles: vec![50],
            user_name: Some("uname100".to_string()),
            password: Some("pass100".to_string()),
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_USER_RECORDS)
                .unwrap();
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_USER_ROLE_RECORDS)
                .unwrap();

            let mut user_repo = PostgresUserRepo::new();
            user_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = user_repo.put(expected_user.clone());

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let user = result.unwrap();

            assert_eq!(user, expected_user);
        }
    }

    #[test]
    #[serial(pgdb_user)]
    fn pgdbuserrepo_put_when_new_user_and_given_id() {
        let expected_user = model::user::User {
            user_id: 201,
            name: "User201".to_string(),
            status: model::user::Status::Active,
            roles: vec![50, 51],
            user_name: Some("uname201".to_string()),
            password: Some("pass201".to_string()),
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_USER_RECORDS)
                .unwrap();
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_USER_ROLE_RECORDS)
                .unwrap();

            let mut user_repo = PostgresUserRepo::new();
            user_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = user_repo.put(expected_user.clone());

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let user = result.unwrap();
            assert_eq!(user, expected_user);
        }
    }

    #[test]
    #[serial(pgdb_user)]
    fn pgdbuserrepo_put_when_new_user_and_not_given_id() {
        let expected_user = model::user::User {
            user_id: 0,
            name: "UserXX".to_string(),
            status: model::user::Status::Active,
            roles: vec![50, 51],
            user_name: Some("unameXX".to_string()),
            password: Some("passXX".to_string()),
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_USER_RECORDS)
                .unwrap();
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_USER_ROLE_RECORDS)
                .unwrap();

            let mut user_repo = PostgresUserRepo::new();
            user_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = user_repo.put(expected_user.clone());

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let user = result.unwrap();
            assert!(user.user_id > 0);
            assert_eq!(user.name, expected_user.name);
        }
    }

    #[test]
    #[serial(pgdb_user)]
    fn pgdbuserrepo_get_when_invalid_user() {
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_USER_RECORDS)
                .unwrap();
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_USER_ROLE_RECORDS)
                .unwrap();

            let mut user_repo = PostgresUserRepo::new();
            user_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = user_repo.get(500);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_user = result.unwrap();

            assert!(actual_user.is_none());
        }
    }

    #[test]
    #[serial(pgdb_user)]
    fn pgdbuserrepo_get_when_valid_user() {
        let expected_user = model::user::User {
            user_id: 100,
            name: "User100".to_string(),
            status: model::user::Status::Active,
            roles: vec![50, 51],
            user_name: Some("uname100".to_string()),
            password: Some("pass100".to_string()),
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_USER_RECORDS)
                .unwrap();
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_USER_ROLE_RECORDS)
                .unwrap();

            let mut user_repo = PostgresUserRepo::new();
            user_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = user_repo.get(expected_user.user_id);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_user = result.unwrap();

            assert!(actual_user.is_some());
            assert_eq!(actual_user.unwrap(), expected_user);
        }
    }

    #[test]
    #[serial(pgdb_user)]
    fn pgdbuserrepo_delete_when_invalid_user() {
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_USER_RECORDS)
                .unwrap();
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_USER_ROLE_RECORDS)
                .unwrap();

            let mut user_repo = PostgresUserRepo::new();
            user_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = user_repo.delete(500);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_user = result.unwrap();

            assert!(actual_user.is_none());
        }
    }

    #[test]
    #[serial(pgdb_user)]
    fn pgdbuserrepo_delete_when_valid_user() {
        let expected_user = model::user::User {
            user_id: 100,
            name: "User100".to_string(),
            status: model::user::Status::Active,
            roles: vec![50, 51],
            user_name: Some("uname100".to_string()),
            password: Some("pass100".to_string()),
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
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_USER_RECORDS)
                .unwrap();
            db_conn::tests::DB
                .lock()
                .unwrap()
                .execute_sql(&mut db_conn, &db_conn::tests::SQL_CREATE_USER_ROLE_RECORDS)
                .unwrap();

            let mut user_repo = PostgresUserRepo::new();
            user_repo
                .connect_to_datasource(
                    &pg_embed
                        .lock()
                        .unwrap()
                        .full_db_uri(db_conn::tests::DB_NAME),
                )
                .unwrap();

            let result = user_repo.delete(expected_user.user_id);

            if let Err(err) = &result {
                panic!("Unexpected result: err={:?}", &err)
            }

            let actual_user = result.unwrap();

            assert!(actual_user.is_some());
            assert_eq!(actual_user.unwrap(), expected_user);
        }
    }
}
