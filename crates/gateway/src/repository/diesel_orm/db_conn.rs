/// Unit tests
#[cfg(test)]
pub mod tests {
    use diesel::{Connection, PgConnection, RunQueryDsl};
    use diesel_migrations::{FileBasedMigrations, MigrationHarness};
    use log::error;
    use once_cell::sync::Lazy;
    use pg_embed::pg_enums::PgAuthMethod;
    use pg_embed::pg_errors::PgEmbedError;
    use pg_embed::pg_fetch::{PgFetchSettings, PG_V15};
    use pg_embed::postgres::{PgEmbed, PgSettings};
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use trust0_common::error::AppError;

    const DB_PORT_START: u16 = 8760;
    pub const DB_NAME: &str = "trust0";
    pub const DB_USERNAME: &str = "postgres";
    pub const DB_PASSWORD: &str = "postgres";

    const MIGRATION_DIR_PATHPARTS: [&str; 3] =
        [env!("CARGO_MANIFEST_DIR"), "migrations", "postgres"];

    pub const SQL_CREATE_ROLE_RECORDS: [&str; 2] = [
        "INSERT INTO roles (id, name) VALUES (50, 'Role50')",
        "INSERT INTO roles (id, name) VALUES (51, 'Role51')",
    ];
    pub const SQL_CREATE_SERVICE_RECORDS: [&str; 2] = [
        "INSERT INTO services (id, name, transport, host, port) VALUES (200, 'Service200', 'TCP', 'host200.com', 8200)",
        "INSERT INTO services (id, name, transport, host, port) VALUES (201, 'Service201', 'UDP', 'host201.com', 8201)",
    ];
    pub const SQL_CREATE_USER_RECORDS: [&str; 2] = [
        "INSERT INTO users (id, name, status, user_name, password) VALUES (100, 'User100', 'Active', 'uname100', 'pass100')",
        "INSERT INTO users (id, name, status, user_name, password) VALUES (101, 'User101', 'Inactive', NULL, NULL)",
    ];
    pub const SQL_CREATE_USER_ROLE_RECORDS: [&str; 2] = [
        "INSERT INTO user_roles (user_id, role_id) VALUES (100, 50)",
        "INSERT INTO user_roles (user_id, role_id) VALUES (100, 51)",
    ];
    pub const SQL_CREATE_SERVICE_ACCESS_RECORDS: [&str; 3] = [
        "INSERT INTO service_accesses (service_id, entity_type, entity_id) VALUES (200, 'User', 100)",
        "INSERT INTO service_accesses (service_id, entity_type, entity_id) VALUES (201, 'Role', 50)",
        "INSERT INTO service_accesses (service_id, entity_type, entity_id) VALUES (200, 'User', 101)",
    ];

    pub static DB: Lazy<Arc<Mutex<EmbeddedDb>>> = Lazy::new(|| {
        Arc::new(Mutex::new(EmbeddedDb {
            next_port: DB_PORT_START,
            databases: HashMap::new(),
        }))
    });

    // utils
    // =====

    pub struct EmbeddedDb {
        next_port: u16,
        databases: HashMap<PathBuf, Arc<Mutex<PgEmbed>>>,
    }

    impl EmbeddedDb {
        pub fn setup_db(
            &mut self,
            database_dir: PathBuf,
        ) -> Result<(Arc<Mutex<PgEmbed>>, PgConnection), AppError> {
            // get embedded db for given path
            let pg_embed = self.acquire_embedded_db(database_dir, false)?;

            // set up current schema
            let migrations_path: PathBuf = MIGRATION_DIR_PATHPARTS.iter().collect();
            let migrations = FileBasedMigrations::from_path(&migrations_path).map_err(|err| {
                AppError::General(format!(
                    "Failed building postgres migrations object: path={:?}, err={:?}",
                    &migrations_path, &err
                ))
            })?;

            let db_url = pg_embed.lock().unwrap().full_db_uri(DB_NAME).clone();
            let mut db_conn = PgConnection::establish(&db_url.as_str()).unwrap();

            if !db_conn
                .has_pending_migration(migrations.clone())
                .map_err(|err| {
                    AppError::General(format!(
                        "Error checking pending postgres migrations: path={:?}, err={:?}",
                        &migrations_path, &err
                    ))
                })?
            {
                db_conn
                    .revert_all_migrations(migrations.clone())
                    .map_err(|err| {
                        AppError::General(format!(
                            "Error reverting postgres migrations: path={:?}, err={:?}",
                            &migrations_path, &err
                        ))
                    })?;
            }
            db_conn.run_pending_migrations(migrations).map_err(|err| {
                AppError::General(format!(
                    "Error running postgres migrations: path={:?}, err={:?}",
                    &migrations_path, &err
                ))
            })?;

            Ok((pg_embed, db_conn))
        }

        fn start_embedded_db(pg_embed: &Arc<Mutex<PgEmbed>>) -> Result<(), AppError> {
            let pg_embed = pg_embed.clone();
            tokio_test::block_on(async { pg_embed.lock().unwrap().start_db().await }).map_err(
                |err: PgEmbedError| {
                    AppError::General(format!("Error starting embedded Postgres: err={:?}", &err))
                },
            )
        }

        fn stop_embedded_db(pg_embed: &Arc<Mutex<PgEmbed>>) -> Result<(), AppError> {
            let pg_embed = pg_embed.clone();
            tokio_test::block_on(async { pg_embed.lock().unwrap().stop_db().await }).map_err(
                |err: PgEmbedError| {
                    AppError::General(format!("Error stopping embedded Postgres: err={:?}", &err))
                },
            )
        }

        pub fn execute_sql(
            &self,
            db_conn: &mut PgConnection,
            sqls: &[&str],
        ) -> Result<(), AppError> {
            for sql in sqls {
                diesel::sql_query(*sql).execute(db_conn).map_err(|err| {
                    AppError::General(format!("Error executing SQL: sql={}, err={:?}", *sql, &err))
                })?;
            }

            Ok(())
        }

        fn acquire_embedded_db(
            &mut self,
            database_dir: PathBuf,
            persistent: bool,
        ) -> Result<Arc<Mutex<PgEmbed>>, AppError> {
            // Return existing DB (if exists)
            if let Some(pg_embed) = self.databases.get(&database_dir) {
                Self::start_embedded_db(pg_embed)?;
                return Ok(pg_embed.clone());
            }

            // Set up new DB
            if database_dir.exists() {
                fs::remove_dir_all(&database_dir).map_err(|err| {
                    AppError::General(format!(
                        "Error removing embedded Postgres DB directory: path={:?}, err={:?}",
                        &database_dir, &err
                    ))
                })?;
            }
            fs::create_dir_all(&database_dir).map_err(|err| {
                AppError::General(format!(
                    "Error creating embedded Postgres DB directory: path={:?}, err={:?}",
                    &database_dir, &err
                ))
            })?;

            let database_dir_copy = database_dir.clone();
            let server_port = self.next_port;
            let pg_embed = tokio_test::block_on(async {
                // Set up new embedded DB
                let pg_settings = PgSettings {
                    database_dir: database_dir_copy,
                    port: server_port,
                    user: DB_USERNAME.to_string(),
                    password: DB_PASSWORD.to_string(),
                    auth_method: PgAuthMethod::Plain,
                    persistent,
                    timeout: Some(Duration::from_secs(10)),
                    migration_dir: None,
                };
                let fetch_settings = PgFetchSettings {
                    version: PG_V15,
                    ..Default::default()
                };
                let mut pg_embed = PgEmbed::new(pg_settings, fetch_settings).await?;
                pg_embed.setup().await?;

                // Startup DB
                pg_embed.start_db().await?;
                pg_embed.create_database(DB_NAME).await?;

                Ok(Arc::new(Mutex::new(pg_embed)))
            })
            .map_err(|err: PgEmbedError| {
                AppError::General(format!(
                    "Error setting up embedded Postgres: dir={:?}, err={:?}",
                    &database_dir, &err
                ))
            })?;
            // Cache db (for potential reuse)
            self.databases.insert(database_dir, pg_embed.clone());
            self.next_port += 1;

            Ok(pg_embed)
        }
    }

    pub struct EmbeddedDbTransaction {
        pub database_dir: PathBuf,
        pub pg_embed: Arc<Mutex<PgEmbed>>,
    }

    impl Drop for EmbeddedDbTransaction {
        fn drop(&mut self) {
            if let Err(err) = EmbeddedDb::stop_embedded_db(&self.pg_embed) {
                error!("Error tearing down embedded Postgres DB: err={:?}", &err);
            }
            _ = DB.lock().unwrap().databases.remove(&self.database_dir);
        }
    }
}
