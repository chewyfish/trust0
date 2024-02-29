use diesel::pg::PgConnection;
use diesel::prelude::*;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use trust0_common::error::AppError;

pub static INSTANCE: Lazy<Arc<Mutex<PostgresDbConn>>> = Lazy::new(|| {
    Arc::new(Mutex::new(PostgresDbConn {
        connections: HashMap::new(),
    }))
});

pub struct PostgresDbConn {
    connections: HashMap<String, Arc<Mutex<PgConnection>>>,
}

impl PostgresDbConn {
    /// Connect to Postgres DB
    ///
    /// # Arguments
    ///
    /// * `database_url` - Database connection URL
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`PgConnection`] object for the connection (wrapped with Arc<Mutex<>>).
    ///
    pub fn establish_connection(
        &mut self,
        database_url: &str,
    ) -> Result<Arc<Mutex<PgConnection>>, AppError> {
        if let Some(connection) = self.connections.get(database_url) {
            return Ok(connection.clone());
        }

        let connection = Arc::new(Mutex::new(PgConnection::establish(database_url).map_err(
            |err| {
                AppError::GenWithMsgAndErr(
                    format!(
                        "Error establishing postgres connection: url={}",
                        database_url
                    ),
                    Box::new(err),
                )
            },
        )?));

        self.connections
            .insert(database_url.to_string(), connection.clone());

        Ok(connection)
    }
}
