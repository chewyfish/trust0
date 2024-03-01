use diesel::mysql::MysqlConnection;
use diesel::prelude::*;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use trust0_common::error::AppError;

pub static INSTANCE: Lazy<Arc<Mutex<MysqlDbConn>>> = Lazy::new(|| {
    Arc::new(Mutex::new(MysqlDbConn {
        connections: HashMap::new(),
    }))
});

pub struct MysqlDbConn {
    connections: HashMap<String, Arc<Mutex<MysqlConnection>>>,
}

impl MysqlDbConn {
    /// Connect to Mysql DB
    ///
    /// # Arguments
    ///
    /// * `database_url` - Database connection URL
    ///
    /// # Returns
    ///
    /// A [`Result`] containing the [`MysqlConnection`] object for the connection (wrapped with Arc<Mutex<>>).
    ///
    pub fn establish_connection(
        &mut self,
        database_url: &str,
    ) -> Result<Arc<Mutex<MysqlConnection>>, AppError> {
        if let Some(connection) = self.connections.get(database_url) {
            return Ok(connection.clone());
        }

        let connection = Arc::new(Mutex::new(
            MysqlConnection::establish(database_url).map_err(|err| {
                AppError::GenWithMsgAndErr(
                    format!("Error establishing mysql connection: url={}", database_url),
                    Box::new(err),
                )
            })?,
        ));

        self.connections
            .insert(database_url.to_string(), connection.clone());

        Ok(connection)
    }
}
