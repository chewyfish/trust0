use crate::repository::diesel_orm::service_repo::DieselServiceRepo;
use crate::repository::mysql_db::db_conn;
use crate::repository::service_repo::ServiceRepository;
use trust0_common::error::AppError;
use trust0_common::model::service::Service;

/// Service Repository
pub struct MysqlServiceRepo {
    /// Service repository ORM delegate
    service_repo_delegate: Option<Box<dyn ServiceRepository>>,
}

impl MysqlServiceRepo {
    /// Creates a new service repository.
    ///
    /// # Returns
    ///
    /// A newly constructed [`MysqlServiceRepo`] object.
    ///
    pub fn new() -> MysqlServiceRepo {
        MysqlServiceRepo {
            service_repo_delegate: None,
        }
    }
}

impl ServiceRepository for MysqlServiceRepo {
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError> {
        self.service_repo_delegate = Some(Box::new(DieselServiceRepo::new(
            &db_conn::INSTANCE
                .lock()
                .unwrap()
                .establish_connection(connect_spec)?,
        )));
        Ok(())
    }

    fn put(&self, service: Service) -> Result<Service, AppError> {
        self.service_repo_delegate.as_ref().unwrap().put(service)
    }

    fn get(&self, service_id: i64) -> Result<Option<Service>, AppError> {
        self.service_repo_delegate.as_ref().unwrap().get(service_id)
    }

    fn get_all(&self) -> Result<Vec<Service>, AppError> {
        self.service_repo_delegate.as_ref().unwrap().get_all()
    }

    fn delete(&self, service_id: i64) -> Result<Option<Service>, AppError> {
        self.service_repo_delegate
            .as_ref()
            .unwrap()
            .delete(service_id)
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::service_repo::tests::MockServiceRepo;
    use mockall::predicate;
    use trust0_common::model::service::Transport;

    #[test]
    fn pgdbsvcrepo_connect_to_datasource() {
        let mut service_repo = MysqlServiceRepo::new();
        if let Ok(()) = service_repo.connect_to_datasource("INVALID") {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn pgdbsvcrepo_put() {
        let expected_service = Service {
            service_id: 200,
            name: "Service200".to_string(),
            transport: Transport::TCP,
            host: "host200.com".to_string(),
            port: 8200,
        };
        let expected_service_copy = expected_service.clone();
        let mut service_repo_delegate = MockServiceRepo::new();
        service_repo_delegate
            .expect_put()
            .with(predicate::eq(expected_service.clone()))
            .times(1)
            .return_once(|_| Ok(expected_service_copy));
        let service_repo = MysqlServiceRepo {
            service_repo_delegate: Some(Box::new(service_repo_delegate)),
        };

        if let Err(err) = service_repo.put(expected_service) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn pgdbsvcrepo_get() {
        let expected_service = Service {
            service_id: 200,
            name: "Service200".to_string(),
            transport: Transport::TCP,
            host: "host200.com".to_string(),
            port: 8200,
        };
        let expected_service_copy = expected_service.clone();
        let mut service_repo_delegate = MockServiceRepo::new();
        service_repo_delegate
            .expect_get()
            .with(predicate::eq(expected_service.service_id))
            .times(1)
            .return_once(|_| Ok(Some(expected_service_copy)));
        let service_repo = MysqlServiceRepo {
            service_repo_delegate: Some(Box::new(service_repo_delegate)),
        };

        if let Err(err) = service_repo.get(expected_service.service_id) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn pgdbsvcrepo_get_all() {
        let mut service_repo_delegate = MockServiceRepo::new();
        service_repo_delegate
            .expect_get_all()
            .times(1)
            .return_once(|| Ok(Vec::new()));
        let service_repo = MysqlServiceRepo {
            service_repo_delegate: Some(Box::new(service_repo_delegate)),
        };

        if let Err(err) = service_repo.get_all() {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn pgdbsvcrepo_delete() {
        let expected_service = Service {
            service_id: 200,
            name: "Service200".to_string(),
            transport: Transport::TCP,
            host: "host200.com".to_string(),
            port: 8200,
        };
        let expected_service_copy = expected_service.clone();
        let mut service_repo_delegate = MockServiceRepo::new();
        service_repo_delegate
            .expect_delete()
            .with(predicate::eq(expected_service.service_id))
            .times(1)
            .return_once(|_| Ok(Some(expected_service_copy)));
        let service_repo = MysqlServiceRepo {
            service_repo_delegate: Some(Box::new(service_repo_delegate)),
        };

        if let Err(err) = service_repo.delete(expected_service.service_id) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }
}
