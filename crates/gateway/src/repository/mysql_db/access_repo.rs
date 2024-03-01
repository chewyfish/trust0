use crate::repository::access_repo::AccessRepository;
use crate::repository::diesel_orm::access_repo::DieselServiceAccessRepo;
use crate::repository::mysql_db::db_conn;
use trust0_common::error::AppError;
use trust0_common::model;

/// ServiceAccess Repository
pub struct MysqlServiceAccessRepo {
    /// Access repository ORM delegate
    access_repo_delegate: Option<Box<dyn AccessRepository>>,
}

impl MysqlServiceAccessRepo {
    /// Creates a new access repository.
    ///
    /// # Returns
    ///
    /// A newly constructed [`MysqlServiceAccessRepo`] object.
    ///
    pub fn new() -> MysqlServiceAccessRepo {
        MysqlServiceAccessRepo {
            access_repo_delegate: None,
        }
    }
}

impl AccessRepository for MysqlServiceAccessRepo {
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError> {
        self.access_repo_delegate = Some(Box::new(DieselServiceAccessRepo::new(
            &db_conn::INSTANCE
                .lock()
                .unwrap()
                .establish_connection(connect_spec)?,
        )));
        Ok(())
    }

    fn put(
        &self,
        access: model::access::ServiceAccess,
    ) -> Result<model::access::ServiceAccess, AppError> {
        self.access_repo_delegate.as_ref().unwrap().put(access)
    }

    fn get(
        &self,
        service_id: i64,
        entity_type: &model::access::EntityType,
        entity_id: i64,
    ) -> Result<Option<model::access::ServiceAccess>, AppError> {
        self.access_repo_delegate
            .as_ref()
            .unwrap()
            .get(service_id, entity_type, entity_id)
    }

    fn get_for_user(
        &self,
        service_id: i64,
        user: &model::user::User,
    ) -> Result<Option<model::access::ServiceAccess>, AppError> {
        self.access_repo_delegate
            .as_ref()
            .unwrap()
            .get_for_user(service_id, user)
    }

    fn get_all_for_user(
        &self,
        user: &model::user::User,
    ) -> Result<Vec<model::access::ServiceAccess>, AppError> {
        self.access_repo_delegate
            .as_ref()
            .unwrap()
            .get_all_for_user(user)
    }

    fn delete(
        &self,
        service_id: i64,
        entity_type: &model::access::EntityType,
        entity_id: i64,
    ) -> Result<Option<model::access::ServiceAccess>, AppError> {
        self.access_repo_delegate
            .as_ref()
            .unwrap()
            .delete(service_id, entity_type, entity_id)
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::access_repo::tests::MockAccessRepo;
    use mockall::predicate;

    #[test]
    fn pgdbaccessrepo_connect_to_datasource() {
        let mut access_repo = MysqlServiceAccessRepo::new();
        if let Ok(()) = access_repo.connect_to_datasource("INVALID") {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn pgdbaccessrepo_put() {
        let expected_access = model::access::ServiceAccess {
            service_id: 200,
            entity_type: model::access::EntityType::User,
            entity_id: 100,
        };
        let expected_access_copy = expected_access.clone();
        let mut access_repo_delegate = MockAccessRepo::new();
        access_repo_delegate
            .expect_put()
            .with(predicate::eq(expected_access.clone()))
            .times(1)
            .return_once(|_| Ok(expected_access_copy));
        let access_repo = MysqlServiceAccessRepo {
            access_repo_delegate: Some(Box::new(access_repo_delegate)),
        };

        if let Err(err) = access_repo.put(expected_access) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn pgdbaccessrepo_get() {
        let expected_access = model::access::ServiceAccess {
            service_id: 200,
            entity_type: model::access::EntityType::User,
            entity_id: 100,
        };
        let expected_access_copy = expected_access.clone();
        let mut access_repo_delegate = MockAccessRepo::new();
        access_repo_delegate
            .expect_get()
            .with(
                predicate::eq(expected_access.service_id),
                predicate::eq(expected_access.entity_type.clone()),
                predicate::eq(expected_access.entity_id),
            )
            .times(1)
            .return_once(|_, _, _| Ok(Some(expected_access_copy)));
        let access_repo = MysqlServiceAccessRepo {
            access_repo_delegate: Some(Box::new(access_repo_delegate)),
        };

        if let Err(err) = access_repo.get(
            expected_access.service_id,
            &expected_access.entity_type.clone(),
            expected_access.entity_id,
        ) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn pgdbaccessrepo_get_for_user() {
        let expected_access = model::access::ServiceAccess {
            service_id: 200,
            entity_type: model::access::EntityType::User,
            entity_id: 100,
        };
        let expected_access_copy = expected_access.clone();
        let expected_user = model::user::User {
            user_id: 100,
            name: "User100".to_string(),
            status: model::user::Status::Active,
            roles: vec![50, 51],
            user_name: Some("uname100".to_string()),
            password: Some("pass100".to_string()),
        };
        let mut access_repo_delegate = MockAccessRepo::new();
        access_repo_delegate
            .expect_get_for_user()
            .with(
                predicate::eq(expected_access.service_id),
                predicate::eq(expected_user.clone()),
            )
            .times(1)
            .return_once(|_, _| Ok(Some(expected_access_copy)));
        let access_repo = MysqlServiceAccessRepo {
            access_repo_delegate: Some(Box::new(access_repo_delegate)),
        };

        if let Err(err) = access_repo.get_for_user(expected_access.service_id, &expected_user) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn pgdbaccessrepo_get_all_for_user() {
        let expected_user = model::user::User {
            user_id: 100,
            name: "User100".to_string(),
            status: model::user::Status::Active,
            roles: vec![50, 51],
            user_name: Some("uname100".to_string()),
            password: Some("pass100".to_string()),
        };
        let mut access_repo_delegate = MockAccessRepo::new();
        access_repo_delegate
            .expect_get_all_for_user()
            .with(predicate::eq(expected_user.clone()))
            .times(1)
            .return_once(|_| Ok(Vec::new()));
        let access_repo = MysqlServiceAccessRepo {
            access_repo_delegate: Some(Box::new(access_repo_delegate)),
        };

        if let Err(err) = access_repo.get_all_for_user(&expected_user) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn pgdbaccessrepo_delete() {
        let expected_access = model::access::ServiceAccess {
            service_id: 200,
            entity_type: model::access::EntityType::User,
            entity_id: 100,
        };
        let expected_access_copy = expected_access.clone();
        let mut access_repo_delegate = MockAccessRepo::new();
        access_repo_delegate
            .expect_delete()
            .with(
                predicate::eq(expected_access.service_id),
                predicate::eq(expected_access.entity_type.clone()),
                predicate::eq(expected_access.entity_id),
            )
            .times(1)
            .return_once(|_, _, _| Ok(Some(expected_access_copy)));
        let access_repo = MysqlServiceAccessRepo {
            access_repo_delegate: Some(Box::new(access_repo_delegate)),
        };

        if let Err(err) = access_repo.delete(
            expected_access.service_id,
            &expected_access.entity_type,
            expected_access.entity_id,
        ) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }
}
