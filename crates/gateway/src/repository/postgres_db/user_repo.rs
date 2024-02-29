use crate::repository::diesel_orm::user_repo::DieselUserRepo;
use crate::repository::postgres_db::db_conn;
use crate::repository::user_repo::UserRepository;
use trust0_common::error::AppError;
use trust0_common::model::user::User;

/// User Repository
pub struct PostgresUserRepo {
    /// User repository ORM delegate
    user_repo_delegate: Option<Box<dyn UserRepository>>,
}

impl PostgresUserRepo {
    /// Creates a new user repository.
    ///
    /// # Returns
    ///
    /// A newly constructed [`PostgresUserRepo`] object.
    ///
    pub fn new() -> PostgresUserRepo {
        PostgresUserRepo {
            user_repo_delegate: None,
        }
    }
}

impl UserRepository for PostgresUserRepo {
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError> {
        self.user_repo_delegate = Some(Box::new(DieselUserRepo::new(
            &db_conn::INSTANCE
                .lock()
                .unwrap()
                .establish_connection(connect_spec)?,
        )));
        Ok(())
    }

    fn put(&self, user: User) -> Result<User, AppError> {
        self.user_repo_delegate.as_ref().unwrap().put(user)
    }

    fn get(&self, user_id: i64) -> Result<Option<User>, AppError> {
        self.user_repo_delegate.as_ref().unwrap().get(user_id)
    }

    fn delete(&self, user_id: i64) -> Result<Option<User>, AppError> {
        self.user_repo_delegate.as_ref().unwrap().delete(user_id)
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::role_repo::tests::MockRoleRepo;
    use crate::repository::user_repo::tests::MockUserRepo;
    use mockall::predicate;
    use trust0_common::model::user::Status;

    #[test]
    fn pgdbuserrepo_connect_to_datasource() {
        let mut user_repo = PostgresUserRepo::new();
        if let Ok(()) = user_repo.connect_to_datasource("INVALID") {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn pgdbuserrepo_put() {
        let expected_user = User {
            user_id: 100,
            name: "User100".to_string(),
            status: Status::Active,
            roles: vec![50],
            user_name: Some("uname100".to_string()),
            password: Some("pass100".to_string()),
        };
        let expected_user_copy = expected_user.clone();
        let mut user_repo_delegate = MockUserRepo::new();
        user_repo_delegate
            .expect_put()
            .with(predicate::eq(expected_user.clone()))
            .times(1)
            .return_once(|_| Ok(expected_user_copy));
        let user_repo = PostgresUserRepo {
            user_repo_delegate: Some(Box::new(user_repo_delegate)),
        };

        if let Err(err) = user_repo.put(expected_user) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn pgdbuserrepo_get() {
        let expected_user = User {
            user_id: 100,
            name: "User100".to_string(),
            status: Status::Active,
            roles: vec![50],
            user_name: Some("uname100".to_string()),
            password: Some("pass100".to_string()),
        };
        let expected_user_copy = expected_user.clone();
        let mut user_repo_delegate = MockUserRepo::new();
        user_repo_delegate
            .expect_get()
            .with(predicate::eq(expected_user.user_id))
            .times(1)
            .return_once(|_| Ok(Some(expected_user_copy)));
        let user_repo = PostgresUserRepo {
            user_repo_delegate: Some(Box::new(user_repo_delegate)),
        };

        if let Err(err) = user_repo.get(expected_user.user_id) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn pgdbuserrepo_delete() {
        let expected_user = User {
            user_id: 100,
            name: "User100".to_string(),
            status: Status::Active,
            roles: vec![50],
            user_name: Some("uname100".to_string()),
            password: Some("pass100".to_string()),
        };
        let expected_user_copy = expected_user.clone();
        let mut user_repo_delegate = MockUserRepo::new();
        user_repo_delegate
            .expect_delete()
            .with(predicate::eq(expected_user.user_id))
            .times(1)
            .return_once(|_| Ok(Some(expected_user_copy)));
        let user_repo = PostgresUserRepo {
            user_repo_delegate: Some(Box::new(user_repo_delegate)),
        };

        if let Err(err) = user_repo.delete(expected_user.user_id) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }
}
