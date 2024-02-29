use crate::repository::diesel_orm::role_repo::DieselRoleRepo;
use crate::repository::postgres_db::db_conn;
use crate::repository::role_repo::RoleRepository;
use trust0_common::error::AppError;
use trust0_common::model::role::Role;

/// RBAC Role Repository
pub struct PostgresRoleRepo {
    /// Role repository ORM delegate
    role_repo_delegate: Option<Box<dyn RoleRepository>>,
}

impl PostgresRoleRepo {
    /// Creates a new role repository.
    ///
    /// # Returns
    ///
    /// A newly constructed [`PostgresRoleRepo`] object.
    ///
    pub fn new() -> PostgresRoleRepo {
        PostgresRoleRepo {
            role_repo_delegate: None,
        }
    }
}

impl RoleRepository for PostgresRoleRepo {
    fn connect_to_datasource(&mut self, connect_spec: &str) -> Result<(), AppError> {
        self.role_repo_delegate = Some(Box::new(DieselRoleRepo::new(
            &db_conn::INSTANCE
                .lock()
                .unwrap()
                .establish_connection(connect_spec)?,
        )));
        Ok(())
    }

    fn put(&self, role: Role) -> Result<Role, AppError> {
        self.role_repo_delegate.as_ref().unwrap().put(role)
    }

    fn get(&self, role_id: i64) -> Result<Option<Role>, AppError> {
        self.role_repo_delegate.as_ref().unwrap().get(role_id)
    }

    fn get_all(&self) -> Result<Vec<Role>, AppError> {
        self.role_repo_delegate.as_ref().unwrap().get_all()
    }

    fn delete(&self, role_id: i64) -> Result<Option<Role>, AppError> {
        self.role_repo_delegate.as_ref().unwrap().delete(role_id)
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::role_repo::tests::MockRoleRepo;
    use mockall::predicate;

    #[test]
    fn pgdbrolerepo_connect_to_datasource() {
        let mut role_repo = PostgresRoleRepo::new();
        if let Ok(()) = role_repo.connect_to_datasource("INVALID") {
            panic!("Unexpected successful result");
        }
    }

    #[test]
    fn pgdbrolerepo_put() {
        let expected_role = Role {
            role_id: 50,
            name: "Role50".to_string(),
        };
        let expected_role_copy = expected_role.clone();
        let mut role_repo_delegate = MockRoleRepo::new();
        role_repo_delegate
            .expect_put()
            .with(predicate::eq(expected_role.clone()))
            .times(1)
            .return_once(|_| Ok(expected_role_copy));
        let role_repo = PostgresRoleRepo {
            role_repo_delegate: Some(Box::new(role_repo_delegate)),
        };

        if let Err(err) = role_repo.put(expected_role) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn pgdbrolerepo_get() {
        let expected_role = Role {
            role_id: 50,
            name: "Role50".to_string(),
        };
        let expected_role_copy = expected_role.clone();
        let mut role_repo_delegate = MockRoleRepo::new();
        role_repo_delegate
            .expect_get()
            .with(predicate::eq(expected_role.role_id))
            .times(1)
            .return_once(|_| Ok(Some(expected_role_copy)));
        let role_repo = PostgresRoleRepo {
            role_repo_delegate: Some(Box::new(role_repo_delegate)),
        };

        if let Err(err) = role_repo.get(expected_role.role_id) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn pgdbrolerepo_get_all() {
        let mut role_repo_delegate = MockRoleRepo::new();
        role_repo_delegate
            .expect_get_all()
            .times(1)
            .return_once(|| Ok(Vec::new()));
        let role_repo = PostgresRoleRepo {
            role_repo_delegate: Some(Box::new(role_repo_delegate)),
        };

        if let Err(err) = role_repo.get_all() {
            panic!("Unexpected result: err={:?}", &err);
        }
    }

    #[test]
    fn pgdbrolerepo_delete() {
        let expected_role = Role {
            role_id: 50,
            name: "Role50".to_string(),
        };
        let expected_role_copy = expected_role.clone();
        let mut role_repo_delegate = MockRoleRepo::new();
        role_repo_delegate
            .expect_delete()
            .with(predicate::eq(expected_role.role_id))
            .times(1)
            .return_once(|_| Ok(Some(expected_role_copy)));
        let role_repo = PostgresRoleRepo {
            role_repo_delegate: Some(Box::new(role_repo_delegate)),
        };

        if let Err(err) = role_repo.delete(expected_role.role_id) {
            panic!("Unexpected result: err={:?}", &err);
        }
    }
}
