use std::collections::HashMap;
use std::fs;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use trust0_common::error::AppError;
use trust0_common::model::user::User;
use crate::repository::user_repo::UserRepository;

pub struct InMemUserRepo {
    users: RwLock<HashMap<u64, User>>,
}

impl InMemUserRepo {

    /// Creates a new in-memory user store.
    pub fn new() -> InMemUserRepo {
        InMemUserRepo {
            users: RwLock::new(HashMap::new())
        }
    }

    /// Load/parse users from given JSON file path
    pub fn load_from_file(&mut self, file_path: &str) -> Result<(), AppError> {

        let data = fs::read_to_string(file_path).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed to read file: path={}", file_path), Box::new(err)))?;
        let users: Vec<User> = serde_json::from_str(&data).map_err(|err|
            AppError::GenWithMsgAndErr(format!("Failed to parse JSON: path={}", file_path), Box::new(err)))?;

        for user in users.iter().as_ref() {
            self.put(user.clone())?;
        }

        Ok(())
    }

    fn access_data_for_write(&self) -> Result<RwLockWriteGuard<HashMap<u64, User>>, AppError> {
        self.users.write().map_err(|err|
            AppError::General(format!("Failed to access write lock to DB: err={}", err)))
    }

    fn access_data_for_read(&self) -> Result<RwLockReadGuard<HashMap<u64, User>>, AppError> {
        self.users.read().map_err(|err|
            AppError::General(format!("Failed to access read lock to DB: err={}", err)))
    }
}

impl UserRepository for InMemUserRepo {

    fn put(&self, user: User) -> Result<Option<User>, AppError> {
        let mut data = self.access_data_for_write()?;
        Ok(data.insert(user.user_id, user.clone()))
    }

    fn get(&self, user_id: u64) -> Result<Option<User>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data.get(&user_id).map(|user| user.clone()))
    }

    fn get_all(&self) -> Result<Vec<User>, AppError> {
        let data = self.access_data_for_read()?;
        Ok(data.iter()
            .map(|entry| entry.1)
            .cloned()
            .collect::<Vec<User>>())
    }

    fn delete(&self, user_id: u64) -> Result<Option<User>, AppError> {
        let mut data = self.access_data_for_write()?;
        Ok(data.remove(&user_id))
    }
}

/*
#[cfg(test)]
mod tests {
    use super::*;
    use test_context::{test_context, AsyncTestContext};

    #[test_context(Context)]
    #[tokio::test]
    async fn create_order_adds_order_to_store(ctx: &mut Context) {
        assert_eq!(
            ctx.in_mem_store
                .list_orders(ctx.user_id_1)
                .await
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            ctx.in_mem_store
                .list_orders(ctx.user_id_2)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[test_context(Context)]
    #[tokio::test]
    async fn get_order_retrieves_existing_order(ctx: &mut Context) {
        if let Ok(stored_order) = ctx.in_mem_store.get_order(ctx.order_1_user_1.id).await {
            assert_eq!(stored_order, ctx.order_1_user_1);
        } else {
            panic!("Order not found after being created");
        }
    }

    #[test_context(Context)]
    #[tokio::test]
    async fn get_order_returns_error_for_non_existing_order(ctx: &mut Context) {
        let order_id = Uuid::new_v4();
        if let Err(OrderStoreError::OrderNotFound(not_found_id)) =
            ctx.in_mem_store.get_order(order_id).await
        {
            assert_eq!(order_id, not_found_id);
        } else {
            panic!("Unexpected order found");
        }
    }

    #[tokio::test]
    async fn item_cannot_be_added_to_non_existing_order() {
        let in_mem_store = InMemOrderStore::new();
        assert!(in_mem_store
            .add_item(Uuid::new_v4(), Uuid::new_v4(), 1)
            .await
            .is_err());
    }

    #[test_context(Context)]
    #[tokio::test]
    async fn order_contains_added_item(ctx: &mut Context) {
        let product_id = Uuid::new_v4();
        let quantity = 42;
        if let Ok(()) = ctx
            .in_mem_store
            .add_item(ctx.order_1_user_1.id, product_id, quantity)
            .await
        {
            if let Ok(stored_order) = ctx.in_mem_store.get_order(ctx.order_1_user_1.id).await {
                assert_eq!(stored_order.items.len(), 1);
                assert_eq!(stored_order.items[0].product_id, product_id);
                assert_eq!(stored_order.items[0].quantity, quantity);
            } else {
                panic!("Order not found after being created");
            }
        } else {
            panic!("Failed to add item to order");
        }
    }

    #[test_context(Context)]
    #[tokio::test]
    async fn order_contains_added_items(ctx: &mut Context) {
        let product_id_0 = Uuid::new_v4();
        let quantity_0 = 42;
        let product_id_1 = Uuid::new_v4();
        let quantity_1 = 7;
        if let (Ok(()), Ok(())) = (
            ctx.in_mem_store
                .add_item(ctx.order_1_user_1.id, product_id_0, quantity_0)
                .await,
            ctx.in_mem_store
                .add_item(ctx.order_1_user_1.id, product_id_1, quantity_1)
                .await,
        ) {
            if let Ok(stored_order) = ctx.in_mem_store.get_order(ctx.order_1_user_1.id).await {
                assert_eq!(stored_order.items.len(), 2);
                assert_eq!(stored_order.items[0].product_id, product_id_0);
                assert_eq!(stored_order.items[0].quantity, quantity_0);
                assert_eq!(stored_order.items[1].product_id, product_id_1);
                assert_eq!(stored_order.items[1].quantity, quantity_1);
            } else {
                panic!("Order not found after being created");
            }
        } else {
            panic!("Failed to add items to order");
        }
    }

    #[tokio::test]
    async fn item_cannot_be_deleted_from_non_existing_order() {
        let in_mem_store = InMemOrderStore::new();
        assert!(in_mem_store.delete_item(Uuid::new_v4(), 1).await.is_err());
    }

    #[test_context(Context)]
    #[tokio::test]
    async fn attempt_to_delete_non_existent_item_from_order_returns_error(ctx: &mut Context) {
        let product_id_0 = Uuid::new_v4();
        let quantity_0 = 42;
        let product_id_1 = Uuid::new_v4();
        let quantity_1 = 7;
        if let (Ok(()), Ok(())) = (
            ctx.in_mem_store
                .add_item(ctx.order_1_user_1.id, product_id_0, quantity_0)
                .await,
            ctx.in_mem_store
                .add_item(ctx.order_1_user_1.id, product_id_1, quantity_1)
                .await,
        ) {
            if let Err(OrderStoreError::ItemIndexOutOfBounds(index)) =
                ctx.in_mem_store.delete_item(ctx.order_1_user_1.id, 2).await
            {
                assert_eq!(index, 2);
            } else {
                panic!("Deleting non-existent item must produce error");
            }
        } else {
            panic!("Failed to add items to order");
        }
    }

    #[test_context(Context)]
    #[tokio::test]
    async fn last_item_can_be_deleted_from_order(ctx: &mut Context) {
        let product_id_0 = Uuid::new_v4();
        let quantity_0 = 42;
        let product_id_1 = Uuid::new_v4();
        let quantity_1 = 7;
        if let (Ok(()), Ok(())) = (
            ctx.in_mem_store
                .add_item(ctx.order_1_user_1.id, product_id_0, quantity_0)
                .await,
            ctx.in_mem_store
                .add_item(ctx.order_1_user_1.id, product_id_1, quantity_1)
                .await,
        ) {
            if let Ok(()) = ctx.in_mem_store.delete_item(ctx.order_1_user_1.id, 1).await {
                if let Ok(stored_order) = ctx.in_mem_store.get_order(ctx.order_1_user_1.id).await {
                    assert_eq!(stored_order.items.len(), 1);
                    assert_eq!(stored_order.items[0].product_id, product_id_0);
                    assert_eq!(stored_order.items[0].quantity, quantity_0);
                } else {
                    panic!("Order not found after being created");
                }
            } else {
                panic!("Failed to delete item from order");
            }
        } else {
            panic!("Failed to add items to order");
        }
    }

    #[test_context(Context)]
    #[tokio::test]
    async fn first_item_can_be_deleted_from_order(ctx: &mut Context) {
        let product_id_0 = Uuid::new_v4();
        let quantity_0 = 42;
        let product_id_1 = Uuid::new_v4();
        let quantity_1 = 7;
        if let (Ok(()), Ok(())) = (
            ctx.in_mem_store
                .add_item(ctx.order_1_user_1.id, product_id_0, quantity_0)
                .await,
            ctx.in_mem_store
                .add_item(ctx.order_1_user_1.id, product_id_1, quantity_1)
                .await,
        ) {
            if let Ok(()) = ctx.in_mem_store.delete_item(ctx.order_1_user_1.id, 0).await {
                if let Ok(stored_order) = ctx.in_mem_store.get_order(ctx.order_1_user_1.id).await {
                    assert_eq!(stored_order.items.len(), 1);
                    assert_eq!(stored_order.items[0].product_id, product_id_1);
                    assert_eq!(stored_order.items[0].quantity, quantity_1);
                } else {
                    panic!("Order not found after being created");
                }
            } else {
                panic!("Failed to delete item from order");
            }
        } else {
            panic!("Failed to add items to order");
        }
    }

    struct Context {
        user_id_1: Uuid,
        user_id_2: Uuid,
        in_mem_store: InMemOrderStore,
        order_1_user_1: Order,
    }

    #[async_trait::async_trait]
    impl AsyncTestContext for Context {
        async fn setup() -> Context {
            let user_id_1 = Uuid::new_v4();
            let in_mem_store = InMemOrderStore::new();
            let order = in_mem_store.create_order(user_id_1).await;
            let ctx = Context {
                user_id_1,
                user_id_2: Uuid::new_v4(),
                in_mem_store,
                order_1_user_1: order.unwrap(),
            };
            _ = ctx.in_mem_store.create_order(ctx.user_id_2).await;
            _ = ctx.in_mem_store.create_order(ctx.user_id_1).await;

            ctx
        }
        async fn teardown(self) {}
    }
}
*/