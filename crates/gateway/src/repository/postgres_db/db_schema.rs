// @generated automatically by Diesel CLI.

diesel::table! {
    roles (id) {
        id -> Int8,
        #[max_length = 50]
        name -> Varchar,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    service_accesses (entity_type, entity_id, service_id) {
        #[max_length = 20]
        entity_type -> Varchar,
        entity_id -> Int8,
        service_id -> Int8,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    services (id) {
        id -> Int8,
        #[max_length = 50]
        name -> Varchar,
        #[max_length = 20]
        transport -> Varchar,
        #[max_length = 255]
        host -> Varchar,
        port -> Int4,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    user_roles (user_id, role_id) {
        user_id -> Int8,
        role_id -> Int8,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    users (id) {
        id -> Int8,
        #[max_length = 50]
        name -> Varchar,
        #[max_length = 20]
        status -> Varchar,
        #[max_length = 50]
        user_name -> Nullable<Varchar>,
        #[max_length = 255]
        password -> Nullable<Varchar>,
        created_at -> Nullable<Timestamp>,
        updated_at -> Nullable<Timestamp>,
    }
}

diesel::joinable!(service_accesses -> services (service_id));
diesel::joinable!(user_roles -> roles (role_id));
diesel::joinable!(user_roles -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(roles, service_accesses, services, user_roles, users,);
