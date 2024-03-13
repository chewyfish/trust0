ALTER TABLE roles ADD COLUMN created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE roles ADD COLUMN updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE services ADD COLUMN created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE services ADD COLUMN updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE service_accesses ADD COLUMN created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE service_accesses ADD COLUMN updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE users ADD COLUMN created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE users ADD COLUMN updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE user_roles ADD COLUMN created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE user_roles ADD COLUMN updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP;

SELECT diesel_manage_updated_at('roles');
SELECT diesel_manage_updated_at('services');
SELECT diesel_manage_updated_at('service_accesses');
SELECT diesel_manage_updated_at('users');
SELECT diesel_manage_updated_at('user_roles');