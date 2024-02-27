CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    status VARCHAR(20) CHECK (users.status IN ('Active', 'Inactive')) NOT NULL,
    user_name VARCHAR(50) NULL,
    password VARCHAR(255) NULL
);
