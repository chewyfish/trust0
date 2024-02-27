CREATE TABLE services (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    transport VARCHAR(20) CHECK (services.transport IN ('TCP', 'UDP')) NOT NULL,
    host VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL
);
