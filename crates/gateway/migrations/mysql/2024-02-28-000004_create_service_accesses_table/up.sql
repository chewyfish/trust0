CREATE TABLE service_accesses (
    entity_type VARCHAR(20) NOT NULL CHECK (entity_type IN ('Role', 'User')),
    entity_id BIGINT NOT NULL,
    service_id BIGINT NOT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (entity_type, entity_id, service_id),
    FOREIGN KEY(service_id)
        REFERENCES services(id)
        ON DELETE CASCADE
);