CREATE TABLE service_accesses (
    entity_type VARCHAR(20) CHECK (service_accesses.entity_type IN ('Role', 'User')) NOT NULL,
    entity_id BIGINT NOT NULL,
    service_id BIGINT NOT NULL,
    PRIMARY KEY (entity_type, entity_id, service_id),
    FOREIGN KEY(service_id)
        REFERENCES services(id)
        ON DELETE CASCADE
);