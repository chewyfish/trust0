INSERT INTO roles (id, name) VALUES (50, 'Role50');
INSERT INTO roles (id, name) VALUES (51, 'Role51');
INSERT INTO services (id, name, transport, host, port) VALUES (200, 'Service200', 'TCP', 'localhost', 8200);
INSERT INTO services (id, name, transport, host, port) VALUES (201, 'Service201', 'UDP', 'localhost', 8201);
INSERT INTO services (id, name, transport, host, port) VALUES (202, 'Service202', 'UDP', 'localhost', 8202);
INSERT INTO services (id, name, transport, host, port) VALUES (203, 'chat-tcp', 'TCP', 'localhost', 8500);
INSERT INTO services (id, name, transport, host, port) VALUES (204, 'echo-udp', 'UDP', 'localhost', 8600);
INSERT INTO users (id, name, status, user_name, password) VALUES (100, 'User100', 'Active', 'user1', '30nasGxfW9JzThsjsGSutayNhTgRNVxkv_Qm6ZUlW2U=');
INSERT INTO users (id, name, status, user_name, password) VALUES (101, 'User101', 'Active', NULL, NULL);
INSERT INTO user_roles (user_id, role_id) VALUES (100, 50);
INSERT INTO user_roles (user_id, role_id) VALUES (100, 51);
INSERT INTO service_accesses (service_id, entity_type, entity_id) VALUES (200, 'User', 100);
INSERT INTO service_accesses (service_id, entity_type, entity_id) VALUES (203, 'Role', 50);
INSERT INTO service_accesses (service_id, entity_type, entity_id) VALUES (204, 'Role', 50);
INSERT INTO service_accesses (service_id, entity_type, entity_id) VALUES (202, 'User', 101);
INSERT INTO service_accesses (service_id, entity_type, entity_id) VALUES (203, 'User', 101);
   
