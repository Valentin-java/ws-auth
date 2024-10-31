INSERT INTO ws01_customer (id, is_enabled, user_name, password)
VALUES (2, true, 'ws-order', '$2a$10$eyBo6KDuoB9ty6cbzaSA8O4lvY4ddlUx2vt/vrXa1zHNzL.rW66ya');

INSERT INTO ws01_customer_role (id, customer_id, role_id)
VALUES (2, 2, 1);

ALTER SEQUENCE ws01_customer_id_seq RESTART WITH 3;
ALTER SEQUENCE ws01_customer_role_id_seq RESTART WITH 3;