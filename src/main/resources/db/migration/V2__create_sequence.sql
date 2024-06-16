CREATE TABLE IF NOT EXISTS ws01_customer (
                               id bigserial NOT NULL,
                               is_enabled bool NOT NULL,
                               user_name varchar(255) NOT NULL,
                               password varchar(255) NOT NULL,
                               CONSTRAINT ws01_customer_pkey PRIMARY KEY (id),
                               CONSTRAINT uk_igkgpat0xlasvhcwd44gs2e5s UNIQUE (user_name)
);

CREATE TABLE IF NOT EXISTS ws01_role (
                           id bigserial NOT NULL,
                           "role" varchar NULL,
                           CONSTRAINT ws01_role_pk PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS ws01_customer_role (
                                    id bigserial NOT NULL,
                                    customer_id int8 NULL,
                                    role_id int8 NULL,
                                    CONSTRAINT customer_role_pk PRIMARY KEY (id),
                                    CONSTRAINT ws01_customer_role_un UNIQUE (customer_id, role_id),
                                    CONSTRAINT ws01_customer_role_fk FOREIGN KEY (customer_id) REFERENCES ws01_customer(id) ON DELETE CASCADE,
                                    CONSTRAINT role_fk FOREIGN KEY (role_id) REFERENCES ws01_role(id)
);

INSERT INTO ws01_role
(id, "role")
VALUES(1, 'ADMIN');
INSERT INTO ws01_role
(id, "role")
VALUES(2, 'USER');