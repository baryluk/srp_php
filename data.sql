SHOW TABLES;

CREATE TABLE dane (
identity VARCHAR(256) PRIMARY KEY,
hash VARCHAR(32),
s_hex VARCHAR(256),
N_base36 VARCHAR(1024),
g_base36 VARCHAR(1024),
v_base36 VARCHAR(1024)
);

describe dane;

select * from dane;
