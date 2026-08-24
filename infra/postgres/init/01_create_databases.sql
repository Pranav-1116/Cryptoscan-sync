-- Create main application database
-- (cryptoscan DB is created by POSTGRES_DB env var)

-- Create test database
CREATE DATABASE cryptoscan_test
    WITH
    OWNER = cryptoscan
    ENCODING = 'UTF8'
    LC_COLLATE = 'en_US.utf8'
    LC_CTYPE = 'en_US.utf8'
    TEMPLATE = template0;

GRANT ALL PRIVILEGES ON DATABASE cryptoscan_test TO cryptoscan;