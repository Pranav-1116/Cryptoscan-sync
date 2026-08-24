-- Enable required PostgreSQL extensions

-- UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Cryptographic functions (for additional integrity verification)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- For full-text search (future use)
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Connect to test database and enable same extensions
\c cryptoscan_test
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";