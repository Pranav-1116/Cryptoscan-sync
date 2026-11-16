-- Simulated core banking ledger. Fictional customers only — safe to ship.

CREATE TABLE branches (
    branch_code  TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    city         TEXT NOT NULL,
    swift_bic    TEXT NOT NULL
);

CREATE TABLE customers (
    customer_id  TEXT PRIMARY KEY,
    full_name    TEXT NOT NULL,
    segment      TEXT NOT NULL,          -- RETAIL | SME | CORPORATE
    kyc_tier     TEXT NOT NULL,          -- FULL | SIMPLIFIED
    branch_code  TEXT REFERENCES branches(branch_code)
);

CREATE TABLE accounts (
    account_no   TEXT PRIMARY KEY,       -- fictional IBAN-shaped ids
    customer_id  TEXT REFERENCES customers(customer_id),
    product      TEXT NOT NULL,          -- CURRENT | SAVINGS | FIXED_DEPOSIT
    currency     TEXT NOT NULL,
    balance      NUMERIC(14,2) NOT NULL,
    opened_on    DATE NOT NULL
);

CREATE TABLE cards (
    card_id      TEXT PRIMARY KEY,
    account_no   TEXT REFERENCES accounts(account_no),
    pan_token    TEXT NOT NULL,          -- tokenized PAN stand-in, NOT a real PAN
    scheme       TEXT NOT NULL,          -- VISA | MASTERCARD | RUPAY
    expires_on   DATE NOT NULL
);

INSERT INTO branches VALUES
  ('BR-001', 'Anna Salai Head Office', 'Chennai',   'MRDILNBB001'),
  ('BR-002', 'Marina Branch',          'Chennai',   'MRDILNBB002'),
  ('BR-003', 'Fort Branch',            'Mumbai',    'MRDIINBB003'),
  ('BR-004', 'Connaught Place Branch', 'New Delhi', 'MRDIINBB004');

INSERT INTO customers VALUES
  ('CU-1001', 'Aarav Krishnan',   'RETAIL',    'FULL', 'BR-001'),
  ('CU-1002', 'Diya Ramanathan',  'SME',       'FULL', 'BR-001'),
  ('CU-1003', 'Imran Sheikh',     'RETAIL',    'FULL', 'BR-002'),
  ('CU-1004', 'Kaveri Nair',      'CORPORATE', 'FULL', 'BR-003'),
  ('CU-1005', 'Rohan Iyer',       'SME',       'FULL', 'BR-004');

INSERT INTO accounts VALUES
  ('INMRDI000012345678901', 'CU-1001', 'SAVINGS',       'INR', 284150.75, '2019-03-14'),
  ('INMRDI000012345678902', 'CU-1002', 'CURRENT',       'INR', 1932000.00, '2021-07-02'),
  ('INMRDI000012345678903', 'CU-1003', 'SAVINGS',       'INR', 96780.10, '2022-11-21'),
  ('INMRDI000012345678904', 'CU-1004', 'CURRENT',       'USD', 41250.00, '2018-01-09'),
  ('INMRDI000012345678905', 'CU-1005', 'FIXED_DEPOSIT', 'INR', 500000.00, '2024-02-28');

INSERT INTO cards VALUES
  ('CD-9001', 'INMRDI000012345678901', 'tok_live_9f1aa2c4b1', 'VISA',       '2028-06-30'),
  ('CD-9002', 'INMRDI000012345678902', 'tok_live_77d3e91a02', 'RUPAY',      '2027-01-31'),
  ('CD-9003', 'INMRDI000012345678904', 'tok_live_51c0bb77de', 'MASTERCARD', '2026-12-31');
