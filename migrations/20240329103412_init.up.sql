CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
  id UUID NOT NULL PRIMARY KEY DEFAULT uuid_generate_v4(),
  email VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP
    WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP
    WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX users_email ON users(email);


-- User data
CREATE TABLE IF NOT EXISTS passwords (
  id UUID NOT NULL PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID references users(id),
  name VARCHAR(255) UNIQUE NOT NULL,
  username VARCHAR(255),
  encrypted_password VARCHAR(255),
  expiration_date TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notes (
  id UUID NOT NULL PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID references users(id),
  name VARCHAR(255) UNIQUE NOT NULL,
  content TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cards (
  id UUID NOT NULL PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID references users(id),
  name VARCHAR(255) UNIQUE NOT NULL,
  cardholder_name VARCHAR(255) NOT NULL,
  number VARCHAR(255) NOT NULL,
  security_code VARCHAR(255) NOT NULL,
  expiration_date VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
