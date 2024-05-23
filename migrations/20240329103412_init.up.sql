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
CREATE TABLE IF NOT EXISTS encrypted_data_entries (
  user_id UUID NOT NULL references users(id),
  name VARCHAR(255) UNIQUE NOT NULL,
  content_type VARCHAR(255) NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  PRIMARY KEY (user_id, name, content_type)
);