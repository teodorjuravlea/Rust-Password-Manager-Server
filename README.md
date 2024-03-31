# Rust Password Manager Server, built with Axum.

Config environment variables:

- `DATABASE_URL`: Full connection string for the database
- `JWT_SECRET`: Secret used to sign and verify JWT tokens
- `JWT_EXPIRED_IN`: Duration of the JWT token
- `JWT_MAX_AGE`: Maximum age of the JWT token