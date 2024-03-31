use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

// Generate password hash and salt
pub async fn generate_password_hash(client_password: &str) -> Result<String, String> {
    // Generate salt
    let salt = SaltString::generate(&mut OsRng);

    // Hash the password
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(client_password.as_bytes(), &salt);

    // Return password hash string or error
    match password_hash {
        Ok(password_hash) => Ok(password_hash.to_string()),
        Err(e) => Err(e.to_string()),
    }
}

// Verify password
pub fn is_password_valid(client_password: &str, stored_password: &str) -> bool {
    match PasswordHash::new(stored_password) {
        Ok(parsed_hash) => Argon2::default()
            .verify_password(client_password.as_bytes(), &parsed_hash)
            .map_or(false, |_| true),
        Err(_) => false,
    }
}
