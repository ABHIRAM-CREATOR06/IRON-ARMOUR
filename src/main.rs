use std::collections::HashMap;
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::{engine::general_purpose, Engine};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tauri::State;

#[cfg_attr(mobile, tauri::mobile_entry_point)]

const SALT: &[u8] = b"iron-armour-salt";

type Vault = HashMap<String, (String, String, String)>; // (ciphertext, nonce, salt)

#[derive(Serialize, Deserialize)]
struct VaultState {
    vault: Vault,
    master_key: Option<String>,
}

fn derive_key(master_password: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(master_password.as_bytes(), SALT, 100_000, &mut key);
    key
}

fn derive_key_argon2(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key).expect("Failed to hash password");
    key
}

fn generate_otp_password(secret: &str, account: &str, username: &str, length: usize) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(secret.as_bytes());
    data.extend_from_slice(account.as_bytes());
    data.extend_from_slice(username.as_bytes());

    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    Mac::update(&mut mac, &data);
    let result = Mac::finalize(mac).into_bytes();

    let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    let mut password = String::new();
    for i in 0..length {
        let index = (result[i % result.len()] as usize) % charset.len();
        password.push(charset.chars().nth(index).unwrap());
    }
    password
}

fn encrypt_password(key: &[u8], password: &str) -> (String, String) {
    let cipher = Aes256Gcm::new_from_slice(key).expect("Invalid key length");
    let nonce_bytes = Nonce::from(rand::random::<[u8; 12]>());
    let ciphertext = cipher
        .encrypt(&nonce_bytes, password.as_bytes())
        .expect("encryption failure!");
    (
        general_purpose::STANDARD.encode(&ciphertext),
        general_purpose::STANDARD.encode(&nonce_bytes),
    )
}

fn decrypt_password(key: &[u8], ciphertext: &str, nonce: &str) -> String {
    let cipher = Aes256Gcm::new_from_slice(key).expect("Invalid key length");
    let nonce_bytes = general_purpose::STANDARD
        .decode(nonce)
        .expect("invalid nonce");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext_bytes = general_purpose::STANDARD
        .decode(ciphertext)
        .expect("invalid ciphertext");
    let plaintext = cipher
        .decrypt(nonce, ciphertext_bytes.as_ref())
        .expect("decryption failure!");
    String::from_utf8(plaintext).expect("invalid UTF-8")
}

#[tauri::command]
fn set_master_password(password: String, state: State<'_, Mutex<VaultState>>) -> Result<(), String> {
    let mut state = state.lock().unwrap();
    state.master_key = Some(password);
    Ok(())
}

#[tauri::command]
fn add_password(account: String, password: String, state: State<'_, Mutex<VaultState>>) -> Result<(), String> {
    let mut state = state.lock().unwrap();
    let master = state.master_key.as_ref().ok_or("Master password not set")?;
    let salt_bytes: [u8; 16] = rand::random();
    let salt = general_purpose::STANDARD.encode(&salt_bytes);
    let entry_key = derive_key_argon2(master, &salt_bytes);
    let (ciphertext, nonce) = encrypt_password(&entry_key, &password);
    state.vault.insert(account, (ciphertext, nonce, salt));
    Ok(())
}

#[tauri::command]
fn get_password(account: String, state: State<'_, Mutex<VaultState>>) -> Result<String, String> {
    let state = state.lock().unwrap();
    let master = state.master_key.as_ref().ok_or("Master password not set")?;
    if let Some((enc_pw, nonce, salt)) = state.vault.get(&account) {
        let salt_bytes = general_purpose::STANDARD.decode(salt).map_err(|_| "Invalid salt")?;
        let entry_key = derive_key_argon2(master, &salt_bytes);
        let decrypted = decrypt_password(&entry_key, enc_pw, nonce);
        Ok(decrypted)
    } else {
        Err("Account not found".to_string())
    }
}

#[tauri::command]
fn list_accounts(state: State<'_, Mutex<VaultState>>) -> Vec<String> {
    let state = state.lock().unwrap();
    state.vault.keys().cloned().collect()
}

#[tauri::command]
fn generate_otp(account: String, username: String, secret: String, length: usize, state: State<'_, Mutex<VaultState>>) -> Result<String, String> {
    let otp_password = generate_otp_password(&secret, &account, &username, length);
    Ok(otp_password)
}

#[tauri::command]
fn analyze_wifi() -> Vec<(String, String, String)> {
    let wifi_passwords = vec![
        ("Home_WiFi".to_string(), "password123".to_string(), "Weak".to_string()),
        ("OfficeNet".to_string(), "M@in_Office2024".to_string(), "Strong".to_string()),
        ("CafeFree".to_string(), "12345678".to_string(), "Weak".to_string()),
    ];
    wifi_passwords
}

pub fn run() {
    tauri::Builder::default()
        .manage(Mutex::new(VaultState {
            vault: HashMap::new(),
            master_key: None,
        }))
        .invoke_handler(tauri::generate_handler![
            set_master_password,
            add_password,
            get_password,
            list_accounts,
            generate_otp,
            analyze_wifi
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn main() {
    run();
}
