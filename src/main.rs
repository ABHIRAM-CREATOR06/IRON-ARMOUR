use std::collections::HashMap;
use std::io::{self, Write};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::aead::generic_array::sequence::GenericSequence; // ✅ Add this line
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose, Engine};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;


const SALT: &[u8] = b"iron-armour-salt";

type Vault = HashMap<String, String>;

fn derive_key(master_password: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(master_password.as_bytes(), SALT, 100_000, &mut key);
    key
}

fn encrypt_password(key: &[u8], password: &str) -> (String, String) {
    let cipher = Aes256Gcm::new_from_slice(key).expect("Invalid key length");
    let nonce_bytes = aes_gcm::Nonce::generate(&mut OsRng);
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

fn main() {
    println!("🔐 Welcome to Iron Armour - Secure Password Vault 🔐");

    print!("Enter master password: ");
    io::stdout().flush().unwrap();

    let mut master = String::new();
    io::stdin().read_line(&mut master).unwrap();
    let master = master.trim();
    let key = derive_key(master);

    let mut vault: HashMap<String, (String, String)> = HashMap::new();

    loop {
        println!("\n1. Add Password\n2. View Password\n3. List Accounts\n4. Analyze Wi-Fi Passwords\n5. Exit");
        print!("Choice: ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();

        match choice.trim() {
            "1" => {
                print!("Enter account name: ");
                io::stdout().flush().unwrap();
                let mut name = String::new();
                io::stdin().read_line(&mut name).unwrap();
                let name = name.trim().to_string();

                print!("Enter password: ");
                io::stdout().flush().unwrap();
                let mut pw = String::new();
                io::stdin().read_line(&mut pw).unwrap();
                let pw = pw.trim();

                let (ciphertext, nonce) = encrypt_password(&key, pw);
                vault.insert(name, (ciphertext, nonce));

                println!("✅ Password stored securely!");
            }
            "2" => {
                print!("Enter account name: ");
                io::stdout().flush().unwrap();
                let mut name = String::new();
                io::stdin().read_line(&mut name).unwrap();
                let name = name.trim();

                if let Some((enc_pw, nonce)) = vault.get(name) {
                    let decrypted = decrypt_password(&key, enc_pw, nonce);
                    println!("🔑 Password for {}: {}", name, decrypted);
                } else {
                    println!("❌ Account not found.");
                }
            }
            "3" => {
                println!("📂 Stored accounts:");
                for name in vault.keys() {
                    println!(" - {}", name);
                }
            }
            "4" => {
                analyze_wifi_passwords();
            }
            "5" => {
                println!("👋 Exiting. Stay safe!");
                break;
            }
            _ => println!("❌ Invalid choice."),
        }
    }
}

fn analyze_wifi_passwords() {
    // Example hardcoded Wi-Fi passwords
    let wifi_passwords = vec![
        ("Home_WiFi", "password123"),
        ("OfficeNet", "M@in_Office2024"),
        ("CafeFree", "12345678"),
    ];

    println!("\n📡 Wi-Fi Password Strength Analyzer:");
    for (ssid, pw) in wifi_passwords {
        let strength = score_password(pw);
        println!(
            "  🔸 {} => {} ({})",
            ssid,
            pw,
            match strength {
                0..=2 => "Weak",
                3..=4 => "Moderate",
                _ => "Strong",
            }
        );
    }
}

fn score_password(password: &str) -> u8 {
    let mut score = 0;
    if password.len() >= 8 {
        score += 1;
    }
    if password.chars().any(|c| c.is_uppercase()) {
        score += 1;
    }
    if password.chars().any(|c| c.is_lowercase()) {
        score += 1;
    }
    if password.chars().any(|c| c.is_numeric()) {
        score += 1;
    }
    if password.chars().any(|c| !c.is_alphanumeric()) {
        score += 1;
    }
    score
}

