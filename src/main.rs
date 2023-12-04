use base64::engine::general_purpose;
use base64::Engine;
use clap::builder::Str;
use clap::{Arg, Command};
use indicatif::ProgressBar;
use rand::random;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;
use text_io::read;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const REV: usize = 1;

#[derive(Serialize, Deserialize)]
pub struct Key {
    pub length: usize,
    pub key: Vec<u8>,
    pub rev: usize,
}

impl Key {
    pub fn gen(l: usize) -> Self {
        let uwu: Vec<u8> = (0..l - 1).map(|_| random()).collect();

        Self {
            length: l,
            key: uwu,
            rev: 0,
        }
    }
}

#[tokio::main]
async fn main() {
    let encrypt = Command::new("encrypt")
        .author("Clifton Toaster Reid")
        .version("v0.1.0 TOAST")
        .args([
            Arg::new("input").short('i').help("The path to the text to encrypt.").required(true),
            Arg::new("output").short('o').help("The path to the desired encrypted file.").required(false),
            Arg::new("key").short('k').help("The path to the key file.").required_if_eq("method", "ded"),
            Arg::new("method").short('m').help("Either 'enc' to encrypt or 'dec' to decrypt.").required(true),
        ])
        .about("This is Transform Obscure Advanced Secure Technique Encryption Routine, or TOASTER, a stupid program, more intelligent that the creator.")
        .get_matches();
    let owo_path = PathBuf::from_str(encrypt.get_one::<String>("input").unwrap()).unwrap();
    if !owo_path.exists() {
        eprint!("Oh noes! It seems that the file input doesn't exist!");
        exit(37)
    }

    let mut owo = String::new();
    File::open(owo_path.clone())
        .await
        .unwrap()
        .read_to_string(&mut owo)
        .await
        .expect("An error occurred while trying to open the file. So sad.");

    match encrypt.get_one::<String>("method").unwrap().as_str() {
        "enc" => {
            println!("Divinding text.");
            let owo = divide_text(&owo);

            let data = match encrypt.get_one::<String>("key") {
                None => {
                    print!("How long do you want the key to be? We recommend 64 : ");
                    let len: usize = read!();
                    let k = Key::gen(len);

                    File::create("./key.toast_k")
                        .await
                        .unwrap()
                        .write_all(toml::to_string_pretty(&k).unwrap().as_bytes())
                        .await
                        .unwrap();

                    encrypt_step(owo, k.key).join("")
                }
                Some(s) => {
                    let owo_path = PathBuf::from_str(s).unwrap();
                    if !owo_path.exists() {
                        eprint!("Oh noes! It seems that the file input doesn't exist!");
                        exit(37)
                    }

                    let mut k_raw: String = String::new();

                    File::open(owo_path)
                        .await
                        .unwrap()
                        .read_to_string(&mut k_raw)
                        .await
                        .unwrap();

                    let k: Key = toml::from_str(&k_raw).unwrap();

                    encrypt_step(owo, k.key).join("")
                }
            };

            File::create(match encrypt.get_one::<String>("output") {
                None => {
                    let path = owo_path.clone();
                    let file_name = path.file_name().unwrap_or_default();
                    let new_file_name = format!("{}.toast", file_name.to_string_lossy());
                    owo_path.with_file_name(new_file_name)
                }
                Some(s) => PathBuf::from_str(&s).unwrap(),
            })
            .await
            .unwrap()
            .write_all(data.as_bytes())
            .await
            .unwrap();
        }
        "dec" => {
            let owo = divide_text(&owo);

            let data = {
                let owo_path =
                    PathBuf::from_str(encrypt.get_one::<String>("key").unwrap()).unwrap();
                if !owo_path.exists() {
                    eprint!("Oh noes! It seems that the file input doesn't exist!");
                    exit(37)
                }

                let mut k_raw: String = String::new();

                File::open(owo_path)
                    .await
                    .unwrap()
                    .read_to_string(&mut k_raw)
                    .await
                    .unwrap();

                let k: Key = toml::from_str(&k_raw).unwrap();

                decrypt_step(owo, k.key).join("")
            };

            File::create(match encrypt.get_one::<String>("output") {
                None => {
                    let path = owo_path.clone();
                    let file_name = path.file_name().unwrap_or_default();
                    let new_file_name = format!("{}.txt", file_name.to_string_lossy());
                    owo_path.with_file_name(new_file_name)
                }
                Some(s) => PathBuf::from_str(&s).unwrap(),
            })
            .await
            .unwrap()
            .write_all(data.as_bytes())
            .await
            .unwrap();
        }
        _ => panic!("T'es une grosse merde tu sais! Either 'enc' to encrypt or 'dec' to decrypt."),
    }
}

fn divide_text(s: &str) -> Vec<String> {
    let mut owo: Vec<String> = Vec::new();
    let mut uwu: String = String::new();

    for c in s.chars() {
        if (c == ' ') | (c == '.') | (c == '?') | (c == '!') | (c == ',') | (c == ':') {
            if !uwu.is_empty() {
                owo.push(uwu.clone());
                uwu = String::new();
                owo.push(c.to_string());
            }
        } else {
            uwu.push(c);
        }
    }
    if !uwu.is_empty() {
        owo.push(uwu.clone());
    }

    owo
}

pub fn encrypt_step(data: Vec<String>, key: Vec<u8>) -> Vec<String> {
    let mut new: Vec<String> = Vec::new();
    let progress = ProgressBar::new(data.len() as u64);

    for uwu in data.iter() {
        progress.inc(1);
        if (uwu == " ") | (uwu == ".") | (uwu == "?") | (uwu == "!") | (uwu == ",") | (uwu == ":") {
            new.push(uwu.clone());
        } else {
            let nuzzle: Vec<u8> = uwu
                .as_bytes()
                .iter()
                .zip(key.iter().cycle())
                .map(|(code, key)| (code ^ key))
                .collect();

            new.push(general_purpose::STANDARD.encode(&nuzzle).to_string())
        }
    }
    progress.finish();

    new
}

pub fn decrypt_step(data: Vec<String>, key: Vec<u8>) -> Vec<String> {
    let mut decoded: Vec<String> = Vec::new();
    let progress = ProgressBar::new(data.len() as u64);

    for uwu in data.iter() {
        progress.inc(1);
        if (uwu == " ") | (uwu == ".") | (uwu == "?") | (uwu == "!") | (uwu == ",") | (uwu == ":") {
            decoded.push(uwu.clone());
        } else {
            print!("{}", &uwu);
            let nuzzle: Vec<u8> = general_purpose::STANDARD.decode(uwu.as_bytes()).unwrap();

            let original: String = nuzzle
                .iter()
                .zip(key.iter().cycle())
                .map(|(code, key)| (code ^ key) as char)
                .collect();

            decoded.push(original);
        }
    }
    progress.finish();

    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        // Test data
        let original_text = divide_text("Hello, world!");
        let key: Vec<u8> = vec![0x0F, 0xAA, 0x42, 0x7E]; // Replace this with a secure way to generate a key

        // Encrypt the text
        let encrypted_data = encrypt_step(original_text.clone(), key.clone());

        // Decrypt the text
        let decrypted_data = decrypt_step(encrypted_data.clone(), key);

        // Assertions
        assert_eq!(original_text, decrypted_data);
    }
}
