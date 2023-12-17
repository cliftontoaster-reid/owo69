mod shuffle;

use crate::shuffle::shuffle_alpha;
use base64::engine::general_purpose;
use base64::Engine;
use clap::{Arg, Command};
use indicatif::ProgressBar;
use rand::random;
use serde::{Deserialize, Serialize};
use xz::bufread::{XzEncoder, XzDecoder};
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;
use text_io::read;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use toml::{from_str, to_string_pretty};

const VERSION: (u16, u16, u16) = (0, 1, 3);

#[derive(Serialize, Deserialize)]
pub struct Key {
  pub length: usize,
  pub key: Vec<u8>,
  pub rev: usize,
}

impl Key {
  pub fn gen(l: usize) -> Self {
    let uwu: Vec<u8> = (0..l - 1).map(|_| random::<u8>()).collect();

    Self {
      length: l,
      key: uwu,
      rev: 0,
    }
  }
}

#[tokio::main]
async fn main() {
  let encrypt = Command::new("owo69")
        .author("Clifton Toaster Reid")
        .version("v0.1.0 TOAST")
        .args([
            Arg::new("input").short('i').help("The path to the text to encrypt or decrypt.").required(true),
            Arg::new("output").short('o').help("The path to the desired encrypted file.").required(false),
            Arg::new("key").short('k').help("The path to the key file.").required_if_eq("method", "dec"),
            Arg::new("method").short('m').help("Either 'enc' to encrypt or 'dec' to decrypt.").required(true),
            Arg::new("steps").short('s').help("The amount of encryption layers the program should apply.").required_if_eq("method", "enc").default_missing_value("16"),
        ])
        .about("This is Transform Obscure Advanced Secure Technique Encryption Routine, or TOASTER, a stupid program, more intelligent that the creator.")
        .get_matches();
  let owo_path = PathBuf::from_str(encrypt.get_one::<String>("input").unwrap()).unwrap();
  if !owo_path.exists() {
    eprint!("Oh noes! It seems that the file input doesn't exist!");
    exit(37)
  }

  match encrypt.get_one::<String>("method").unwrap().as_str() {
    "enc" => {
      let mut owo_r = String::new();
      File::open(owo_path.clone())
        .await
        .unwrap()
        .read_to_string(&mut owo_r)
        .await
        .expect("An error occurred while trying to open the file. So sad.");

      let key = match encrypt.get_one::<String>("key") {
        None => {
          print!("How long do you want the key to be? We recommend 64 : ");
          let len: usize = read!();
          let k = Key::gen(len);

          File::create("./key.toast_k")
            .await
            .unwrap()
            .write_all(to_string_pretty(&k).unwrap().as_bytes())
            .await
            .unwrap();

          k
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

          from_str(&k_raw).unwrap()
        }
      };

      EncodedTOAST::from_str(
        owo_r,
        encrypt.get_one::<String>("steps").unwrap().parse().unwrap(),
        key.key,
      )
      .save(match encrypt.get_one::<String>("output") {
        None => {
          let path = owo_path.clone();
          let file_name = path.file_name().unwrap_or_default();
          let new_file_name = format!("{}.toast", file_name.to_string_lossy());
          owo_path.with_file_name(new_file_name)
        }
        Some(s) => PathBuf::from_str(&s).unwrap(),
      })
      .await;
    }
    "dec" => {
      let owo = EncodedTOAST::load(&owo_path).await;

      let data = {
        let owo_path = PathBuf::from_str(encrypt.get_one::<String>("key").unwrap()).unwrap();
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

        let k: Key = from_str(&k_raw).unwrap();

        owo.to_str(k.key)
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

#[derive(Serialize, Deserialize)]
struct EncodedTOAST {
  pub metadata: TOASTMetadata,
  pub data: Vec<String>,
}
#[derive(Serialize, Deserialize)]
struct TOASTMetadata {
  pub version: (u16, u16, u16),
  pub steps: usize,
}

impl EncodedTOAST {
  pub async fn load(owo_path: &PathBuf) -> Self {
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

    if k_raw.contains("~@") {
      let fuck: Vec<&str> = k_raw.split("~@").collect();
      
      #[cfg(debug_assertions)]
      println!("{:?}", fuck);
      Self {
        metadata: from_str(
          &String::from_utf8(
            general_purpose::STANDARD
              .decode(fuck.first().unwrap())
              .unwrap(),
          )
          .unwrap(),
        )
        .unwrap(),
        data: divide_text(fuck.last().unwrap()),
      }
    } else {
      Self {
        metadata: TOASTMetadata {
          version: VERSION,
          steps: 1,
        },
        data: vec![],
      }
    }
  }

  pub async fn save(&self, p: PathBuf) {
    let l = format!(
      "{}~@{}",
      general_purpose::STANDARD.encode(to_string_pretty(&self.metadata).unwrap()),
      self.data.join("")
    );
    #[cfg(debug_assertions)]
    println!("{}", general_purpose::STANDARD.encode(to_string_pretty(&self.metadata).unwrap()));
    File::create(p)
      .await
      .unwrap()
      .write_all(
        l
        .as_bytes(),
      )
      .await
      .unwrap();
  }

  pub fn from_str(s: String, steps: usize, key: Vec<u8>) -> Self {
    let mut owo = divide_text(&s);
    if steps == 0 {
      panic!("Cannot encrypt 0 times.")
    }
    for s in 0..steps {
      println!("Step {}/{}", s, steps);
      owo = encrypt_step(owo.clone(), key.clone());
    }

    Self {
      metadata: TOASTMetadata {
        version: VERSION,
        steps,
      },
      data: owo,
    }
  }

  pub fn to_str(&self, key: Vec<u8>) -> String {
    let mut owo = self.data.clone();
    if self.metadata.steps == 0 {
      panic!("Cannot decrypt 0 times.")
    }
    for _ in 0..self.metadata.steps {
      owo = decrypt_step(owo.clone(), key.clone());
    }

    owo.join("")
  }
}

fn divide_text(s: &str) -> Vec<String> {
  let mut owo: Vec<String> = Vec::new();
  let mut uwu: String = String::new();

  #[cfg(debug_assertions)]
  print!("Chars : [ ");
  for c in s.chars() {
    #[cfg(debug_assertions)]
    print!("'{}'", c);
    if (c == ' ') | (c == '.') | (c == '?') | (c == '!') | (c == ',') | (c == ':') {
      #[cfg(debug_assertions)]
      print!("r, ");
      if !uwu.is_empty() {
        owo.push(uwu.clone());
        uwu = String::new();
        owo.push(c.to_string());
      } else {
        owo.push(c.to_string());
      }
    } else {
      #[cfg(debug_assertions)]
      print!("n, ");
      uwu.push(c);
    }
  }
  if !uwu.is_empty() {
    owo.push(uwu.clone());
  }

  #[cfg(debug_assertions)]
  println!("] {:?}", &owo);

  owo
}

pub fn encrypt_step(data: Vec<String>, key: Vec<u8>) -> Vec<String> {
  #[cfg(debug_assertions)]
  println!("Encrypting data:\n\n-- {:?}", data);

  let mut new: Vec<String> = Vec::new();
  let progress = ProgressBar::new(data.len() as u64);

  for uwu in data.iter() {
    progress.inc(1);
    if (uwu == " ") | (uwu == ".") | (uwu == "?") | (uwu == "!") | (uwu == ",") | (uwu == ":") {
      #[cfg(debug_assertions)]
      println!("--{}--", uwu);
      new.push(uwu.clone());
    } else {
      let nuzzle: Vec<u8> = uwu
        .as_bytes()
        .iter()
        .zip(key.iter().cycle())
        .map(|(code, key)| (code ^ key))
        .collect();

      new.push(
        general_purpose::STANDARD
          .encode(
            &shuffle_alpha(
              XzEncoder::new(nuzzle.to_owned().as_slice(), 9).into_inner().to_vec()
            )
          )
          .to_string(),
      )
    }
  }
  progress.finish();

  new
}

pub fn decrypt_step(data_r: Vec<String>, key: Vec<u8>) -> Vec<String> {
  let data: Vec<Vec<u8>> = data_r
    .into_iter()
    .map(|uwu| {
      if (uwu == " ") | (uwu == ".") | (uwu == "?") | (uwu == "!") | (uwu == ",") | (uwu == ":") {
        uwu.into_bytes()
      } else {
        let owo = shuffle_alpha(
          general_purpose::STANDARD.decode(
            uwu
          ).unwrap()
        );
        let hihi = XzDecoder::new(
          owo.as_slice()
        );
        hihi.into_inner().to_vec()
      }
    })
    .collect();

  #[cfg(debug_assertions)]
  println!("Decrypting data:\n\n-- {:?}", data);

  let progress = ProgressBar::new(data.len() as u64);

  let mut decoded: Vec<String> = Vec::new();
  for uwu in data.iter() {
    progress.inc(1);
    if (uwu == " ".as_bytes())
      | (uwu == ".".as_bytes())
      | (uwu == "?".as_bytes())
      | (uwu == "!".as_bytes())
      | (uwu == ",".as_bytes())
      | (uwu == ":".as_bytes())
    {
      decoded.push(String::from_utf8(uwu.clone()).unwrap());
      #[cfg(debug_assertions)]
      println!("=='{}'==", String::from_utf8(uwu.clone()).unwrap())
    } else {
      let original: Vec<u8> = uwu
        .iter()
        .zip(key.iter().cycle())
        .map(|(code, key)| (code ^ key))
        .collect();

      decoded.push(String::from_utf8(original).unwrap());
    }
  }
  progress.finish();

  decoded
}

#[cfg(test)]
mod tests {
  use super::*;
  use rand::Rng;

  #[tokio::test]
  async fn test_encryption_decryption() {
    // Test data
    let original_text = divide_text(
      &rand::thread_rng()
        .sample_iter::<char, _>(rand::distributions::Standard)
        .take(69420)
        .collect::<String>(),
    );

    let key: Vec<u8> = rand::thread_rng()
      .sample_iter::<u8, _>(rand::distributions::Standard)
      .take(69)
      .collect(); // Replace this with a secure way to generate a key

    // Encrypt the text
    let encrypted_data = encrypt_step(original_text.clone(), key.clone());

    // Decrypt the text
    let decrypted_data = decrypt_step(encrypted_data.clone(), key);

    // Assertions
    assert_eq!(original_text, decrypted_data);
  }
}
