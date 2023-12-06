use boolvec::BoolVec;

pub fn shuffle_alpha(d: Vec<u8>) -> Vec<u8> {
  d.iter()
    .map(|e| {
      let uwu = BoolVec::from_vec(vec![e.to_owned()]);

      let owo = [
        uwu.get(1).unwrap(),
        uwu.get(0).unwrap(),
        uwu.get(3).unwrap(),
        uwu.get(2).unwrap(),
        uwu.get(5).unwrap(),
        uwu.get(4).unwrap(),
        uwu.get(6).unwrap(),
        uwu.get(7).unwrap(),
      ];
      let u: Vec<u8> = BoolVec::from_iter(owo)
        .bytes()
        .map(|d| d.to_owned())
        .collect();
      #[cfg(test)]
      println!("-- {} -+ {:?}", e, u);

      u.first().unwrap().to_owned()
    })
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;
  use rand::random;

  #[tokio::test]
  async fn test_encryption_decryption() {
    let mut v: Vec<u8> = Vec::new();

    for i in 0..16 {
      v.push(random())
    }

    let owo = shuffle_alpha(v.clone());

    assert_eq!(v, shuffle_alpha(owo.clone()))
  }
}
