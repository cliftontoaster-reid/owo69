use boolvec::BoolVec;

pub fn shuffle_alpha(d: Vec<u8>) -> Vec<u8> {
    let mut v = Vec::with_capacity(d.len());
    if d.len() % 2 == 0 {
        for i in 0..(d.len()/2) {
            v[(i*2)+1] = d[i];
            v[i*2] = d[i+1];
        }
    } else {
        for i in 0..((d.len()-1)/2) {
            v[(i*2)+1] = d[i];
            v[i*2] = d[i+1];
        }
        v.push(d.last().unwrap().to_owned());
    }

    v
}

pub fn shuffle_beta(d: Vec<u8>) -> Vec<u8> {
    d.iter().map(|e| {
        let uwu = BoolVec::from_vec(vec![e.to_owned()]);
        
        let owo = [uwu.get(1).unwrap(), uwu.get(0).unwrap(), uwu.get(3).unwrap(), uwu.get(2).unwrap(), uwu.get(5).unwrap(), uwu.get(4).unwrap(), uwu.get(6).unwrap(), uwu.get(7).unwrap(), ];
        let u: Vec<u8> = BoolVec::from_iter(owo).bytes().map(|d| d.to_owned()).collect();
        #[cfg(test)]
        println!("-- {} -+ {:?}", e, u);
        
        u.first().unwrap().to_owned()
    }).collect()
}

#[cfg(test)]
mod tests {
    use rand::random;
    use super::*;
    
    #[tokio::test]
    async fn test_encryption_decryption() {
        let mut v: Vec<u8> = Vec::new();
        
        for i in 0..16 {
            v.push(random())
        }
        
        let owo = shuffle_beta(v.clone());
        
        assert_eq!(v, shuffle_beta(owo.clone()))
    }
}