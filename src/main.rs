extern crate num_bigint;
extern crate rand;

use num_bigint::BigUint;
use rand::prelude::*;
use sha2::{Digest, Sha512};

fn rsa_generate_keys() -> ((BigUint, BigUint), (BigUint, BigUint)) {
    (
        (
            BigUint::parse_bytes(b"65537", 10).unwrap(),
            BigUint::parse_bytes(b"58967658369561163583995664151705537612631456941226585145001736155445085885436956133402962616775555500479429922140321605063456075222335023020218578571558003435174909963319619244821157746252197885628802071763470174413201522569356053296685834595362968800778468737693074613267684084217204017873750446802044584084498581219849973790017343888256411013653688556278788070745635045095995056877259642839730825907965544973672656542601570609068817838234644958846427643088478240335082249677864789882511592486797239674160452077169411971273434857626735582274817190984442183721945999865859466422472845277588368259261760233826535480137", 10).unwrap()
        ),
        (
            BigUint::parse_bytes(b"32639742054323523661031580828650534544392003478949839063736255562124081596351847364013089886417596950354636310108218358259943735367279937975211699593540109138569129405212055903155962561652878992005591100527818545966603574053221236696683939389678915058929150433015761702105657992264877747720954135956649973789334911071168428227464085150820871588160770978551544646965210798269197906675922224772713666123225990305644372957419486169245295190574189157389340237417783311258488777336686103120891002317113842264416737708675921812070527474901946450952078789439410581693777829144977217172397092723130874770379072485175449578961", 10).unwrap(),
            BigUint::parse_bytes(b"58967658369561163583995664151705537612631456941226585145001736155445085885436956133402962616775555500479429922140321605063456075222335023020218578571558003435174909963319619244821157746252197885628802071763470174413201522569356053296685834595362968800778468737693074613267684084217204017873750446802044584084498581219849973790017343888256411013653688556278788070745635045095995056877259642839730825907965544973672656542601570609068817838234644958846427643088478240335082249677864789882511592486797239674160452077169411971273434857626735582274817190984442183721945999865859466422472845277588368259261760233826535480137", 10).unwrap()
        )
    )
}

fn bxor(x: &Vec<u8>, y: &Vec<u8>) -> Vec<u8> {
    x.iter().zip(y.iter()).map(|x| x.0 ^ x.1).collect()
}

fn extend_hash(h: &mut Vec<u8>, content: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    let result: Vec<u8> = Vec::new();
    hasher.input(content);
    let hash = &hasher.result()[..];
    h.extend_from_slice(hash);
    result
}

fn hash(content: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.input(content);
    let hash = &hasher.result()[..];
    hash.to_vec()
}


fn i32_to_bytes(content: &BigUint, length: usize) -> Vec<u8> {
    let bs_byte = content.to_bytes_be();
    let mut result = vec![0; length - bs_byte.len()];
    result.extend(bs_byte);
    result
}

fn rsa_encrypt(plaintext: &BigUint, public_key: &(BigUint, BigUint)) -> BigUint {
    let mut rng = rand::thread_rng();
    let mut iv: [u8; 64] = [0; 64];
    for i in 0..64 {
        iv[i] = rng.gen();
    }
    let mut h: Vec<u8> = Vec::new();
    let h1 = extend_hash(&mut h, &iv[..]);
    let h2 = extend_hash(&mut h, &h1[..]);
    extend_hash(&mut h, &h2[..]);
    let pt = i32_to_bytes(plaintext, 192);
    let mut x192 = bxor(&pt, &h);
    let h4 = hash(&x192);
    let viv = iv.to_vec();
    let x64 = bxor(&viv, &h4);
    x192.extend(x64.iter());
    let x256 = BigUint::from_bytes_be(&x192);
    x256.modpow(&public_key.0, &public_key.1)
}

fn rsa_decrypt(ciphertext: BigUint, secret_key: (BigUint, BigUint)) -> BigUint {
    let cipher = ciphertext.modpow(&secret_key.0, &secret_key.1);
    let cipher_bytes = cipher.to_bytes_be();
    let mut x256 = vec![0; 256 - cipher_bytes.len()];
    x256.extend(cipher_bytes.iter());
    let (x192, x64) = (&x256[..192], &x256[192..]);
    let h4 = hash(&x192.to_vec());
    let iv = bxor(&x64.to_vec(), &h4);
    let mut h: Vec<u8> = Vec::new();
    let h1 = extend_hash(&mut h, &iv[..]);
    let h2 = extend_hash(&mut h, &h1[..]);
    extend_hash(&mut h, &h2[..]);
    let pt = bxor(&x192.to_vec(), &h);
    BigUint::from_bytes_be(&pt)
}

fn main() {
    let (public_key, secret_key) = rsa_generate_keys();
    let original = BigUint::parse_bytes(b"0", 10).unwrap();
    let ciphertext = rsa_encrypt(&original, &public_key);
    let plaintext = rsa_decrypt(ciphertext, secret_key);
    assert_eq!(original, plaintext);
}
