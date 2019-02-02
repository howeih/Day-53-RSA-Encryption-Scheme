Day 53: RSA Encryption Scheme
<br>
I have large prime numbers and know how to generate RSA keys and how to use them.
<br>
One more tool is needed, though, a strong pseudo-random generator. I will use SHA-512. It is a secure hash function, and to be secure it has to comply some special demands. Among others, it has to be a secure PRG.
<br>
My recipe is inspired by RSA OAEP, which is used in practice.
![Alt text](rsa.png?raw=true "RSA")
<br>
Assuming I have two 1024-bit primes, 2048-bit modulus, random generator and SHA-512, I can transfer up to 192-byte message.
<br>
Here are the steps:
<br>
1. IV: generate 64-byte block of random values
2. H1, H2, H3: apply repetitively SHA-512 to produce 64-byte blocks of uniform random values
3. X192: XOR plaintext message with concatenated block H1|H2|H3
4. X64: use SHA-512 on block X192 to produce another 64-byte block of uniform random values and XOR with IV
5. encrypt: RSA(X192|X64, public_key)
<br>
The key idea is that randomization of raw message makes encryption non-deterministic and chosen-ciphertext secure. The final 256-byte message X192|X64 is fully random with uniform distribution. 

run:
```
fn main() {
    let (public_key, secret_key) = rsa_generate_keys();
    let original = BigUint::parse_bytes(b"0", 10).unwrap();
    let ciphertext = rsa_encrypt(&original, &public_key);
    let plaintext = rsa_decrypt(ciphertext, secret_key);
    assert_eq!(original, plaintext);
}
```
