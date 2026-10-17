use rsa::RsaPrivateKey;

fn f(rng: &mut impl rand::CryptoRng) {
    let _k = RsaPrivateKey::new(rng, 2048).unwrap();
}
