use des::Des;
use cipher::KeyInit;

fn f(k: &[u8; 8]) {
    let _c = Des::new(k.into());
}
