use sha2::{Sha256, Digest};

#[derive(Clone)]
pub struct Hmac {
    ih: Sha256,
    output_xor: [u8; 64],
}

fn xor(mut array: [u8; 64], byte: u8) -> [u8; 64] {
    for b in array.iter_mut() {
        *b ^= byte;
    }

    array
}

impl Hmac {
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        let key = key.as_ref();

        let stack_array: [u8; 32];
        let key = if key.len() > 64 {
            let mut hashed_key = Sha256::new();
            hashed_key.update(key);
            stack_array = hashed_key.finalize().into();
            &stack_array
        } else {
            key
        };

        let mut padded = [0; 64];
        padded[..key.len()].copy_from_slice(key);

        let input_xor = xor(padded, 0x36);
        let output_xor = xor(padded, 0x5C);

        let mut ih = Sha256::new();
        ih.update(&input_xor);
        Self { ih, output_xor }
    }

    pub fn update(&mut self, input: impl AsRef<[u8]>) {
        self.ih.update(input);
    }

    pub fn finalize(self) -> [u8; 32] {
        let mut oh = Sha256::new();
        oh.update(&self.output_xor);
        oh.update(self.ih.finalize());
        oh.finalize().into()
    }
}