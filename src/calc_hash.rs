
use dapol::{NdmSmt, User, UserId, D256};
use crate::H256Finalizable;

fn main() {
    let hash = {
        let mut hasher = H256Finalizable::new();
        hasher.update("0x28cddc853d5bfea98a5bc68949ff040a398d17c41f1fcbe023b0b4db143e650c".as_bytes());
        hasher.update("0x12e4abcff6d2443182b2610aea518b40b997cbaacc910bf6f3e01098c896446f".as_bytes());
        hasher.update("0x5f52520131e8c7fb80c9c75f836d73185d96a52dca93da41d659765f31145e35".as_bytes());
        hasher.update("0xb350807c0419757ffb77da7ed7c257eccb2896d4cafce61811814344676aae96".as_bytes());
        hasher.finalize_as_h256() // TODO do a unit test that compares the output of this to a different piece of code
    };

    println!("0x29470e0396c988739573d25aaeefb0c33bfb013acfa6f6de0065d55170f8642d");
    println!("{:?}", hash);
}
