// STENT TODO docs & impl

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Salt([u8; 32]);
