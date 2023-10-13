//! Abstracted height data type.

use log::error;
use std::{num::ParseIntError, str::FromStr};

static UNDERLYING_INT_TYPE_STR: &str = "u8";
type UnderlyingInt = u8;

/// Minimum tree height supported.
/// It does not make any sense to have a tree of size 1 and the code may
/// actually break with this input so 2 is a reasonable minimum.
pub static MIN_HEIGHT: Height = Height(2);

/// Maximum tree height supported.
/// This number does not have any programmatic/theoretic reason for being 64,
/// it's just a soft limit that can be increased later if need be.
pub static MAX_HEIGHT: Height = Height(64);

/// 2^32 is about half the human population so it is a reasonable default height
/// to have for any protocol involving people as the entities.
pub static DEFAULT_HEIGHT: UnderlyingInt = 32;

#[derive(Clone, Debug, PartialEq)]
pub struct Height(UnderlyingInt);

impl Height {
    pub fn from_with_err(int: UnderlyingInt) -> Result<Self, HeightError> {
        if int < MIN_HEIGHT.0 {
            Err(HeightError::InputTooSmall)
        } else if int > MAX_HEIGHT.0 {
            Err(HeightError::InputTooBig)
        } else {
            Ok(Height(int))
        }
    }

    /// Panics instead of returning an error.
    /// Useful if you are confident the input is correct.
    pub fn from(int: UnderlyingInt) -> Self {
        match Self::from_with_err(int) {
            Ok(h) => h,
            Err(e) => {
                error!("Malformed input, error: {:?}", e);
                panic!("Malformed input, error: {:?}", e);
            }
        }
    }

    /// Return the height for the given y-coord.
    /// Why the offset? `y` starts from 0 but height starts from 1.
    /// See [super][Coordinate] for more details.
    pub fn from_y_coord(y_coord: u8) -> Self {
        Self::from(y_coord + 1)
    }

    /// Return the y-coord for the given height.
    /// Why the offset? `y` starts from 0 but height starts from 1.
    /// See [super][Coordinate] for more details.
    pub fn as_y_coord(&self) -> u8 {
        self.0 - 1
    }

    pub fn as_raw_int(&self) -> UnderlyingInt {
        self.0
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }

    pub fn as_u32(&self) -> u32 {
        self.0 as u32
    }
}

impl FromStr for Height {
    type Err = HeightError;

    /// Constructor that takes in a string slice.
    /// If the length of the str is greater than the max then Err is returned.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Height::from_with_err(UnderlyingInt::from_str(s)?)?)
    }
}

impl Default for Height {
    fn default() -> Self {
        Height(DEFAULT_HEIGHT)
    }
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum HeightError {
    #[error("Input is greater than the upper bound {MAX_HEIGHT:?}")]
    InputTooBig,
    #[error("Input is smaller than the lower bound {MIN_HEIGHT:?}")]
    InputTooSmall,
    #[error("Malformed string input for {UNDERLYING_INT_TYPE_STR:?} type")]
    MalformedString(#[from] ParseIntError),
}