// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use std::ops::Add;

use num_integer::div_ceil;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd)]
pub struct FrameCount {
    numeric_value: u64,
}

pub fn as_be_bytes(x: u64) -> impl Iterator<Item = u8> {
    let be_bytes = x.to_be_bytes();
    let length_in_bytes = get_nof_non_zero_bytes(x).max(1);
    be_bytes
        .into_iter()
        .skip(be_bytes.len() - length_in_bytes as usize)
}

// TODO: we could this on byte not on bit level
pub fn get_nof_non_zero_bytes(value: u64) -> u8 {
    div_ceil(u64::BITS - value.leading_zeros(), u8::BITS) as u8
}

impl FrameCount {
    pub fn new(numeric_value: u64) -> FrameCount {
        FrameCount { numeric_value }
    }

    pub fn value(&self) -> u64 {
        self.numeric_value
    }

    pub fn as_be_bytes(&self) -> impl Iterator<Item = u8> {
        as_be_bytes(self.numeric_value)
    }

    pub fn length_in_bytes(&self) -> u8 {
        get_nof_non_zero_bytes(self.numeric_value).max(1)
    }
}

impl Add<u64> for FrameCount {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        FrameCount {
            numeric_value: self.numeric_value + rhs,
        }
    }
}
impl PartialEq<u64> for FrameCount {
    fn eq(&self, other: &u64) -> bool {
        self.numeric_value == *other
    }
}

impl From<u64> for FrameCount {
    fn from(numeric_value: u64) -> Self {
        FrameCount { numeric_value }
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct FrameCountGenerator {
    current_frame_count: u64,
}

impl FrameCountGenerator {
    const MAX_FRAME_COUNT: u64 = u64::MAX;

    pub fn increment(&mut self) -> FrameCount {
        let frame_count = FrameCount::new(self.current_frame_count);
        self.current_frame_count =
            (self.current_frame_count + 1) % FrameCountGenerator::MAX_FRAME_COUNT;
        frame_count
    }
}

#[cfg(test)]
mod test {
    use super::{FrameCount, FrameCountGenerator};
    use pretty_assertions::assert_eq;

    #[test]
    fn return_numeric_value() {
        let frame_count = FrameCount::new(42);
        assert_eq!(42, frame_count.value());
    }

    #[test]
    fn return_value_as_be_bytes_without_trailing_zeros_iter() {
        let frame_count = FrameCount::new(666);
        assert_eq!(vec![2, 154], frame_count.as_be_bytes().collect::<Vec<_>>());

        let frame_count = FrameCount::new(0);
        assert_eq!(vec![0], frame_count.as_be_bytes().collect::<Vec<_>>());
    }

    #[test]
    fn return_length_in_bytes() {
        let frame_count = FrameCount::new(666);
        assert_eq!(2, frame_count.length_in_bytes());

        let frame_count = FrameCount::new(0);
        assert_eq!(1, frame_count.length_in_bytes());

        let frame_count = FrameCount::new(u64::MAX);
        assert_eq!((usize::BITS / 8) as u8, frame_count.length_in_bytes());
    }

    #[test]
    fn create_increasing_frame_counts() {
        let mut frame_count_generator = FrameCountGenerator::default();

        for i in 0..10 {
            assert_eq!(frame_count_generator.increment().value(), i);
        }
    }
}
