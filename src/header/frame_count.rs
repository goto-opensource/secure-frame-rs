// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use std::ops::Add;

use super::util::{as_min_be_bytes, min_len_in_bytes};

/// Represents the frame count (CTR) in a sframe header
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd)]
pub struct FrameCount {
    numeric_value: u64,
}

impl FrameCount {
    /// returns the underlying value as an iterator over big-endian bytes
    pub fn as_be_bytes(&self) -> impl DoubleEndedIterator<Item = u8> {
        as_min_be_bytes(self.numeric_value)
    }

    /// The minimum nof bytes needed to represent this count
    pub fn length_in_bytes(&self) -> u8 {
        min_len_in_bytes(self.numeric_value)
    }
}

impl std::ops::Sub<FrameCount> for FrameCount {
    type Output = Self;

    fn sub(self, rhs: FrameCount) -> Self::Output {
        FrameCount {
            numeric_value: self.numeric_value - rhs.numeric_value,
        }
    }
}

impl std::ops::Sub<FrameCount> for u64 {
    type Output = Self;

    fn sub(self, rhs: FrameCount) -> Self::Output {
        self - rhs.numeric_value
    }
}

impl std::ops::Sub<u64> for FrameCount {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self::Output {
        FrameCount {
            numeric_value: self.numeric_value - rhs,
        }
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

impl PartialOrd<u64> for FrameCount {
    fn partial_cmp(&self, other: &u64) -> Option<std::cmp::Ordering> {
        self.numeric_value.partial_cmp(other)
    }
}

impl PartialEq<u64> for FrameCount {
    fn eq(&self, other: &u64) -> bool {
        self.numeric_value == *other
    }
}

impl From<FrameCount> for u64 {
    fn from(frame_count: FrameCount) -> Self {
        frame_count.numeric_value
    }
}

impl From<u64> for FrameCount {
    fn from(numeric_value: u64) -> Self {
        FrameCount { numeric_value }
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct FrameCountGenerator {
    current_frame_count: u64,
}

impl FrameCountGenerator {
    const MAX_FRAME_COUNT: u64 = u64::MAX;

    pub fn increment(&mut self) -> FrameCount {
        let frame_count = FrameCount::from(self.current_frame_count);
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
        let frame_count = FrameCount::from(42);
        assert_eq!(frame_count, 42);
    }

    #[test]
    fn return_value_as_be_bytes_without_trailing_zeros_iter() {
        let frame_count = FrameCount::from(666);
        assert_eq!(vec![2, 154], frame_count.as_be_bytes().collect::<Vec<_>>());

        let frame_count = FrameCount::from(0);
        assert_eq!(vec![0], frame_count.as_be_bytes().collect::<Vec<_>>());
    }

    #[test]
    fn return_length_in_bytes() {
        let frame_count = FrameCount::from(666);
        assert_eq!(2, frame_count.length_in_bytes());

        let frame_count = FrameCount::from(0);
        assert_eq!(1, frame_count.length_in_bytes());

        let frame_count = FrameCount::from(u64::MAX);
        assert_eq!((usize::BITS / 8) as u8, frame_count.length_in_bytes());
    }

    #[test]
    fn create_increasing_frame_counts() {
        let mut frame_count_generator = FrameCountGenerator::default();

        for i in 0..10 {
            assert_eq!(frame_count_generator.increment(), i);
        }
    }
}
