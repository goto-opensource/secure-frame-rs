use crate::{
    error::{Result, SframeError},
    header::{FrameCount, Header, HeaderFields},
};
use std::cell::Cell;

pub trait FrameValidation {
    fn validate(&self, header: &Header) -> Result<()>;
}

pub struct ReplayAttackProtection {
    tolerance: u64,
    last_frame_count: Cell<FrameCount>,
}

impl ReplayAttackProtection {
    pub fn with_tolerance(tolerance: u64) -> Self {
        ReplayAttackProtection {
            tolerance,
            last_frame_count: Cell::new(0.into()),
        }
    }
}

impl FrameValidation for ReplayAttackProtection {
    fn validate(&self, header: &Header) -> Result<()> {
        let last_frame_count = self.last_frame_count.get();
        let current_frame_count = header.get_frame_counter();

        if current_frame_count > last_frame_count {
            // frame is fine and fresh
            self.last_frame_count.set(current_frame_count);
            Ok(())
        } else {
            // frame old
            let age: u64 = last_frame_count.value() - current_frame_count.value();

            if age <= self.tolerance {
                self.last_frame_count.set(current_frame_count);
                Ok(())
            } else {
                // maybe there was an overflow
                let dist_to_overflow = u64::MAX - last_frame_count.value();
                let overflow_age = current_frame_count.value() + dist_to_overflow;

                // no it's just too old
                if overflow_age <= self.tolerance {
                    self.last_frame_count.set(current_frame_count);
                    Ok(())
                } else {
                    Err(SframeError::FrameValidationFailed)
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn accept_newer_headers() {
        let validator = ReplayAttackProtection::with_tolerance(128);
        let first_header = Header::with_frame_counter(23456789u64, 2400);
        let second_header = Header::with_frame_counter(23456789u64, 2480);

        assert_eq!(validator.validate(&first_header), Ok(()));
        assert_eq!(validator.validate(&second_header), Ok(()));
    }

    #[test]
    fn accept_older_headers_in_tolerance() {
        let validator = ReplayAttackProtection::with_tolerance(128);
        let first_header = Header::with_frame_counter(23456789u64, 2480);
        let late_header = Header::with_frame_counter(23456789u64, 2400);

        assert_eq!(validator.validate(&first_header), Ok(()));
        assert_eq!(validator.validate(&late_header), Ok(()));
    }

    #[test]
    fn reject_too_old_headers() {
        let validator = ReplayAttackProtection::with_tolerance(128);
        let first_header = Header::with_frame_counter(23456789u64, 2480);
        let too_late_header = Header::with_frame_counter(23456789u64, 1024);

        assert_eq!(validator.validate(&first_header), Ok(()));
        assert_eq!(
            validator.validate(&too_late_header),
            Err(SframeError::FrameValidationFailed)
        )
    }

    #[test]
    fn handle_overflowing_counters() {
        let validator = ReplayAttackProtection::with_tolerance(128);
        let start_count = u64::MAX - 3;
        let first_header = Header::with_frame_counter(23456789u64, start_count);

        assert_eq!(validator.validate(&first_header), Ok(()));

        for step in 0..10 {
            let late_count = start_count.wrapping_add(step); // using this instead of `+` to avoid overflow panic in debug
            let too_late_header = Header::with_frame_counter(23456789u64, late_count);
            assert_eq!(validator.validate(&too_late_header), Ok(()))
        }
    }
}