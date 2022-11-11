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
            last_frame_count: Cell::new(0.into())
        }
    }
}
impl FrameValidation for ReplayAttackProtection {
    fn validate(&self, header: &Header) -> Result<()> {
        let last_frame_count = self.last_frame_count.get();
        let current_frame_count = header.get_frame_counter();

        if current_frame_count > last_frame_count {
            self.last_frame_count.set(current_frame_count);
            Ok(())
        } else {
            let age: u64 = last_frame_count.value() - current_frame_count.value();

            if age > self.tolerance {
                Err(SframeError::FrameValidationFailed)
            } else {
                self.last_frame_count.set(current_frame_count);
                Ok(())
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
}
