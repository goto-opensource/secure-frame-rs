use super::BasicHeader;

pub type BasicKeyId = u8;
pub type ExtendedKeyId = u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum KeyId {
    Basic(BasicKeyId),
    Extended(ExtendedKeyId),
}

impl Default for KeyId {
    fn default() -> Self {
        KeyId::Basic(0)
    }
}

impl From<u8> for KeyId {
    fn from(value: u8) -> Self {
        Self::Basic(value)
    }
}

impl From<u64> for KeyId {
    fn from(id: u64) -> Self {
        if id <= BasicHeader::MAX_KEY_ID {
            let sender_id_u8: u8 = id as u8;
            KeyId::Basic(sender_id_u8)
        } else {
            KeyId::Extended(id)
        }
    }
}

#[cfg(test)]
mod test {
    use super::KeyId;

    fn create_valid_sender_id_asserted(id: u64) -> KeyId {
        KeyId::from(id)
    }

    #[test]
    fn create_basic_sender_id_for_ge0_l8() {
        let mut sender_id = create_valid_sender_id_asserted(0);
        assert!(matches!(sender_id, KeyId::Basic(0)));

        sender_id = create_valid_sender_id_asserted(7);
        assert!(matches!(sender_id, KeyId::Basic(7)));
    }

    #[test]
    fn create_extended_sender_id_for_ge8() {
        let mut sender_id = create_valid_sender_id_asserted(8);
        assert!(matches!(sender_id, KeyId::Extended(8)));

        sender_id = create_valid_sender_id_asserted(u64::MAX);
        assert!(matches!(sender_id, KeyId::Extended(u64::MAX)));
    }
}
