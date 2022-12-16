// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

#[cfg(test)]
pub(crate) fn bin2string(bin: &[u8]) -> String {
    bin.iter().map(|x| format!("{x:08b} ")).collect()
}

#[cfg(test)]
pub mod test {
    use super::bin2string;
    use pretty_assertions::assert_eq;

    #[allow(clippy::missing_panics_doc)]
    pub fn assert_bytes_eq(l: &[u8], r: &[u8]) {
        assert_eq!(bin2string(l), bin2string(r));
    }
}
