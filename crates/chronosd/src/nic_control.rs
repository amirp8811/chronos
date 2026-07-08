//! NIC RSS/Toeplitz control command construction.
//!
//! This module does not execute privileged netlink/ethtool calls yet. It builds
//! validated command arguments so the runtime boundary is explicit and testable.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NicControlError {
    InvalidSaltLength { got: usize, expected: usize },
}

pub fn build_ethtool_toeplitz_args(
    interface: &str,
    salt: &[u8],
) -> Result<Vec<String>, NicControlError> {
    if salt.len() != 40 {
        return Err(NicControlError::InvalidSaltLength {
            got: salt.len(),
            expected: 40,
        });
    }
    let hex = salt.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok(vec![
        "-X".to_string(),
        interface.to_string(),
        "hkey".to_string(),
        hex,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn builds_ethtool_hkey_args() {
        let args = build_ethtool_toeplitz_args("eth0", &[0xAB; 40]).unwrap();
        assert_eq!(args[0], "-X");
        assert_eq!(args[1], "eth0");
        assert_eq!(args[2], "hkey");
        assert_eq!(args[3].len(), 80);
    }
    #[test]
    fn rejects_wrong_salt_length() {
        assert_eq!(
            build_ethtool_toeplitz_args("eth0", &[0; 4]),
            Err(NicControlError::InvalidSaltLength {
                got: 4,
                expected: 40
            })
        );
    }
}
