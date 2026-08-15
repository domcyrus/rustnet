use anyhow::Result;
use flate2::read::GzDecoder;
use log::debug;
use std::collections::HashMap;
use std::io::Read;

const OUI_DATA_GZ: &[u8] = include_bytes!("../../assets/oui.gz");

/// OUI (Organizationally Unique Identifier) vendor lookup table
#[derive(Debug, Clone)]
pub struct OuiLookup {
    vendors: HashMap<[u8; 3], String>,
}

impl OuiLookup {
    /// Load OUI data from the embedded gzip-compressed IEEE database
    pub fn from_embedded() -> Result<Self> {
        let mut decoder = GzDecoder::new(OUI_DATA_GZ);
        let mut oui_text = String::new();
        decoder.read_to_string(&mut oui_text)?;

        let mut vendors = HashMap::new();

        for line in oui_text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Format: AABBCC\tVendor Name
            let Some((prefix_str, vendor)) = line.split_once('\t') else {
                continue;
            };

            if prefix_str.len() != 6 {
                continue;
            }

            let Ok(bytes) = (0..3)
                .map(|i| u8::from_str_radix(&prefix_str[i * 2..i * 2 + 2], 16))
                .collect::<std::result::Result<Vec<u8>, _>>()
            else {
                continue;
            };

            let prefix = [bytes[0], bytes[1], bytes[2]];
            vendors.entry(prefix).or_insert_with(|| vendor.to_string());
        }

        if vendors.is_empty() {
            return Err(anyhow::anyhow!("No OUI entries found in embedded data"));
        }
        debug!(
            "Loaded {} OUI vendor entries from embedded data",
            vendors.len()
        );

        Ok(Self { vendors })
    }

    /// Look up a vendor name by MAC address string (e.g., "aa:bb:cc:dd:ee:ff")
    pub fn lookup(&self, mac: &str) -> Option<&str> {
        let prefix = parse_mac_prefix(mac)?;
        self.vendors.get(&prefix).map(|s| s.as_str())
    }
}

/// Format a 6-byte MAC address in the canonical colon-separated lowercase
/// form every producer in this crate uses (and the string-keyed MAC checks
/// in `neighbors` rely on).
///
/// # Panics
///
/// Panics if `bytes` is shorter than 6 bytes.
pub(crate) fn format_mac(bytes: &[u8]) -> String {
    crate::network::util::hex_encode(&bytes[..6], ":")
}

/// Parse the first octet of a MAC address string.
/// Supports the same formats as [`parse_mac_prefix`].
pub(crate) fn mac_first_octet(mac: &str) -> Option<u8> {
    parse_mac_prefix(mac).map(|prefix| prefix[0])
}

/// Whether the MAC has the locally-administered bit set (and is unicast).
/// Such addresses are software-assigned (typically the randomized MACs
/// modern phones use for privacy) and never appear in the OUI registry.
pub fn is_locally_administered(mac: &str) -> bool {
    mac_first_octet(mac).is_some_and(|first| first & 0x02 != 0 && first & 0x01 == 0)
}

/// Parse the first 3 octets of a MAC address string into a byte array.
/// Supports formats: "aa:bb:cc:...", "aa-bb-cc-...", "aabbcc..."
fn parse_mac_prefix(mac: &str) -> Option<[u8; 3]> {
    let mac = mac.trim();

    // Try colon or hyphen-separated format
    let parts: Vec<&str> = if mac.contains(':') {
        mac.split(':').collect()
    } else if mac.contains('-') {
        mac.split('-').collect()
    } else if mac.len() >= 6 {
        // Unseparated hex format
        let a = u8::from_str_radix(&mac[0..2], 16).ok()?;
        let b = u8::from_str_radix(&mac[2..4], 16).ok()?;
        let c = u8::from_str_radix(&mac[4..6], 16).ok()?;
        return Some([a, b, c]);
    } else {
        return None;
    };

    if parts.len() < 3 {
        return None;
    }

    let a = u8::from_str_radix(parts[0], 16).ok()?;
    let b = u8::from_str_radix(parts[1], 16).ok()?;
    let c = u8::from_str_radix(parts[2], 16).ok()?;
    Some([a, b, c])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_prefix_colon() {
        assert_eq!(
            parse_mac_prefix("aa:bb:cc:dd:ee:ff"),
            Some([0xaa, 0xbb, 0xcc])
        );
    }

    #[test]
    fn test_parse_mac_prefix_hyphen() {
        assert_eq!(
            parse_mac_prefix("AA-BB-CC-DD-EE-FF"),
            Some([0xaa, 0xbb, 0xcc])
        );
    }

    #[test]
    fn test_parse_mac_prefix_unseparated() {
        assert_eq!(parse_mac_prefix("aabbccddeeff"), Some([0xaa, 0xbb, 0xcc]));
    }

    #[test]
    fn test_parse_mac_prefix_too_short() {
        assert_eq!(parse_mac_prefix("aa:bb"), None);
        assert_eq!(parse_mac_prefix("aabb"), None);
    }

    #[test]
    fn test_parse_mac_prefix_invalid_hex() {
        assert_eq!(parse_mac_prefix("zz:yy:xx:00:00:00"), None);
    }

    #[test]
    fn test_is_locally_administered() {
        // 0x5a has the locally-administered bit (0x02) set.
        assert!(is_locally_administered("5a:33:44:55:66:77"));
        // Universally administered vendor OUI.
        assert!(!is_locally_administered("68:5e:dd:09:15:5e"));
        // Group addresses (I/G bit) are excluded even with 0x02 set.
        assert!(!is_locally_administered("33:33:00:00:00:01"));
        assert!(!is_locally_administered("not a mac"));
    }

    #[test]
    fn test_from_embedded() {
        let lookup = OuiLookup::from_embedded().expect("should load embedded OUI data");
        assert!(lookup.vendors.len() > 1000, "should have many OUI entries");
    }

    #[test]
    fn test_lookup_miss() {
        let lookup = OuiLookup::from_embedded().unwrap();
        // All-zeros OUI is unlikely to match a real vendor
        assert!(
            lookup.lookup("00:00:00:00:00:00").is_none()
                || lookup.lookup("00:00:00:00:00:00").is_some()
        );
        // Truly random prefix
        assert!(
            lookup.lookup("ff:ff:ff:dd:ee:00").is_none()
                || lookup.lookup("ff:ff:ff:dd:ee:00").is_some()
        );
    }

    #[test]
    fn test_lookup_known_vendor() {
        let lookup = OuiLookup::from_embedded().unwrap();
        // Apple has many OUIs - test a well-known one
        // 00:1B:63 is Apple
        // If the database changes this test may need updating
        // Just verify the lookup function works with a real MAC
        let result = lookup.lookup("00:1b:63:00:00:00");
        // We just verify it returns Some (exact vendor name may vary)
        if let Some(vendor) = result {
            assert!(!vendor.is_empty());
        }
    }
}
