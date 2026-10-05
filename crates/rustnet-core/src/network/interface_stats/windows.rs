//! Windows IP Helper API interface stats.

use super::{InterfaceStats, InterfaceStatsProvider};
use std::collections::HashMap;
use std::io;
use std::time::SystemTime;

use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;

/// Match Npcap's GUID device name to the alias used by interface counters.
/// Resolve once when starting the sampler, not on every graph refresh.
pub fn capture_interface_alias(name: &str) -> Option<String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceGuidToLuid, ConvertInterfaceLuidToAlias,
    };
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows::core::GUID;

    let guid = name.strip_prefix(r"\Device\NPF_{")?.strip_suffix('}')?;
    let guid = GUID::from_u128(u128::from_str_radix(&guid.replace('-', ""), 16).ok()?);
    let mut luid = NET_LUID_LH::default();
    let mut alias = [0u16; 257];
    // Both calls write only to the stack buffers passed here.
    unsafe {
        ConvertInterfaceGuidToLuid(&guid, &mut luid).ok().ok()?;
        ConvertInterfaceLuidToAlias(&luid, &mut alias).ok().ok()?;
    }
    let alias = String::from_utf16_lossy(&alias)
        .trim_end_matches('\0')
        .to_string();
    (!alias.is_empty()).then_some(alias)
}

/// Windows-specific implementation using IP Helper API
pub struct WindowsStatsProvider;

impl InterfaceStatsProvider for WindowsStatsProvider {
    fn get_all_stats(&self) -> Result<Vec<InterfaceStats>, io::Error> {
        unsafe {
            let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();

            let result = GetIfTable2(&mut table);
            if result.is_err() {
                return Err(io::Error::other(format!(
                    "GetIfTable2 failed with error code: {:?}",
                    result
                )));
            }

            let table_ref = match table.as_ref() {
                Some(t) => t,
                None => return Err(io::Error::other("Failed to get interface table")),
            };

            let num_entries = table_ref.NumEntries as usize;
            // Use LUID as key for deduplication since it's unique per interface
            let mut stats_map: HashMap<u64, InterfaceStats> = HashMap::new();

            for i in 0..num_entries {
                let row = &*table_ref.Table.as_ptr().add(i);

                // Convert interface alias (friendly name) to string
                let name = String::from_utf16_lossy(&row.Alias)
                    .trim_end_matches('\0')
                    .to_string();

                if name.is_empty() {
                    continue;
                }

                // Skip virtual/filter interfaces by name patterns
                // These are NDIS filter drivers, WFP filters, and virtual adapters
                // Always skip these as they just mirror the physical interface
                let name_lower = name.to_lowercase();
                if name_lower.contains("-npcap")
                    || name_lower.contains("-wfp")
                    || name_lower.contains("-qos")
                    || name_lower.contains("-native")
                    || name_lower.contains("-virtual")
                    || name_lower.contains("-packet")
                    || name_lower.contains("lightweight filter")
                    || name_lower.contains("mac layer")
                {
                    continue;
                }

                // Skip "Local Area Con" with zero traffic (these are usually disconnected adapters)
                let total_traffic =
                    row.InOctets + row.OutOctets + row.InUcastPkts + row.OutUcastPkts;
                if name_lower.starts_with("local area con") && total_traffic == 0 {
                    continue;
                }

                // Skip interfaces that are not operationally up
                // But allow them if they have any traffic statistics
                let has_traffic = row.InOctets > 0 || row.OutOctets > 0;
                if row.OperStatus != IfOperStatusUp && !has_traffic {
                    continue;
                }

                let stat = InterfaceStats {
                    interface_name: name.clone(),
                    rx_bytes: row.InOctets,
                    tx_bytes: row.OutOctets,
                    rx_packets: row.InUcastPkts + row.InNUcastPkts,
                    tx_packets: row.OutUcastPkts + row.OutNUcastPkts,
                    rx_errors: row.InErrors,
                    tx_errors: row.OutErrors,
                    rx_dropped: row.InDiscards,
                    tx_dropped: row.OutDiscards,
                    collisions: 0, // Not available on modern Windows interfaces
                    timestamp: SystemTime::now(),
                };

                let luid_value = row.InterfaceLuid.Value;
                stats_map.insert(luid_value, stat);
            }

            FreeMibTable(table.cast());

            let stats_vec: Vec<InterfaceStats> = stats_map.into_values().collect();
            log::debug!(
                "Windows interface stats collected: {} interfaces",
                stats_vec.len()
            );
            for stat in &stats_vec {
                log::debug!(
                    "  {} - RX: {} bytes, TX: {} bytes",
                    stat.interface_name,
                    stat.rx_bytes,
                    stat.tx_bytes
                );
            }

            Ok(stats_vec)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_list_interfaces() {
        let provider = WindowsStatsProvider;
        let stats = provider.get_all_stats().expect("Failed to list interfaces");
        assert!(!stats.is_empty(), "Expected at least one interface");
        for stat in stats {
            assert!(!stat.interface_name.is_empty());
        }
    }
}
