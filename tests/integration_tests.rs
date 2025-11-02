//! Integration tests for rustnet

#[cfg(target_os = "linux")]
mod linux_tests {
    use rustnet_monitor::network::platform::create_process_lookup;

    #[test]
    fn test_process_lookup_creation() {
        // Test that we can create a process lookup without panicking
        let result = create_process_lookup(false);
        assert!(result.is_ok(), "Should be able to create process lookup");
    }

    #[cfg(feature = "ebpf")]
    #[test]
    fn test_ebpf_enhanced_lookup() {
        // This test verifies that the enhanced lookup can be created
        // when eBPF feature is enabled
        let result = create_process_lookup(false);
        assert!(
            result.is_ok(),
            "Enhanced lookup should be created successfully"
        );

        // Just verify we got a lookup instance that can be refreshed
        let lookup = result.unwrap();
        let refresh_result = lookup.refresh();
        assert!(refresh_result.is_ok(), "Refresh should work");
    }
}

#[cfg(target_os = "macos")]
mod other_platforms {
    use rustnet_monitor::network::platform::create_process_lookup;

    #[test]
    fn test_other_platform_lookup() {
        // Test that other platforms can create process lookups
        let result = create_process_lookup(false);
        assert!(result.is_ok(), "Should work on other platforms too");
    }
}
