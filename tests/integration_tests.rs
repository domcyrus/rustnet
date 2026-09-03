//! Integration tests for rustnet

#[cfg(target_os = "linux")]
mod linux_tests {
    use rustnet_monitor::network::platform::create_process_lookup;

    #[test]
    fn test_process_lookup_creation() {
        let result = create_process_lookup(false);
        assert!(result.is_ok(), "Should be able to create process lookup");
    }

    #[cfg(feature = "ebpf")]
    #[test]
    fn test_ebpf_enhanced_lookup() {
        let result = create_process_lookup(false);
        assert!(
            result.is_ok(),
            "Enhanced lookup should be created successfully"
        );

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
        let result = create_process_lookup(false);
        assert!(result.is_ok(), "Should work on other platforms too");
    }
}
