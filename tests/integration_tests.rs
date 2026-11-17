//! Integration tests for rustnet

#[cfg(target_os = "linux")]
mod linux_tests {
    use rustnet_host::create_process_lookup;

    #[test]
    fn test_process_lookup_creation_and_refresh() {
        let lookup = create_process_lookup(false).expect("create process lookup");
        lookup.refresh().expect("refresh process lookup");
    }
}

#[cfg(target_os = "macos")]
mod other_platforms {
    use rustnet_host::create_process_lookup;

    #[test]
    fn test_other_platform_lookup() {
        let result = create_process_lookup(false);
        assert!(result.is_ok(), "Should work on other platforms too");
    }
}
