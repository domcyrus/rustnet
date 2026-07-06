//! Live integration test for the Kubernetes resolver.
//!
//! Runs only on Linux with the `kubernetes` feature enabled, and only when the
//! current process is inside a kubepods cgroup. On any other host the test
//! reports `Ok` after a single quick probe so CI on non-K8s machines stays
//! green. The intended invocation is from a debug pod on a Kubernetes node:
//!
//!     cargo test --features kubernetes --test kubernetes_resolver_live -- --nocapture

#![cfg(all(target_os = "linux", feature = "kubernetes"))]

use rustnet_monitor::network::kubernetes::{KubernetesResolver, lookup_for_pid};

#[test]
fn resolver_picks_up_pod_uid_for_current_process() {
    let cg = std::fs::read_to_string("/proc/self/cgroup").expect("read /proc/self/cgroup");
    eprintln!("===/proc/self/cgroup===\n{cg}");

    if !cg.contains("kubepods") {
        eprintln!(
            "Not inside a kubepods cgroup — skipping live assertion. This is expected on non-Kubernetes hosts."
        );
        return;
    }

    let pid = std::process::id();
    let cgroup = lookup_for_pid(pid).expect("parser recognised current kubepods cgroup");
    eprintln!("===CgroupInfo for pid {pid}===\n{cgroup:?}");
    assert!(
        cgroup.pod_uid.is_some(),
        "pod_uid should be populated for a kubepods process"
    );
    assert!(
        cgroup.container_id.is_some(),
        "container_id should be populated for a kubepods process"
    );

    let resolver = KubernetesResolver::new();
    let info = resolver
        .enrich(pid)
        .expect("resolver returned None for current pid inside kubepods");
    eprintln!("===K8sInfo===\n{info:?}");
    assert!(info.pod_uid.is_some(), "K8sInfo.pod_uid populated");
    assert!(
        info.container_id.is_some(),
        "K8sInfo.container_id populated"
    );
    assert!(info.cgroup_path.is_some(), "K8sInfo.cgroup_path populated");

    // Second call should hit the in-memory cache.
    let cached = resolver
        .enrich(pid)
        .expect("cached lookup returned None unexpectedly");
    assert_eq!(cached.pod_uid, info.pod_uid);
}
