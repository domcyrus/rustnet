//! Smoke-test binary: takes a PID on the command line, runs the Kubernetes
//! resolver against `/proc/<pid>/cgroup`, and prints the resolver's view.
//! Intended for running inside a `hostPID: true` pod on a Kubernetes node:
//!
//!     cargo build --release --features kubernetes --example k8s_resolver_check
//!     ./k8s_resolver_check $(pidof nginx | awk '{print $1}')

#[cfg(feature = "kubernetes")]
fn main() {
    let pid: u32 = std::env::args()
        .nth(1)
        .expect("usage: k8s_resolver_check <pid>")
        .parse()
        .expect("PID must be an integer");

    let path = format!("/proc/{pid}/cgroup");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("read {path}: {e}");
        std::process::exit(2);
    });
    println!("--- /proc/{pid}/cgroup ---");
    println!("{raw}");

    let resolver = rustnet_monitor::network::kubernetes::KubernetesResolver::new();
    match resolver.enrich(pid) {
        Some(info) => {
            println!("--- resolver output ---");
            println!("{info:#?}");
            // Mirror the JSON shape that log_connection_event would emit.
            let mut obj = serde_json::Map::new();
            if let Some(v) = info.pod_uid {
                obj.insert("pod_uid".into(), serde_json::json!(v));
            }
            if let Some(v) = info.container_id {
                obj.insert("container_id".into(), serde_json::json!(v));
            }
            if let Some(v) = info.cgroup_path {
                obj.insert("cgroup_path".into(), serde_json::json!(v));
            }
            println!("--- JSONL 'kubernetes' block ---");
            println!("{}", serde_json::to_string(&obj).unwrap());
        }
        None => {
            println!("--- resolver returned None (no kubepods cgroup) ---");
            std::process::exit(1);
        }
    }
}

#[cfg(not(feature = "kubernetes"))]
fn main() {
    eprintln!("Build with --features kubernetes");
    std::process::exit(2);
}
