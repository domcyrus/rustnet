# Kubernetes capture and evidence

[简体中文](KUBERNETES.zh-CN.md) | [日本語](KUBERNETES.ja.md)

## Short flows (unreleased)

With Linux eBPF and cgroup v2, RustNet retains the container and parent pod cgroup names at each socket event. Standard systemd and cgroupfs Kubernetes layouts can therefore be attributed after the process exits, even when the flow starts and ends between the five-second namespace scans. Lookup tries the observed endpoint orientation first, including wildcard source addresses, then the reverse orientation, so host capture can match sockets in a pod network namespace. Pod and container names are resolved from the existing kubelet log metadata. The recorded pod UID and container ID take precedence over cached PID metadata.

The socket map holds up to 32,768 tuples and evicts older records under pressure. Existing cleanup removes records more than 60 seconds old on a 30-second cleanup cadence. A newer event for the same tuple replaces its owner. Retained events supply attribution for captured packets; they do not reconstruct packets missed by capture. The event contains two cgroup names, so `cgroup_path` is omitted when enrichment uses this source.

Cgroup v1, nested cgroups below the container, unavailable eBPF, and unreadable or truncated cgroup names still rely on procfs discovery and can miss processes that exit between scans. Human-readable names require the kubelet log metadata to remain available.

## Export follow-up

The kubectl plugin lives in a separate repository: [domcyrus/kubectl-rustnet](https://github.com/domcyrus/kubectl-rustnet). Its coordinated [`--output-dir` follow-up](https://github.com/domcyrus/kubectl-rustnet/issues/20) must stop capture gracefully, flush and copy JSONL or PCAPNG evidence (including any sidecar), and only then delete the debug pod. If copying fails, it must preserve the pod and report recovery instructions.

This flag is planned in the plugin, not implemented by this RustNet change. Until it ships, copy exports with `kubectl cp` while the debug pod is still running, before quitting the session. See the [usage guide](USAGE.md#--kubernetes-mode-optional-feature) for Kubernetes setup.
