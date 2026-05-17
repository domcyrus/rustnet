#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
NDK_ROOT=${RUSTNET_ANDROID_NDK:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}
ANDROID_TARGET=${RUSTNET_ANDROID_TARGET:-aarch64-linux-android}
ANDROID_API=${RUSTNET_ANDROID_API:-}
LIBPCAP_ROOT=${RUSTNET_ANDROID_LIBPCAP_ROOT:-${ROOT_DIR}/../libpcap-install}
LIBPCAP_VER=${RUSTNET_ANDROID_LIBPCAP_VER:-1.10.5}
ENABLE_ANDROID_EBPF=${RUSTNET_ANDROID_ENABLE_EBPF:-1}
ANDROID_EBPF_CONFIG="${ROOT_DIR}/.cargo/android-ebpf-config.toml"

if [[ -z "${NDK_ROOT}" ]]; then
    cat >&2 <<'EOF'
Android NDK path is required.

Set one of:
  RUSTNET_ANDROID_NDK
  ANDROID_NDK_HOME
  ANDROID_NDK_ROOT
EOF
    exit 1
fi

find_prebuilt_dir() {
    local prebuilt_root="${NDK_ROOT}/toolchains/llvm/prebuilt"
    local host_tag=${RUSTNET_ANDROID_HOST_TAG:-}

    if [[ -n "${host_tag}" ]]; then
        echo "${prebuilt_root}/${host_tag}"
        return
    fi

    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64) host_tag="linux-x86_64" ;;
        Darwin-arm64) host_tag="darwin-x86_64" ;;
        Darwin-x86_64) host_tag="darwin-x86_64" ;;
        *)
            host_tag=$(find "${prebuilt_root}" -mindepth 1 -maxdepth 1 -type d | head -n 1)
            echo "${host_tag}"
            return
            ;;
    esac

    echo "${prebuilt_root}/${host_tag}"
}

default_api_for_target() {
    case "$1" in
        aarch64-linux-android|x86_64-linux-android|armv7-linux-androideabi|i686-linux-android) echo 24 ;;
        *) echo 24 ;;
    esac
}

PREBUILT_DIR=$(find_prebuilt_dir)
TOOLCHAIN_DIR="${PREBUILT_DIR}/bin"

if [[ ! -d "${TOOLCHAIN_DIR}" ]]; then
    echo "Android NDK toolchain directory not found: ${TOOLCHAIN_DIR}" >&2
    exit 1
fi

if [[ -z "${ANDROID_API}" ]]; then
    ANDROID_API=$(default_api_for_target "${ANDROID_TARGET}")
fi

if (( ANDROID_API < 24 )); then
    echo "Android API ${ANDROID_API} is too low for current libpcap/pnet support; using 24 instead." >&2
    ANDROID_API=24
fi

CLANG="${TOOLCHAIN_DIR}/${ANDROID_TARGET}${ANDROID_API}-clang"
AR="${TOOLCHAIN_DIR}/llvm-ar"

if [[ ! -x "${CLANG}" ]]; then
    echo "Android clang not found: ${CLANG}" >&2
    echo "Available ${ANDROID_TARGET} toolchains:" >&2
    find "${TOOLCHAIN_DIR}" -maxdepth 1 -type f -name "${ANDROID_TARGET}*-clang" -printf '  %f\n' | sort >&2 || true
    exit 1
fi

if [[ ! -x "${AR}" ]]; then
    echo "Android llvm-ar not found: ${AR}" >&2
    exit 1
fi

if [[ ! -d "${LIBPCAP_ROOT}" ]]; then
    echo "Android libpcap root not found: ${LIBPCAP_ROOT}" >&2
    exit 1
fi

if [[ ! -d "${LIBPCAP_ROOT}/lib" ]]; then
    echo "Android libpcap library directory not found: ${LIBPCAP_ROOT}/lib" >&2
    exit 1
fi

if [[ ! -d "${LIBPCAP_ROOT}/include" ]]; then
    echo "Android libpcap include directory not found: ${LIBPCAP_ROOT}/include" >&2
    exit 1
fi

target_env=${ANDROID_TARGET//-/_}
export "CC_${target_env}=${CLANG}"
export "AR_${target_env}=${AR}"
export "CARGO_TARGET_${target_env^^}_LINKER=${CLANG}"
export "CARGO_TARGET_${target_env^^}_AR=${AR}"
export LIBPCAP_LIBDIR="${LIBPCAP_ROOT}/lib"
export LIBPCAP_VER="${LIBPCAP_VER}"

cat >&2 <<EOF
Android target: ${ANDROID_TARGET}
Android API: ${ANDROID_API}
NDK prebuilt: ${PREBUILT_DIR}
Clang: ${CLANG}
libpcap: ${LIBPCAP_ROOT}
android-ebpf: ${ENABLE_ANDROID_EBPF}
EOF

args=("$@")

has_no_default_features=0
has_features=0
for arg in "${args[@]}"; do
    case "${arg}" in
        --no-default-features) has_no_default_features=1 ;;
        --features|--all-features) has_features=1 ;;
        --features=*) has_features=1 ;;
    esac
done

if [[ ${has_no_default_features} -eq 0 ]]; then
    args+=(--no-default-features)
fi

if [[ ${ENABLE_ANDROID_EBPF} == 1 && ${has_features} -eq 0 ]]; then
    args+=(--features android-ebpf)
fi

restore_lockfile() {
    if [[ -n "${lock_backup_path:-}" && -f "${lock_backup_path}" ]]; then
        mv "${lock_backup_path}" "${ROOT_DIR}/Cargo.lock"
    fi
}

if [[ ${ENABLE_ANDROID_EBPF} == 1 ]]; then
    args+=(--config "${ANDROID_EBPF_CONFIG}")

    if [[ -f "${ROOT_DIR}/Cargo.lock" ]]; then
        lock_backup_path=$(mktemp "${ROOT_DIR}/Cargo.lock.android-ebpf.XXXXXX")
        cp "${ROOT_DIR}/Cargo.lock" "${lock_backup_path}"
        trap restore_lockfile EXIT
    fi
fi

cargo "${args[@]}"
