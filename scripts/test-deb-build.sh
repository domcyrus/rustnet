#!/bin/bash
set -e

UBUNTU_RELEASE=${1:-noble}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Testing Debian package build for Ubuntu $UBUNTU_RELEASE"
echo "=================================================="

# Build the Docker container
docker build -t rustnet-deb-test:$UBUNTU_RELEASE -f - "$PROJECT_DIR" <<EOF
FROM ubuntu:$UBUNTU_RELEASE

# Install build dependencies
RUN apt-get update && apt-get install -y \\
    debhelper \\
    devscripts \\
    dpkg-dev \\
    rustup \\
    libpcap-dev \\
    libelf-dev \\
    elfutils \\
    zlib1g-dev \\
    clang \\
    llvm \\
    pkg-config \\
    lintian \\
    file

WORKDIR /build
COPY . /build/

# Build the source package
RUN echo "Building source package..." && \\
    debuild -S -sa -d -us -uc

# Build the binary package (simulates what Launchpad does)
RUN echo "Building binary package..." && \\
    cd .. && \\
    dpkg-source -x rustnet-monitor_*.dsc extracted && \\
    cd extracted && \\
    dpkg-buildpackage -b -uc -us

# List the built packages
RUN echo "Built packages:" && \\
    ls -lh /build/../*.deb || true

# Run lintian on the package
RUN echo "Running lintian checks..." && \\
    lintian /build/../*.deb || true

# Test the package contents
RUN echo "Package contents:" && \\
    dpkg-deb -c /build/../rustnet_*.deb

CMD ["/bin/bash"]
EOF

echo ""
echo "Build completed successfully!"
echo ""
echo "To extract the .deb file, run:"
echo "  docker create --name rustnet-deb-extract rustnet-deb-test:$UBUNTU_RELEASE"
echo "  docker cp rustnet-deb-extract:/build/../rustnet_*.deb ."
echo "  docker rm rustnet-deb-extract"
