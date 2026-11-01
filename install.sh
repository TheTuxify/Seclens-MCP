#!/usr/bin/env bash
set -euo pipefail

# SecLens-MCP Universal Installer for Linux & macOS
# Repository: https://github.com/thetuxify/seclens-mcp

REPO="thetuxify/seclens-mcp"
INSTALL_DIR="/usr/local/bin"
BIN_NAME="seclens-mcp"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
GOLD='\033[38;2;255;215;0m'
NC='\033[0m'

echo -e "${GOLD}"
echo "  ▄▀▀▄ █▀▀▄ ▀▀█▀▀ ▀█▀ █▀▀▀ █▀▀█ █▀▀█ █░░█ ▀█▀ ▀▀█▀▀ █░░█"
echo "  █▄▄█ █░░█ ░░█░░ ░█░ █░▀█ █▄▄▀ █▄▄█ ▀▄▄▀ ░█░ ░░█░░ ░▀▄▀"
echo "  ▀░░▀ ▀░░▀ ░░▀░░ ▀▀▀ ▀▀▀▀ ▀░▀▀ ▀░░▀ ░░▀░ ▀▀▀ ░░▀░░ ░░▀░"
echo -e "${NC}"
echo -e "${BLUE}=== SecLens-MCP Universal Installer (Linux & macOS) ===${NC}\n"

# 1. Detect OS & Architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
    linux)
        TARGET_OS="linux"
        ;;
    darwin)
        TARGET_OS="darwin"
        ;;
    *)
        echo -e "${RED}[!] Unsupported operating system: $OS${NC}"
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64)
        TARGET_ARCH="x86_64"
        ;;
    aarch64|arm64)
        TARGET_ARCH="aarch64"
        ;;
    *)
        echo -e "${RED}[!] Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

# For Linux x86_64, prefer standalone static musl binary (universal compatibility)
if [ "$TARGET_OS" = "linux" ] && [ "$TARGET_ARCH" = "x86_64" ]; then
    RELEASE_ASSET="seclens-mcp-linux-x86_64-musl.tar.gz"
else
    RELEASE_ASSET="seclens-mcp-${TARGET_OS}-${TARGET_ARCH}.tar.gz"
fi

echo -e "[*] Detected Platform: ${GREEN}${TARGET_OS} (${TARGET_ARCH})${NC}"
echo -e "[*] Target Asset: ${YELLOW}${RELEASE_ASSET}${NC}"

# 2. Resolve Installation Directory Permissions
if [ ! -w "$INSTALL_DIR" ]; then
    if [ "$EUID" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            SUDO="sudo"
        else
            INSTALL_DIR="$HOME/.local/bin"
            mkdir -p "$INSTALL_DIR"
            SUDO=""
        fi
    else
        SUDO=""
    fi
else
    SUDO=""
fi

echo -e "[*] Target Install Path: ${GOLD}${INSTALL_DIR}/${BIN_NAME}${NC}"

# 3. Download & Extract Release
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${RELEASE_ASSET}"
echo -e "[*] Downloading from: ${BLUE}${DOWNLOAD_URL}${NC} ..."

if command -v curl >/dev/null 2>&1; then
    if ! curl -sSL --fail "$DOWNLOAD_URL" -o "${TEMP_DIR}/${RELEASE_ASSET}"; then
        echo -e "${YELLOW}[!] Release asset not found on GitHub. Checking for local build...${NC}"
        LOCAL_BUILD="src/target/release/seclens-mcp"
        if [ -f "$LOCAL_BUILD" ]; then
            echo -e "${GREEN}[+] Found local release build: ${LOCAL_BUILD}${NC}"
            cp "$LOCAL_BUILD" "${TEMP_DIR}/${BIN_NAME}"
        else
            LOCAL_DEBUG="src/target/debug/seclens-mcp"
            if [ -f "$LOCAL_DEBUG" ]; then
                echo -e "${GREEN}[+] Found local debug build: ${LOCAL_DEBUG}${NC}"
                cp "$LOCAL_DEBUG" "${TEMP_DIR}/${BIN_NAME}"
            else
                echo -e "${RED}[!] Could not download release or find local build.${NC}"
                exit 1
            fi
        fi
    else
        tar -xzf "${TEMP_DIR}/${RELEASE_ASSET}" -C "$TEMP_DIR"
    fi
else
    echo -e "${RED}[!] curl is required to run the installer.${NC}"
    exit 1
fi

chmod +x "${TEMP_DIR}/${BIN_NAME}"
$SUDO cp "${TEMP_DIR}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"

echo -e "\n${GREEN}[✓] SecLens-MCP installed successfully to ${INSTALL_DIR}/${BIN_NAME}!${NC}"
echo -e "${GOLD}To verify installation, run:${NC}"
echo -e "  ${BIN_NAME} --version\n"
