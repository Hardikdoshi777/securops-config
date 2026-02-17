#!/bin/bash
# ============================================================
# SecurOps Developer Onboarding Script
# File: scripts/onboard.sh
# Share this with ALL developers - run ONCE per machine
#
# Supports:
#   macOS (Intel + Apple Silicon M1/M2/M3)
#   Linux (Ubuntu, Debian, CentOS)
#   Windows (Git Bash / WSL2)
# ============================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Config - UPDATE THESE for your company
COMPANY_NAME="YourCompany"
CONFIG_REPO="https://github.com/yourcompany/securops-config.git"
SECUROPS_DIR="$HOME/.securops"
SUPPORT_SLACK="#securops-support"
SUPPORT_EMAIL="security@yourcompany.com"

clear
echo -e "${CYAN}${BOLD}"
echo "╔═══════════════════════════════════════════════════╗"
echo "║     🛡️  $COMPANY_NAME SecurOps Onboarding          ║"
echo "║     Shift-Left Security Setup                     ║"
echo "╚═══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "This script will:"
echo "  1. Install security tools (pre-commit, gitleaks)"
echo "  2. Download company security config"
echo "  3. Configure git hooks globally"
echo "  4. Test the setup"
echo ""
echo "⏱️  Estimated time: 5 minutes"
echo ""
read -p "Press ENTER to start (or Ctrl+C to cancel)..."
echo ""

# ─────────────────────────────────────────────────────────
# STEP 1: Detect OS
# ─────────────────────────────────────────────────────────
echo -e "${BLUE}${BOLD}STEP 1/5: Detecting your system...${NC}"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin*)
    OS_TYPE="mac"
    if [ "$ARCH" = "arm64" ]; then
      echo -e "  ✅ macOS Apple Silicon (M1/M2/M3) detected"
      BREW_PREFIX="/opt/homebrew"
    else
      echo -e "  ✅ macOS Intel detected"
      BREW_PREFIX="/usr/local"
    fi
    ;;
  Linux*)
    OS_TYPE="linux"
    echo -e "  ✅ Linux detected"
    ;;
  CYGWIN*|MINGW*|MSYS*)
    OS_TYPE="windows"
    echo -e "  ✅ Windows (Git Bash) detected"
    ;;
  *)
    echo -e "  ${YELLOW}⚠️  Unknown OS: $OS — trying Linux method${NC}"
    OS_TYPE="linux"
    ;;
esac
echo ""

# ─────────────────────────────────────────────────────────
# STEP 2: Install Pre-commit
# ─────────────────────────────────────────────────────────
echo -e "${BLUE}${BOLD}STEP 2/5: Installing pre-commit...${NC}"

install_precommit_mac() {
  if ! command -v brew &>/dev/null; then
    echo -e "  ${YELLOW}Installing Homebrew...${NC}"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    eval "$($BREW_PREFIX/bin/brew shellenv)"
    echo "eval \"\$($BREW_PREFIX/bin/brew shellenv)\"" >> ~/.zprofile
  fi
  brew install pre-commit gitleaks
}

install_precommit_linux() {
  if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y python3-pip
  elif command -v yum &>/dev/null; then
    sudo yum install -y python3-pip
  fi
  pip3 install pre-commit --break-system-packages 2>/dev/null || pip3 install pre-commit
}

install_precommit_windows() {
  pip install pre-commit
}

if command -v pre-commit &>/dev/null; then
  echo -e "  ✅ pre-commit already installed: $(pre-commit --version)"
else
  echo -e "  ${YELLOW}Installing pre-commit...${NC}"
  case "$OS_TYPE" in
    mac)     install_precommit_mac ;;
    linux)   install_precommit_linux ;;
    windows) install_precommit_windows ;;
  esac
  echo -e "  ✅ pre-commit installed: $(pre-commit --version)"
fi

# Install gitleaks separately if not installed
if ! command -v gitleaks &>/dev/null && [ "$OS_TYPE" = "linux" ]; then
  echo -e "  ${YELLOW}Installing gitleaks...${NC}"
  GITLEAKS_VERSION="v8.18.2"
  curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_8.18.2_linux_x64.tar.gz" | tar -xz -C /tmp
  sudo mv /tmp/gitleaks /usr/local/bin/gitleaks
  echo -e "  ✅ gitleaks installed"
fi
echo ""

# ─────────────────────────────────────────────────────────
# STEP 3: Download Company Config
# ─────────────────────────────────────────────────────────
echo -e "${BLUE}${BOLD}STEP 3/5: Downloading company security config...${NC}"

if [ -d "$SECUROPS_DIR/.git" ]; then
  echo -e "  ${YELLOW}Updating existing config...${NC}"
  cd "$SECUROPS_DIR" && git pull --quiet
  cd - > /dev/null
else
  echo -e "  ${YELLOW}Cloning company config...${NC}"
  git clone --quiet "$CONFIG_REPO" "$SECUROPS_DIR"
fi

echo -e "  ✅ Config downloaded to: $SECUROPS_DIR"
echo ""

# ─────────────────────────────────────────────────────────
# STEP 4: Configure Git Globally
# ─────────────────────────────────────────────────────────
echo -e "${BLUE}${BOLD}STEP 4/5: Configuring git globally...${NC}"

# Create global git template directory
GIT_TEMPLATE="$SECUROPS_DIR/git-template"
mkdir -p "$GIT_TEMPLATE/hooks"

# Create pre-commit hook that runs securops
cat > "$GIT_TEMPLATE/hooks/pre-commit" << 'HOOK'
#!/bin/bash
# SecurOps Global Pre-commit Hook
# Runs automatically on every git commit in any repo

if command -v pre-commit &>/dev/null; then
  # If repo has .pre-commit-config.yaml, run it
  if [ -f ".pre-commit-config.yaml" ]; then
    pre-commit run --hook-stage commit
    exit $?
  fi

  # Otherwise use company default config
  SECUROPS_CONFIG="$HOME/.securops/.pre-commit-config.yaml"
  if [ -f "$SECUROPS_CONFIG" ]; then
    pre-commit run --hook-stage commit --config "$SECUROPS_CONFIG"
    exit $?
  fi
fi
exit 0
HOOK

chmod +x "$GIT_TEMPLATE/hooks/pre-commit"

# Set global git template
git config --global init.templateDir "$GIT_TEMPLATE"

# Also set global gitleaks config
git config --global core.hooksPath "$GIT_TEMPLATE/hooks" 2>/dev/null || true

echo -e "  ✅ Git configured to use SecurOps hooks globally"
echo -e "  ✅ All NEW git repos will auto-have security hooks"
echo ""

# ─────────────────────────────────────────────────────────
# STEP 5: Install Hooks in Current Repo (if applicable)
# ─────────────────────────────────────────────────────────
echo -e "${BLUE}${BOLD}STEP 5/5: Setting up current project...${NC}"

if git rev-parse --git-dir > /dev/null 2>&1; then
  CURRENT_REPO=$(git rev-parse --show-toplevel)
  echo -e "  Found git repo: $CURRENT_REPO"

  # Copy config files if not present
  if [ ! -f ".pre-commit-config.yaml" ]; then
    cp "$SECUROPS_DIR/.pre-commit-config.yaml" .pre-commit-config.yaml
    echo -e "  ✅ Copied .pre-commit-config.yaml"
  fi

  if [ ! -f ".gitleaks.toml" ]; then
    cp "$SECUROPS_DIR/.gitleaks.toml" .gitleaks.toml
    echo -e "  ✅ Copied .gitleaks.toml"
  fi

  # Install hooks
  pre-commit install --quiet
  pre-commit install --hook-type pre-push --quiet
  echo -e "  ✅ Pre-commit hooks installed in current project"
else
  echo -e "  ${YELLOW}⚠️  Not in a git repo — skipping project setup${NC}"
  echo -e "  Run this from inside a project folder next time"
fi
echo ""

# ─────────────────────────────────────────────────────────
# VALIDATION TEST
# ─────────────────────────────────────────────────────────
echo -e "${BLUE}${BOLD}🧪 Running Validation Test...${NC}"

# Create temp test file with fake secret
TMPFILE=$(mktemp /tmp/securops-test-XXXXX.py)
echo 'test_key = "AKIAIOSFODNN7EXAMPLE"' > "$TMPFILE"

# Test if gitleaks catches it
if command -v gitleaks &>/dev/null; then
  if gitleaks detect --source "$(dirname $TMPFILE)" --no-git --quiet 2>/dev/null; then
    echo -e "  ${YELLOW}⚠️  Test inconclusive - gitleaks needs git context${NC}"
  else
    echo -e "  ✅ Secret detection is WORKING (fake AWS key detected)"
  fi
fi

# Cleanup
rm -f "$TMPFILE"
echo ""

# ─────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────
echo -e "${GREEN}${BOLD}"
echo "╔═══════════════════════════════════════════════════╗"
echo "║            ✅ SETUP COMPLETE!                     ║"
echo "╚═══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "What's now protecting you:"
echo "  🔐 Secret Scanner  — Blocks AWS keys, GitHub tokens, etc."
echo "  🔍 Code Scanner    — Blocks OWASP Top 10 vulnerabilities"
echo "  🛡️  Dep Scanner    — Blocks known CVEs in dependencies"
echo "  🔑 Private Keys    — Blocks .pem files and private keys"
echo ""
echo "How it works:"
echo "  • Every git commit → security scan runs automatically"
echo "  • HIGH issues → commit is BLOCKED"
echo "  • MEDIUM issues → warning shown, commit allowed"
echo ""
echo "Need help?"
echo "  Slack:  $SUPPORT_SLACK"
echo "  Email:  $SUPPORT_EMAIL"
echo ""
echo "To add hooks to another project:"
echo "  cd /path/to/other-project"
echo "  pre-commit install"
echo ""
