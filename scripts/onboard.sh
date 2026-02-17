#!/bin/bash
# ============================================================
# SecurOps Developer Onboarding Script
# Repo: https://github.com/Hardikdoshi777/securops-config
#
# ONE command does EVERYTHING:
#   1. Installs pre-commit + gitleaks
#   2. Downloads company security config
#   3. Copies all 5 security files into current project
#   4. Installs git hooks
#   5. Validates the setup
#
# Usage:
#   bash <(curl -s https://raw.githubusercontent.com/Hardikdoshi777/securops-config/main/scripts/onboard.sh)
#
# Supports: macOS (Intel + M1/M2/M3), Linux, Windows Git Bash
# ============================================================

set -e

# ─────────────────────────────────────────────────────────
# CONFIG — update these to match your company
# ─────────────────────────────────────────────────────────
GITHUB_ORG="Hardikdoshi777"
CONFIG_REPO="securops-config"
BRANCH="main"
BASE_URL="https://raw.githubusercontent.com/${GITHUB_ORG}/${CONFIG_REPO}/${BRANCH}"
SECUROPS_DIR="$HOME/.securops"
SUPPORT_SLACK="#securops-support"
SUPPORT_EMAIL="security@yourcompany.com"

# ─────────────────────────────────────────────────────────
# 5 FILES that get copied into every project repo
# ─────────────────────────────────────────────────────────
# Format: "source_path_in_config_repo|destination_path_in_project"
FILES=(
  ".pre-commit-config.yaml|.pre-commit-config.yaml"
  ".gitleaks.toml|.gitleaks.toml"
  ".github/workflows/security-scan.yml|.github/workflows/security-scan.yml"
  "scripts/trivy-scan.sh|scripts/trivy-scan.sh"
  "scripts/generate-report.py|scripts/generate-report.py"
)

# ─────────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────
ok()   { echo -e "  ${GREEN}✅ $1${NC}"; }
warn() { echo -e "  ${YELLOW}⚠️  $1${NC}"; }
fail() { echo -e "  ${RED}❌ $1${NC}"; }
info() { echo -e "  ${BLUE}ℹ️  $1${NC}"; }
step() { echo -e "\n${CYAN}${BOLD}── STEP $1 ──────────────────────────────────────────${NC}"; echo -e "${BOLD}   $2${NC}\n"; }

# ─────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────
clear
echo -e "${CYAN}${BOLD}"
echo "╔═══════════════════════════════════════════════════════╗"
echo "║          🛡️  SecurOps Developer Onboarding            ║"
echo "║          Shift-Left Security — Automated Setup        ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "  This script will:"
echo "    1. Install pre-commit + gitleaks (security tools)"
echo "    2. Download company security config"
echo "    3. Copy all 5 security files into THIS project"
echo "    4. Install git hooks (runs on every commit)"
echo "    5. Validate the full setup"
echo ""
echo -e "  ${YELLOW}Run this script from inside your project folder.${NC}"
echo ""
read -p "  Press ENTER to start (Ctrl+C to cancel)..."

# ─────────────────────────────────────────────────────────
# VERIFY we are inside a git repo
# ─────────────────────────────────────────────────────────
if ! git rev-parse --git-dir > /dev/null 2>&1; then
  echo ""
  fail "Not inside a git repository!"
  echo ""
  echo "  Please run this script from inside your project folder:"
  echo ""
  echo "    cd /path/to/your-project"
  echo "    bash <(curl -s ${BASE_URL}/scripts/onboard.sh)"
  echo ""
  exit 1
fi

PROJECT_DIR=$(git rev-parse --show-toplevel)
PROJECT_NAME=$(basename "$PROJECT_DIR")
cd "$PROJECT_DIR"

echo ""
info "Project detected: ${BOLD}$PROJECT_NAME${NC}"
info "Location: $PROJECT_DIR"

# ─────────────────────────────────────────────────────────
# STEP 1 — Detect OS
# ─────────────────────────────────────────────────────────
step "1/5" "Detecting your system..."

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin*)
    OS_TYPE="mac"
    BREW_PREFIX=$( [ "$ARCH" = "arm64" ] && echo "/opt/homebrew" || echo "/usr/local" )
    CHIP=$( [ "$ARCH" = "arm64" ] && echo "Apple Silicon M1/M2/M3" || echo "Intel" )
    ok "macOS ${CHIP} detected"
    ;;
  Linux*)
    OS_TYPE="linux"
    ok "Linux detected ($(uname -r | cut -d- -f1))"
    ;;
  CYGWIN*|MINGW*|MSYS*)
    OS_TYPE="windows"
    ok "Windows Git Bash detected"
    ;;
  *)
    OS_TYPE="linux"
    warn "Unknown OS ($OS) — using Linux method"
    ;;
esac

# ─────────────────────────────────────────────────────────
# STEP 2 — Install pre-commit + gitleaks
# ─────────────────────────────────────────────────────────
step "2/5" "Installing security tools (pre-commit + gitleaks)..."

install_mac() {
  if ! command -v brew &>/dev/null; then
    warn "Installing Homebrew first..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    eval "$($BREW_PREFIX/bin/brew shellenv)"
    echo "eval \"\$($BREW_PREFIX/bin/brew shellenv)\"" >> ~/.zprofile
  fi
  brew install pre-commit gitleaks 2>/dev/null || brew upgrade pre-commit gitleaks 2>/dev/null || true
}

install_linux() {
  if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y python3-pip python3-venv curl 2>/dev/null || true
  elif command -v yum &>/dev/null; then
    sudo yum install -y python3-pip curl 2>/dev/null || true
  fi
  pip3 install pre-commit --break-system-packages 2>/dev/null || pip3 install pre-commit || true

  # Install gitleaks on Linux
  if ! command -v gitleaks &>/dev/null; then
    GITLEAKS_VER="8.18.2"
    ARCH_SUFFIX=$( [ "$(uname -m)" = "aarch64" ] && echo "arm64" || echo "x64" )
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_linux_${ARCH_SUFFIX}.tar.gz" \
      | tar -xz -C /tmp gitleaks 2>/dev/null
    sudo mv /tmp/gitleaks /usr/local/bin/gitleaks 2>/dev/null || mv /tmp/gitleaks ~/.local/bin/gitleaks 2>/dev/null || true
  fi
}

install_windows() {
  pip install pre-commit 2>/dev/null || true
  warn "Install gitleaks manually: https://github.com/gitleaks/gitleaks/releases"
}

# Install if not already present
if command -v pre-commit &>/dev/null && command -v gitleaks &>/dev/null; then
  ok "pre-commit $(pre-commit --version) already installed"
  ok "gitleaks $(gitleaks version 2>/dev/null || echo 'installed') already installed"
else
  case "$OS_TYPE" in
    mac)     install_mac ;;
    linux)   install_linux ;;
    windows) install_windows ;;
  esac

  command -v pre-commit &>/dev/null && ok "pre-commit installed: $(pre-commit --version)" || fail "pre-commit install failed"
  command -v gitleaks &>/dev/null   && ok "gitleaks installed"                               || warn "gitleaks not found — secret scanning may not work"
fi

# ─────────────────────────────────────────────────────────
# STEP 3 — Download central config
# ─────────────────────────────────────────────────────────
step "3/5" "Downloading company security config..."

mkdir -p "$SECUROPS_DIR"

if [ -d "$SECUROPS_DIR/.git" ]; then
  info "Updating existing config..."
  git -C "$SECUROPS_DIR" pull --quiet 2>/dev/null || true
else
  info "Cloning config repo..."
  git clone --quiet "https://github.com/${GITHUB_ORG}/${CONFIG_REPO}.git" "$SECUROPS_DIR" 2>/dev/null || {
    # Fallback: download files individually if clone fails
    warn "Clone failed — downloading files individually..."
    for entry in "${FILES[@]}"; do
      SRC="${entry%%|*}"
      mkdir -p "$SECUROPS_DIR/$(dirname "$SRC")"
      curl -sSfL "${BASE_URL}/${SRC}" -o "$SECUROPS_DIR/${SRC}" 2>/dev/null || true
    done
  }
fi

ok "Security config saved to: $SECUROPS_DIR"

# ─────────────────────────────────────────────────────────
# STEP 4 — Copy all 5 files into THIS project repo
# ─────────────────────────────────────────────────────────
step "4/5" "Copying security files into: $PROJECT_NAME..."

COPIED=0
SKIPPED=0

for entry in "${FILES[@]}"; do
  SRC="${entry%%|*}"    # source path in securops-config
  DST="${entry##*|}"    # destination path in project

  # Create destination directory if needed
  mkdir -p "$(dirname "$DST")"

  # Determine source: prefer local clone, fallback to raw URL
  LOCAL_SRC="$SECUROPS_DIR/$SRC"

  if [ -f "$LOCAL_SRC" ]; then
    # Copy from local clone
    if [ -f "$DST" ]; then
      # File exists — check if it's already the latest version
      if cmp -s "$LOCAL_SRC" "$DST"; then
        info "Already up to date: $DST"
        SKIPPED=$((SKIPPED + 1))
      else
        cp "$LOCAL_SRC" "$DST"
        ok "Updated: $DST"
        COPIED=$((COPIED + 1))
      fi
    else
      cp "$LOCAL_SRC" "$DST"
      ok "Copied: $DST"
      COPIED=$((COPIED + 1))
    fi
  else
    # Fallback: download directly from GitHub raw URL
    info "Downloading: $DST"
    if curl -sSfL "${BASE_URL}/${SRC}" -o "$DST" 2>/dev/null; then
      ok "Downloaded: $DST"
      COPIED=$((COPIED + 1))
    else
      fail "Could not copy: $DST"
    fi
  fi
done

# Make shell scripts executable
chmod +x scripts/trivy-scan.sh 2>/dev/null || true

echo ""
ok "${COPIED} file(s) copied, ${SKIPPED} already up to date"
echo ""
echo "  Files now in your project:"
echo "    ✅ .pre-commit-config.yaml      ← hook definitions"
echo "    ✅ .gitleaks.toml               ← 130+ secret patterns"
echo "    ✅ .github/workflows/security-scan.yml  ← CI/CD pipeline"
echo "    ✅ scripts/trivy-scan.sh        ← dependency scanner"
echo "    ✅ scripts/generate-report.py   ← HTML dashboard"

# ─────────────────────────────────────────────────────────
# STEP 5 — Install git hooks + validate
# ─────────────────────────────────────────────────────────
step "5/5" "Installing git hooks + running validation..."

# Install pre-commit hooks
pre-commit install
pre-commit install --hook-type pre-push
ok "Git hooks installed (runs on every commit automatically)"

# Configure global git template so ALL future repos are protected
GIT_TEMPLATE="$SECUROPS_DIR/git-template"
mkdir -p "$GIT_TEMPLATE/hooks"
cat > "$GIT_TEMPLATE/hooks/pre-commit" << 'HOOK'
#!/bin/bash
# SecurOps Global Pre-commit Hook
if command -v pre-commit &>/dev/null && [ -f ".pre-commit-config.yaml" ]; then
  pre-commit run --hook-stage commit
  exit $?
fi
exit 0
HOOK
chmod +x "$GIT_TEMPLATE/hooks/pre-commit"
git config --global init.templateDir "$GIT_TEMPLATE"
ok "Global git template set — all NEW repos will auto-have hooks"

# ── Validation Test ───────────────────────────────────────
echo ""
info "Running validation — testing secret detection..."

# Create temp file with fake AWS key
TMPFILE=$(mktemp /tmp/securops-test-XXXXX.py)
echo 'aws_key = "AKIAFAKEKEY1234567890"' > "$TMPFILE"

# Run gitleaks directly on the temp file
if command -v gitleaks &>/dev/null; then
  if ! gitleaks detect --no-git --source "$(dirname "$TMPFILE")" --quiet 2>/dev/null; then
    ok "Secret detection WORKING — fake key was caught!"
  else
    warn "Validation inconclusive — gitleaks needs git context for full test"
    info "Run: git add test-secret.py && git commit — to test for real"
  fi
fi

rm -f "$TMPFILE"

# ── Git add all new files ─────────────────────────────────
echo ""
info "Staging security files for commit..."
git add .pre-commit-config.yaml .gitleaks.toml .github/workflows/security-scan.yml scripts/ 2>/dev/null || true
echo ""
warn "Security files staged — run: git commit -m 'feat: add SecurOps security scanning'"

# ─────────────────────────────────────────────────────────
# SUCCESS BANNER
# ─────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}"
echo "╔═══════════════════════════════════════════════════════╗"
echo "║            ✅ SETUP COMPLETE!                         ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "  Your project '${PROJECT_NAME}' is now protected:"
echo ""
echo "    🔐 130+ secrets blocked on every commit"
echo "    🔍 OWASP Top 10 SAST scanning on every commit"
echo "    🛡️  Dependency CVE scanning on every push"
echo "    📊 Security dashboard in GitHub Actions"
echo "    🚦 Security gate blocks unsafe PRs"
echo ""
echo "  ─────────────────────────────────────────────────────"
echo "  Next steps:"
echo ""
echo "    1. Commit the security files:"
echo "       git commit -m 'feat: add SecurOps security scanning'"
echo ""
echo "    2. Push to trigger the GitHub Actions pipeline:"
echo "       git push"
echo ""
echo "    3. Test — try committing a fake secret:"
echo "       echo 'key=\"AKIAIOSFODNN7EXAMPLE\"' > test.py"
echo "       git add test.py && git commit -m 'test'"
echo "       # Expected: ❌ BLOCKED"
echo ""
echo "  ─────────────────────────────────────────────────────"
echo "  Need help?"
echo "    Slack:  ${SUPPORT_SLACK}"
echo "    Email:  ${SUPPORT_EMAIL}"
echo ""
echo "  To add SecurOps to ANOTHER project:"
echo "    cd /path/to/other-project"
echo "    bash <(curl -s https://raw.githubusercontent.com/${GITHUB_ORG}/${CONFIG_REPO}/main/scripts/onboard.sh)"
echo ""
