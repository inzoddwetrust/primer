#!/usr/bin/env bash
# Bootstrap of pridem on a clean Ubuntu 24.04 x86_64 box (TZ section 6.1).
#
# Five actions, no questions: check the host; install the packages; clone pridem
# at the pinned commit; build the venv without an index; link `current` and
# `pridem`. In the repository this file is a template: the release workflow
# substitutes the five pins below -- tag, commit, the wheel's sha256 and the two
# sources, the repository and the wheel's address -- and publishes the result as
# an asset of the GitHub Release, next to the pridem wheel; tier 3 substitutes a
# local clone and a file:// wheel built in its run. With unsubstituted pins it
# refuses.
#
# PRIDEM_ROOT prefixes every path the script reads or writes (empty on a box);
# it changes where, never what.
set -euo pipefail

TAG="@PRIDEM_TAG@"
COMMIT="@PRIDEM_COMMIT@"
WHEEL_SHA256="@PRIDEM_WHEEL_SHA256@"
REPO="@PRIDEM_REPO@"
WHEEL_URL="@PRIDEM_WHEEL_URL@"
SOPS_VERSION="v3.13.3"
SOPS_SHA256="e5bec3346a873ae91d871550f3e698c1aad962aff462a080e40f25fde17fef6b"

ROOT="${PRIDEM_ROOT:-}"
HOME_DIR="$ROOT/opt/pridem"
TARGET="$HOME_DIR/versions/$TAG"
BIN="$ROOT/usr/local/bin"

fail() {
    echo "install.sh: $*" >&2
    exit 1
}

# 1. The host: exactly Ubuntu 24.04 on x86_64, as root, with real pins.
[[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ && $COMMIT =~ ^[0-9a-f]{40}$ &&
    $WHEEL_SHA256 =~ ^[0-9a-f]{64}$ &&
    $REPO =~ ^(https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|file:///[^[:space:]]+)$ &&
    $WHEEL_URL =~ ^(https://github\.com/|file:///)[^[:space:]]+\.whl$ ]] ||
    fail "pins are not set: use install.sh from the GitHub Release of a tag"
[[ -r $ROOT/etc/os-release ]] || fail "no /etc/os-release: not Ubuntu 24.04"
os_id="" os_version=""
while IFS='=' read -r key value; do
    case $key in
        ID) os_id=${value//\"/} ;;
        VERSION_ID) os_version=${value//\"/} ;;
    esac
done <"$ROOT/etc/os-release"
[[ $os_id == "ubuntu" && $os_version == "24.04" ]] ||
    fail "needs Ubuntu 24.04, found '${os_id} ${os_version}'"
arch=$(uname -m)
[[ $arch == "x86_64" ]] || fail "needs x86_64, found ${arch}"
[[ $(id -u) == "0" ]] || fail "needs root"
echo "1/5 host: Ubuntu 24.04 x86_64, root"

if [[ -x $TARGET/venv/bin/pridem && $("$TARGET/venv/bin/pridem" version) == "pridem ${TAG#v}" ]]; then
    echo "2-4/5 pridem $TAG is installed already"
else
    # 2. Packages: apt waits for the dpkg lock instead of breaking it; sops is
    #    not in apt on 24.04 and comes from its release by version and sha256.
    apt-get -o DPkg::Lock::Timeout=600 update
    apt-get -o DPkg::Lock::Timeout=600 install -y python3 python3-venv git curl age
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    curl -fsSL -o "$work/sops" \
        "https://github.com/getsops/sops/releases/download/$SOPS_VERSION/sops-$SOPS_VERSION.linux.amd64"
    echo "$SOPS_SHA256  $work/sops" | sha256sum -c --strict
    install -m 0755 "$work/sops" "$BIN/sops"
    echo "2/5 packages: python3 python3-venv git curl age sops $SOPS_VERSION"

    # 3. The pinned clone: the tag must be the commit the release was built from.
    git clone --quiet --depth 1 --branch "$TAG" "$REPO.git" "$work/pridem"
    head=$(git -C "$work/pridem" rev-parse HEAD)
    [[ $head == "$COMMIT" ]] || fail "tag $TAG is $head, the pin is $COMMIT"
    echo "3/5 clone: $TAG at $COMMIT"

    # 4. The venv without an index: the runtime from wheels/ by the lock, the
    #    wheel of pridem from the Release; nothing is built here. A venv cannot
    #    be moved, so an earlier attempt that did not end installed is removed.
    curl -fsSL -o "$work/pridem-${TAG#v}-py3-none-any.whl" "$WHEEL_URL"
    echo "$WHEEL_SHA256  $work/pridem-${TAG#v}-py3-none-any.whl" | sha256sum -c --strict
    rm -rf "$TARGET"
    # the machine's home is root's alone, like every file of the box
    install -d -m 0700 "$HOME_DIR"
    mkdir -p "$HOME_DIR/versions"
    python3 -m venv "$TARGET/venv"
    "$TARGET/venv/bin/pip" install --no-index --find-links "$work/pridem/wheels" \
        --require-hashes -r "$work/pridem/requirements.lock"
    "$TARGET/venv/bin/pip" install --no-index --no-deps \
        "$work/pridem-${TAG#v}-py3-none-any.whl"
    version=$("$TARGET/venv/bin/pridem" version)
    [[ $version == "pridem ${TAG#v}" ]] || fail "installed pridem says '$version'"
    echo "4/5 venv: $TARGET/venv, $version"
fi

# 5. The links: `current` to this version, `pridem` on the PATH.
ln -sfn "$TARGET" "$HOME_DIR/current"
ln -sfn "$HOME_DIR/current/venv/bin/pridem" "$BIN/pridem"
echo "5/5 links: $HOME_DIR/current -> $TARGET, $BIN/pridem"
