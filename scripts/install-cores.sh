set -euo pipefail
mkdir -p "$RUNNER_TEMP/freedom-cores"
install_xray() {
  local version url archive
  version="${XRAY_VERSION:-latest}"
  if [ "$version" = latest ]; then
    version=$(curl -fsSL --retry 3 https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.tag_name')
  fi
  url="https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-64.zip"
  archive="$RUNNER_TEMP/freedom-cores/xray.zip"
  curl -fL --retry 3 --connect-timeout 20 --max-time 180 "$url" -o "$archive"
  mkdir -p "$RUNNER_TEMP/freedom-cores/xray-extract"
  unzip -oq "$archive" -d "$RUNNER_TEMP/freedom-cores/xray-extract"
  install "$RUNNER_TEMP/freedom-cores/xray-extract/xray" "$RUNNER_TEMP/freedom-cores/xray"
}
install_singbox() {
  local version tag url archive dir
  version="${SING_BOX_VERSION:-latest}"
  if [ "$version" = latest ]; then
    tag=$(curl -fsSL --retry 3 https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name')
  else
    tag="$version"
  fi
  url="https://github.com/SagerNet/sing-box/releases/download/${tag}/sing-box-${tag#v}-linux-amd64.tar.gz"
  archive="$RUNNER_TEMP/freedom-cores/sing-box.tar.gz"
  curl -fL --retry 3 --connect-timeout 20 --max-time 180 "$url" -o "$archive"
  mkdir -p "$RUNNER_TEMP/freedom-cores/sing-box-extract"
  tar -xzf "$archive" -C "$RUNNER_TEMP/freedom-cores/sing-box-extract"
  dir=$(find "$RUNNER_TEMP/freedom-cores/sing-box-extract" -type f -name sing-box -print -quit)
  test -n "$dir"
  install "$dir" "$RUNNER_TEMP/freedom-cores/sing-box"
}
install_xray
install_singbox
{
  echo "$RUNNER_TEMP/freedom-cores" >> "$GITHUB_PATH"
} 
