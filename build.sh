#!/usr/bin/env bash
# ARTEX cross-platform release builder.
#
# The default mode builds one target and embeds the already-exported frontend.
# `./build.sh --release` builds and packages all supported desktop/server targets.
#
# Environment variables:
#   ARTEX_TARGET_OS=linux             One target OS in single-target mode.
#   ARTEX_TARGET_ARCH=amd64           One target arch in single-target mode.
#   ARTEX_TARGETS=linux/amd64,...     Comma-separated targets for multi-target mode.
#   ARTEX_NODE_TARGETS=linux/amd64,... Platforms bundled under node-binaries/.
#   ARTEX_BUILD_VERSION=v0.3.3        Version embedded in the binary and archive name.
#   ARTEX_OUTPUT=/path/to/artex       Explicit binary path in single-target mode.
#   ARTEX_OUTPUT_DIR=dist             Directory for default binary paths.
#   ARTEX_PACKAGE=1                   Create a zip archive for each target.
#   ARTEX_PACKAGE_DIR=dist            Directory for release archives.
#   ARTEX_COMPRESS=off                UPX mode: off, auto, or required.
#   ARTEX_UPX_ARGS="--best --lzma"    Arguments passed to UPX.
#   ARTEX_SKIP_FRONTEND=1             Reuse server/webui/dist (for CI artifact builds).
#   ARTEX_SKIP_NPM_CI=1               Skip npm ci while rebuilding the frontend.
#   ARTEX_GOSUMDB=sum.golang.org      Go checksum database.
set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)"

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok() { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
用法：
  ./build.sh                         编译当前系统当前架构
  ./build.sh --target linux/amd64   编译一个指定目标
  ./build.sh --release               编译并打包全部支持的目标

选项：
  --release              构建 Linux、macOS、Windows 的 amd64/arm64 目标并生成 zip
  --target OS/ARCH       设置单个目标，例如 windows/amd64
  --upx                  强制使用 UPX 压缩二进制（可能影响部分 Linux 环境兼容性）
  --no-compress          不使用 UPX，仅使用 Go linker 裁剪并压缩 zip
  --help                 显示帮助

多目标列表可通过 ARTEX_TARGETS 覆盖，例如：
  ARTEX_TARGETS=linux/amd64,windows/amd64 ./build.sh --release
EOF
}

RELEASE_TARGETS_DEFAULT="linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64"
NODE_TARGETS_DEFAULT="linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64"
ARTEX_RELEASE="${ARTEX_RELEASE:-0}"
ARTEX_COMPRESS="${ARTEX_COMPRESS:-off}"
ARTEX_PACKAGE="${ARTEX_PACKAGE:-0}"
ARTEX_NODE_TARGETS="${ARTEX_NODE_TARGETS:-$NODE_TARGETS_DEFAULT}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      ARTEX_RELEASE=1
      ARTEX_PACKAGE=1
      shift
      ;;
    --target)
      [ "$#" -ge 2 ] || die "--target 需要 OS/ARCH 参数"
      target_arg="$2"
      case "$target_arg" in
        */*)
          ARTEX_TARGET_OS="${target_arg%%/*}"
          ARTEX_TARGET_ARCH="${target_arg##*/}"
          ARTEX_TARGETS="$target_arg"
          ;;
        *) die "目标必须是 OS/ARCH，例如 linux/amd64" ;;
      esac
      shift 2
      ;;
    --no-compress)
      ARTEX_COMPRESS=0
      shift
      ;;
    --upx)
      ARTEX_COMPRESS=required
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *) die "未知参数：$1（使用 --help 查看用法）" ;;
  esac
done

command -v go >/dev/null 2>&1 || die "未检测到 Go（项目需要 Go 1.26 或更高版本）"

ARTEX_GOSUMDB="${ARTEX_GOSUMDB:-sum.golang.org}"
if [ -z "${ARTEX_BUILD_VERSION:-}" ]; then
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    ARTEX_BUILD_VERSION="$(git describe --tags --always --dirty)"
  else
    ARTEX_BUILD_VERSION="dev"
  fi
fi
# Release tags are commonly passed as v0.3.3; keep the binary version consistent.
ARTEX_BUILD_VERSION="${ARTEX_BUILD_VERSION#v}"
case "$ARTEX_BUILD_VERSION" in
  ''|*[!A-Za-z0-9._+-]*) die "版本只能包含 ASCII 字母、数字、点、下划线、加号和连字符，避免生成无效清单 JSON" ;;
esac
ARTEX_OUTPUT_DIR="${ARTEX_OUTPUT_DIR:-dist}"
ARTEX_PACKAGE_DIR="${ARTEX_PACKAGE_DIR:-$ARTEX_OUTPUT_DIR}"
ARTEX_UPX_ARGS="${ARTEX_UPX_ARGS:---best --lzma}"

if [ "${ARTEX_RELEASE}" = "1" ]; then
  ARTEX_TARGETS="${ARTEX_TARGETS:-$RELEASE_TARGETS_DEFAULT}"
else
  ARTEX_TARGET_OS="${ARTEX_TARGET_OS:-$(GOSUMDB="$ARTEX_GOSUMDB" go env GOOS)}"
  ARTEX_TARGET_ARCH="${ARTEX_TARGET_ARCH:-$(GOSUMDB="$ARTEX_GOSUMDB" go env GOARCH)}"
  ARTEX_TARGETS="${ARTEX_TARGETS:-${ARTEX_TARGET_OS}/${ARTEX_TARGET_ARCH}}"
fi

if [ "${ARTEX_SKIP_FRONTEND:-0}" = "1" ]; then
  [ -d server/webui/dist ] || die "ARTEX_SKIP_FRONTEND=1 但 server/webui/dist 不存在"
else
  command -v npm >/dev/null 2>&1 || die "未检测到 npm（前端静态构建需要 Node.js/npm）"
  command -v rsync >/dev/null 2>&1 || die "未检测到 rsync"
  info "构建前端静态资源"
  if [ "${ARTEX_SKIP_NPM_CI:-0}" != "1" ]; then
    (cd web && npm ci)
  fi
  (cd web && npm run build:static)
  info "同步前端资源到 server/webui/dist"
  mkdir -p server/webui/dist
  rsync -a --delete web/out/ server/webui/dist/
fi

compress_binary() {
  binary="$1"
  goos="$2"
  case "$ARTEX_COMPRESS" in
    0|off|false|none)
      info "跳过 UPX：$binary"
      return 0
      ;;
    auto|required|true|1) ;;
    *) die "ARTEX_COMPRESS 必须是 off、auto 或 required" ;;
  esac

  if ! command -v upx >/dev/null 2>&1; then
    if [ "$ARTEX_COMPRESS" = "required" ]; then
      die "ARTEX_COMPRESS=required 但未检测到 upx"
    fi
    warn "未检测到 upx，保留 linker 压缩结果：$binary"
    return 0
  fi

  before=$(wc -c < "$binary" | tr -d ' ')
  upx_args="$ARTEX_UPX_ARGS"
  [ "$goos" = "darwin" ] && upx_args="$upx_args --force-macos"
  # shellcheck disable=SC2086
  if ! upx $upx_args -- "$binary"; then
    if [ "$ARTEX_COMPRESS" = "required" ]; then
      die "UPX 压缩失败：$binary"
    fi
    warn "UPX 不支持该目标格式，保留未压缩二进制：$binary"
    return 0
  fi
  after=$(wc -c < "$binary" | tr -d ' ')
  ok "UPX 压缩完成：$binary (${before} -> ${after} bytes)"
}

package_binary() {
  binary="$1"
  goos="$2"
  goarch="$3"
  package_name="artex-${ARTEX_BUILD_VERSION}-${goos}-${goarch}"
  package_root="${ARTEX_PACKAGE_DIR}/${package_name}"
  archive="${ARTEX_PACKAGE_DIR}/${package_name}.zip"

  command -v zip >/dev/null 2>&1 || die "打包需要 zip"
  rm -rf "$package_root" "$archive"
  mkdir -p "$package_root"
  cp "$binary" "$package_root/"
  node_name="artex-node"
  [ "$goos" = "windows" ] && node_name="artex-node.exe"
  cp "$(dirname "$binary")/$node_name" "$package_root/"
  [ -d "$(dirname "$binary")/node-binaries" ] || die "缺少同版本 node-binaries 资源目录"
  cp -R "$(dirname "$binary")/node-binaries" "$package_root/"
  mkdir -p "$package_root/examples" "$package_root/docs"
  cp examples/team-node*.json "$package_root/examples/"
  cp examples/README.md "$package_root/examples/"
  cp docs/team-onboarding.md docs/team-onboarding-validation.md docs/team-branches.md docs/team-shared-messages.md "$package_root/docs/"
  # 守护启动脚本是正式入口：页面上的一键更新要靠它在进程退出后重新拉起，
  # 直接跑 artex 本体的话更新完就再也起不来了。按目标系统只带对应的那一份。
  if [ "$goos" = "windows" ]; then
    cp start.bat "$package_root/"
  else
    cp start.sh "$package_root/"
    chmod +x "$package_root/start.sh"
  fi
  cp -R skills "$package_root/"
  cp config.example.json "$package_root/"
  if [ -f README.md ]; then cp README.md "$package_root/"; fi
  (cd "$ARTEX_PACKAGE_DIR" && zip -q -r -9 "$(basename "$archive")" "$(basename "$package_root")")
  rm -rf "$package_root"
  ok "Release 压缩包：$archive"
}

node_binary_name() {
  local target="$1" name
  name="artex-node-${target//\//-}"
  [ "${target%%/*}" = "windows" ] && name="$name.exe"
  printf '%s\n' "$name"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "生成 Node 资源清单需要 sha256sum 或 shasum"
  fi
}

build_node_binaries() {
  local target goos goarch file sum index=0 count="${#node_manifest_targets[@]}"
  printf '{\n  "version": "%s",\n  "binaries": [\n' "$ARTEX_BUILD_VERSION" > "$node_cache_dir/manifest.json.tmp"
  for target in "${node_manifest_targets[@]}"; do
    goos="${target%%/*}"
    goarch="${target##*/}"
    file="$(node_binary_name "$target")"
    info "编译成员 Node ${goos}/${goarch}，版本 ${ARTEX_BUILD_VERSION}"
    GOSUMDB="$ARTEX_GOSUMDB" CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
      go build -trimpath -ldflags "-s -w -buildid= -X main.version=${ARTEX_BUILD_VERSION}" \
      -o "$node_cache_dir/$file" ./cmd/artex-node
    sum="$(sha256_file "$node_cache_dir/$file")"
    case "$sum" in *[!0-9a-fA-F]*|'') die "无法计算 Node SHA256：$file" ;; esac
    [ "${#sum}" -eq 64 ] || die "Node SHA256 长度无效：$file"
    if [ "$index" -gt 0 ]; then printf ',\n' >> "$node_cache_dir/manifest.json.tmp"; fi
    printf '    {"platform":"%s","file":"%s","sha256":"%s"}' \
      "${target//\//-}" "$file" "$sum" >> "$node_cache_dir/manifest.json.tmp"
    index=$((index + 1))
  done
  [ "$index" -eq "$count" ] || die "Node manifest 条目数量不匹配"
  printf '\n  ]\n}\n' >> "$node_cache_dir/manifest.json.tmp"
  mv "$node_cache_dir/manifest.json.tmp" "$node_cache_dir/manifest.json"
  ok "已生成 Node 资源清单（$index 个平台，版本 $ARTEX_BUILD_VERSION）"
}

stage_node_resources() {
  local output="$1" output_target_os="$2" output_target_arch="$3" target file source main_dir resources
  main_dir="$(cd "$(dirname "$output")" && pwd -P)"
  [ -n "$main_dir" ] && [ "$main_dir" != "/" ] || die "拒绝在文件系统根目录创建 Node 资源目录"
  resources="$main_dir/node-binaries"
  case "$resources" in "$main_dir"/node-binaries) ;; *) die "Node 资源目录超出主端输出目录" ;; esac
  if [ -L "$resources" ]; then die "拒绝覆盖符号链接 Node 资源目录：$resources"; fi
  if [ -e "$resources" ]; then
    [ -d "$resources" ] || die "Node 资源目标已存在且不是目录：$resources"
    # 此固定路径已限定在本次主端二进制的 dirname 下。
    rm -rf -- "$resources"
  fi
  mkdir -p "$resources"
  for target in "${node_manifest_targets[@]}"; do
    file="$(node_binary_name "$target")"
    source="$node_cache_dir/$file"
    [ -f "$source" ] || die "本次构建缺少 Node 平台资源：$target"
    cp "$source" "$resources/$file"
  done
  # 最后写入清单，避免它引用上一次构建的资源。
  cp "$node_cache_dir/manifest.json" "$resources/manifest.json"
  target="${output_target_os}/${output_target_arch}"
  file="artex-node"
  [ "$output_target_os" = "windows" ] && file="artex-node.exe"
  source="$node_cache_dir/$(node_binary_name "$target")"
  if [ ! -f "$source" ]; then
    info "编译主端同目标 Node ${output_target_os}/${output_target_arch}（未纳入平台资源清单）"
    GOSUMDB="$ARTEX_GOSUMDB" CGO_ENABLED=0 GOOS="$output_target_os" GOARCH="$output_target_arch" \
      go build -trimpath -ldflags "-s -w -buildid= -X main.version=${ARTEX_BUILD_VERSION}" \
      -o "$source" ./cmd/artex-node
  fi
  [ -f "$source" ] || die "本次构建缺少同目标 Node 可执行文件：$target"
  cp "$source" "$main_dir/$file"
}

build_target() {
  target="$1"
  case "$target" in
    */*) ;;
    *) die "无效目标：$target（必须是 OS/ARCH）" ;;
  esac
  goos="${target%%/*}"
  goarch="${target##*/}"
  case "$goos" in
    linux|darwin|windows) ;;
    *) die "不支持的系统：$goos（支持 linux、darwin、windows）" ;;
  esac

  binary_name="artex"
  [ "$goos" = "windows" ] && binary_name="artex.exe"
  if [ -n "${ARTEX_OUTPUT:-}" ] && [ "$ARTEX_RELEASE" != "1" ]; then
    output="$ARTEX_OUTPUT"
  else
    output="${ARTEX_OUTPUT_DIR}/artex-${goos}-${goarch}/${binary_name}"
  fi
  mkdir -p "$(dirname "$output")"

  info "编译 ${goos}/${goarch}，版本 ${ARTEX_BUILD_VERSION}"
  GOSUMDB="$ARTEX_GOSUMDB" \
  CGO_ENABLED=0 \
  GOOS="$goos" \
  GOARCH="$goarch" \
  go build \
    -tags embedui \
    -trimpath \
    -ldflags "-s -w -buildid= -X main.version=${ARTEX_BUILD_VERSION}" \
    -o "$output" \
    ./cmd/artex

  compress_binary "$output" "$goos"
  stage_node_resources "$output" "$goos" "$goarch"
  if command -v file >/dev/null 2>&1; then file "$output"; fi
  if [ "$ARTEX_PACKAGE" = "1" ]; then package_binary "$output" "$goos" "$goarch"; fi
  ok "编译完成：$output"
}

write_checksums() {
  [ "$ARTEX_PACKAGE" = "1" ] || return 0
  checksum_file="$ARTEX_PACKAGE_DIR/SHA256SUMS"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$ARTEX_PACKAGE_DIR" && for archive in *.zip; do sha256sum "$archive"; done > "$(basename "$checksum_file")")
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$ARTEX_PACKAGE_DIR" && for archive in *.zip; do shasum -a 256 "$archive"; done > "$(basename "$checksum_file")")
  else
    warn "未检测到 sha256sum 或 shasum，跳过 SHA256SUMS"
    return 0
  fi
  ok "校验文件：$checksum_file"
}

mkdir -p "$ARTEX_OUTPUT_DIR"
if [ "$ARTEX_PACKAGE" = "1" ]; then mkdir -p "$ARTEX_PACKAGE_DIR"; fi
ARTEX_OUTPUT_ROOT="$(cd "$ARTEX_OUTPUT_DIR" && pwd -P)"
[ "$ARTEX_OUTPUT_ROOT" != "/" ] || die "ARTEX_OUTPUT_DIR 不能是文件系统根目录"

old_ifs="$IFS"
IFS=','
read -r -a targets <<< "$ARTEX_TARGETS"
read -r -a raw_node_targets <<< "$ARTEX_NODE_TARGETS"
IFS="$old_ifs"
normalized_targets=()
for target in "${targets[@]}"; do
  target="${target//[[:space:]]/}"
  [ -n "$target" ] && normalized_targets+=("$target")
done
targets=("${normalized_targets[@]}")
[ "${#targets[@]}" -gt 0 ] || die "ARTEX_TARGETS 不能为空"

node_manifest_targets=()
for target in "${raw_node_targets[@]}"; do
  target="${target//[[:space:]]/}"
  [ -n "$target" ] || continue
  case "$target" in
    linux/amd64|linux/arm64|darwin/amd64|darwin/arm64|windows/amd64) ;;
    *) die "ARTEX_NODE_TARGETS 不支持目标：$target" ;;
  esac
  duplicate=0
  for existing in "${node_manifest_targets[@]}"; do
    [ "$existing" = "$target" ] && duplicate=1
  done
  [ "$duplicate" = "1" ] || node_manifest_targets+=("$target")
done
[ "${#node_manifest_targets[@]}" -gt 0 ] || die "ARTEX_NODE_TARGETS 不能为空"

node_cache_dir="$(mktemp -d "$ARTEX_OUTPUT_ROOT/.artex-node-binaries.XXXXXX")"
cleanup_node_cache() {
  [ -n "${node_cache_dir:-}" ] || return 0
  case "$node_cache_dir" in
    "$ARTEX_OUTPUT_ROOT"/.artex-node-binaries.*)
      [ -d "$node_cache_dir" ] && [ ! -L "$node_cache_dir" ] && rm -rf -- "$node_cache_dir"
      ;;
    *) warn "跳过清理路径范围外的临时目录：$node_cache_dir" ;;
  esac
}
trap cleanup_node_cache EXIT
build_node_binaries

for target in "${targets[@]}"; do
  [ -n "$target" ] || continue
  build_target "$target"
done

if [ "$ARTEX_PACKAGE" = "1" ]; then
  write_checksums
  info "Release 包已生成于：$ARTEX_PACKAGE_DIR"
fi
