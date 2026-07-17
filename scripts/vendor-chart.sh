#!/usr/bin/env bash
# Copyright 2026 BitWise Media Group Ltd
# SPDX-License-Identifier: MIT

# Vendor the pinned upstream chart version into charts/<name>/vendor/ and record its
# upstream tgz digest in images.lock.yaml. The tgz itself is not committed; publish
# re-pulls it and verifies both the digest and the committed vendor tree.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

chart="${1:?usage: vendor-chart.sh <chart>}"
need helm yq

dir="$(chart_dir "$chart")"
name="$(manifest "$chart" '.chart.name')"
version="$(manifest "$chart" '.chart.version')"

work="$(mktemp -d "${TMPDIR:-/tmp}/vendor.XXXXXX")"
trap 'rm -rf "$work"' EXIT

log "vendoring $name $version"
tgz="$(pull_chart_tgz "$chart" "$work")"
sha="$(sha256_of "$tgz")"

rm -rf "$dir/vendor"
mkdir -p "$dir/vendor"
tar -xzf "$tgz" -C "$dir/vendor"
[[ -f "$dir/vendor/$name/Chart.yaml" ]] || die "extracted chart missing Chart.yaml"

lock="$(lock_path "$chart")"
[[ -f "$lock" ]] || printf 'chart: {}\nimages: []\n' > "$lock"
CHART_NAME="$name" CHART_VERSION="$version" TGZ_SHA="$sha" \
  yq -i '.chart.name = env(CHART_NAME) | .chart.version = env(CHART_VERSION) | .chart.upstreamTgzSha256 = env(TGZ_SHA)' "$lock"

log "vendored to charts/$chart/vendor/$name (upstream tgz sha256 $sha)"
