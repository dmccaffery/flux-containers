#!/usr/bin/env bash
# Copyright 2026 BitWise Media Group Ltd
# SPDX-License-Identifier: MIT

# Render the vendored chart with the chart's discovery values into rendered/manifests.yaml.
# The output is committed: PR diffs show exactly what would change in-cluster, and image
# discovery runs against it.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

chart="${1:?usage: render-chart.sh <chart>}"
need helm yq

dir="$(chart_dir "$chart")"
name="$(manifest "$chart" '.chart.name')"
namespace="$(manifest_or "$chart" '.discovery.namespace' "$chart")"
kube_version="$(manifest_or "$chart" '.discovery.kubeVersion' '1.34.0')"

[[ -d "$dir/vendor/$name" ]] || die "chart '$chart' is not vendored; run vendor-chart.sh first"

args=(
  "$name" "$dir/vendor/$name"
  --namespace "$namespace"
  --kube-version "$kube_version"
  --include-crds
)

while IFS= read -r vf; do
  [[ -n "$vf" ]] || continue
  [[ -f "$dir/$vf" ]] || die "values file '$vf' not found under charts/$chart/"
  args+=(-f "$dir/$vf")
done < <(yq '.discovery.valuesFiles // [] | .[]' "$(manifest_path "$chart")")

while IFS= read -r av; do
  [[ -n "$av" ]] && args+=(--api-versions "$av")
done < <(yq '.discovery.apiVersions // [] | .[]' "$(manifest_path "$chart")")

mkdir -p "$dir/rendered"
helm template "${args[@]}" > "$dir/rendered/manifests.yaml"
log "rendered charts/$chart/rendered/manifests.yaml ($(grep -c '^---' "$dir/rendered/manifests.yaml" || true) documents)"
