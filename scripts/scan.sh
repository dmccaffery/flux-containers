#!/usr/bin/env bash
# Copyright 2026 BitWise Media Group Ltd
# SPDX-License-Identifier: MIT

# Scan every locked image (by digest) with Grype and the chart configuration with Kubescape.
# Blocking severities come from the manifest (fallback: config/global.yaml); accepted CVEs
# live in charts/<name>/security/allowlist.yaml (statement + expiry, lint-enforced) and are
# translated into Grype ignore rules at scan time.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

chart="${1:?usage: scan.sh <chart>}"
need yq grype kubescape

dir="$(chart_dir "$chart")"
lock="$(lock_path "$chart")"
[[ -f "$lock" ]] || die "no lock for chart '$chart'"

if [[ "$(manifest_or "$chart" '.scan.failOn | join(",")' '')" != "" ]]; then
  severities="$(manifest "$chart" '.scan.failOn | join(",")')"
else
  severities="$(global '.scan.failOn | join(",")')"
fi
ignore_unfixed="$(manifest_or "$chart" '.scan.ignoreUnfixed' "$(global '.scan.ignoreUnfixed')")"

# Grype gates on a single "this severity or worse" threshold, so the failOn list collapses
# to its least severe entry.
fail_on=""
for level in LOW MEDIUM HIGH CRITICAL; do
  if [[ ",$severities," == *",$level,"* ]]; then
    fail_on="$(tr '[:upper:]' '[:lower:]' <<<"$level")"
    break
  fi
done
[[ -n "$fail_on" ]] || die "scan.failOn must contain one of LOW, MEDIUM, HIGH, CRITICAL (got '$severities')"

args=(--fail-on "$fail_on" --quiet)
[[ "$ignore_unfixed" == "true" ]] && args+=(--only-fixed)
if [[ -f "$dir/security/allowlist.yaml" ]]; then
  # Grype infers the config format from the extension, so the file needs a real .yaml name.
  grype_config_dir="$(mktemp -d "${TMPDIR:-/tmp}/grype-allowlist.XXXXXX")"
  trap 'rm -rf "$grype_config_dir"' EXIT
  grype_config="$grype_config_dir/config.yaml"
  # include-aliases also suppresses the finding when Grype reports it under a GHSA alias.
  yq '{"ignore": [(.vulnerabilities // [])[] | {"vulnerability": .id, "include-aliases": true, "reason": .statement}]}' \
    "$dir/security/allowlist.yaml" > "$grype_config"
  args+=(--config "$grype_config")
fi

failures=0
while IFS=$'\t' read -r source digest; do
  # yq emits a single blank line for an empty images list; skip it.
  [[ -n "$source" ]] || continue
  ref="$(rewrite_source "${source%%:*}")@$digest"
  log "scanning $source"
  grype "${args[@]}" "registry:$ref" || { warn "blocking vulnerabilities in $source"; failures=$((failures + 1)); }
done < <(yq '.images[] | [.source, .digest] | @tsv' "$lock")

# Chart configuration findings (RBAC breadth, security contexts) are usually inherent to what
# an upstream operator chart must do; they inform review rather than block by default.
# Kubescape scans the committed rendered manifests (discovery values) instead of re-rendering
# the chart with upstream defaults.
config_mode="$(global '.scan.configScan')"
rendered="$dir/rendered/manifests.yaml"
[[ -f "$rendered" ]] || die "no rendered manifests for chart '$chart' (run: make render CHART=$chart)"
log "scanning chart configuration (mode: $config_mode)"
# Kubescape must not see a kubeconfig: given one, even a file scan lists SecurityException
# CRDs from the current cluster and merges them into the results, so findings would depend
# on whatever cluster the developer happens to be pointed at (and it warns noisily when
# that cluster is unreachable). An empty KUBECONFIG keeps file scans self-contained and
# identical to CI, where no kubeconfig exists.
# --logger warning silences the progress-spinner UI, which sidesteps an upstream bug where
# kubescape appends .txt to the /dev/null sink it points that UI at ("failed to open file
# for writing ... /dev/null.txt"). Results tables and real warnings still print.
if [[ "$config_mode" == "block" ]]; then
  KUBECONFIG=/dev/null kubescape scan "$rendered" --logger warning --severity-threshold low \
    || { warn "blocking misconfigurations in chart $chart"; failures=$((failures + 1)); }
else
  KUBECONFIG=/dev/null kubescape scan "$rendered" --logger warning || true
fi

((failures == 0)) || die "$failures scan failure(s); fix or allowlist with statement + expiry"
log "scan clean"
