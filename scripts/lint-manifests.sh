#!/usr/bin/env bash
# Copyright 2026 BitWise Media Group Ltd
# SPDX-License-Identifier: MIT

# Validate every chart manifest and CVE allowlist. Allowlist entries must carry a statement
# and an expiry no further out than scan.allowlistMaxDays; expired entries fail the lint so
# accepted risk is re-reviewed on schedule.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

need yq
failures=0
fail() {
  printf 'lint: %s\n' "$*" >&2
  failures=$((failures + 1))
}

max_days="$(global '.scan.allowlistMaxDays')"
today_epoch="$(date +%s)"
horizon_epoch=$((today_epoch + max_days * 86400))

for manifest_file in "$ROOT"/charts/*/manifest.yaml; do
  [[ -e "$manifest_file" ]] || continue
  chart="$(basename "$(dirname "$manifest_file")")"
  log "chart: ${chart}"

  for field in .name .chart.repo .chart.name .chart.version .publish.chartRepo; do
    yq -e "$field" "$manifest_file" >/dev/null || fail "$chart: manifest missing $field"
  done

  [[ "$(yq '.name' "$manifest_file")" == "$chart" ]] ||
    fail "$chart: manifest .name must match its directory"

  repo="$(yq '.chart.repo // ""' "$manifest_file")"
  [[ "$repo" == oci://* || "$repo" == https://* ]] ||
    fail "$chart: .chart.repo must be an oci:// or https:// URL"

  provider="$(yq '.chart.verifyUpstream.provider // "none"' "$manifest_file")"
  case "$provider" in
  none | cosign-keyless | cosign-key) ;;
  *) fail "$chart: unknown chart verifyUpstream provider '$provider'" ;;
  esac

  rule_count="$(yq '.images.verifyUpstream // [] | length' "$manifest_file")"
  [[ "$rule_count" -gt 0 ]] || fail "$chart: images.verifyUpstream must declare at least one rule (use provider: none to document a gap)"
  for ((i = 0; i < rule_count; i++)); do
    rp="$(yq ".images.verifyUpstream[$i].provider // \"\"" "$manifest_file")"
    case "$rp" in
    none | cosign-keyless | cosign-key) ;;
    *) fail "$chart: images.verifyUpstream[$i] has unknown provider '$rp'" ;;
    esac
    yq -e ".images.verifyUpstream[$i].match" "$manifest_file" >/dev/null ||
      fail "$chart: images.verifyUpstream[$i] missing match pattern"
  done

  allowlist="$(dirname "$manifest_file")/security/allowlist.yaml"
  if [[ -f "$allowlist" ]]; then
    entries="$(yq '.vulnerabilities // [] | length' "$allowlist")"
    for ((i = 0; i < entries; i++)); do
      id="$(yq ".vulnerabilities[$i].id // \"\"" "$allowlist")"
      statement="$(yq ".vulnerabilities[$i].statement // \"\"" "$allowlist")"
      expiry="$(yq ".vulnerabilities[$i].expired_at // \"\"" "$allowlist")"
      [[ -n "$id" ]] || fail "$chart: allowlist entry $i missing id"
      [[ -n "$statement" ]] || fail "$chart: allowlist $id missing statement"
      if [[ -z "$expiry" ]]; then
        fail "$chart: allowlist $id missing expired_at"
      else
        expiry_epoch="$(date -j -f '%Y-%m-%d' "$expiry" +%s 2>/dev/null || date -d "$expiry" +%s 2>/dev/null)" ||
          {
            fail "$chart: allowlist $id has unparseable expired_at '$expiry'"
            continue
          }
        ((expiry_epoch > today_epoch)) || fail "$chart: allowlist $id expired on $expiry"
        ((expiry_epoch <= horizon_epoch)) || fail "$chart: allowlist $id expires more than $max_days days out"
      fi
    done
  fi
done

((failures == 0)) || die "$failures lint failure(s)"
log "all manifests and allowlists valid"
