#!/usr/bin/env bash
# Copyright 2026 BitWise Media Group Ltd
# SPDX-License-Identifier: MIT

# Verify upstream provenance of the chart and every locked image, per the manifest's
# verifyUpstream rules. Fails when a declared signature is missing or invalid; images
# matched by a `provider: none` rule are reported as documented gaps, not failures.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

chart="${1:?usage: verify-upstream.sh <chart>}"
need yq cosign

m="$(manifest_path "$chart")"
lock="$(lock_path "$chart")"
[[ -f "$lock" ]] || die "no lock for chart '$chart'"

unverified=()

# cosign's stdout is the verified-payload JSON (noise here); its stderr carries the check
# summary and any errors, and streams through so failures explain themselves in real time.
cosign_verify() { # cosign_verify <ref> <rule-yq-prefix> <manifest-file>
  local ref="$1" prefix="$2" file="$3" provider identity issuer key sig_repo digest_alg
  provider="$(yq "$prefix.provider" "$file")"
  # Some publishers (e.g. kyverno) store signatures in a dedicated repository
  # instead of alongside the artifact; cosign discovers them via COSIGN_REPOSITORY.
  sig_repo="$(yq "$prefix.signatureRepository // \"\"" "$file")"
  if [[ -n "$sig_repo" ]]; then
    export COSIGN_REPOSITORY="$sig_repo"
  else
    unset COSIGN_REPOSITORY # don't leak a previous rule's signature repository
  fi
  case "$provider" in
    cosign-keyless)
      identity="$(yq -e "$prefix.certificateIdentityRegexp" "$file")" \
        || die "$prefix: cosign-keyless requires certificateIdentityRegexp"
      issuer="$(yq "$prefix.certificateOidcIssuer // \"https://token.actions.githubusercontent.com\"" "$file")"
      cosign verify \
        --certificate-identity-regexp "$identity" \
        --certificate-oidc-issuer "$issuer" \
        "$ref" >/dev/null
      ;;
    cosign-key)
      key="$(yq -e "$prefix.key" "$file")" || die "$prefix: cosign-key requires key"
      # Some publishers sign with a non-default payload digest (cert-manager
      # uses sha512); the rule's optional signatureDigestAlgorithm passes through.
      digest_alg="$(yq "$prefix.signatureDigestAlgorithm // \"\"" "$file")"
      cosign verify --key "$key" --insecure-ignore-tlog=true \
        ${digest_alg:+--signature-digest-algorithm "$digest_alg"} \
        "$ref" >/dev/null
      ;;
    *)
      die "unsupported provider '$provider' at $prefix"
      ;;
  esac
}

# Chart provenance.
chart_provider="$(yq '.chart.verifyUpstream.provider // "none"' "$m")"
repo="$(manifest "$chart" '.chart.repo')"
name="$(manifest "$chart" '.chart.name')"
version="$(manifest "$chart" '.chart.version')"
if [[ "$chart_provider" == "none" ]]; then
  unverified+=("chart $name (no upstream provenance declared)")
elif [[ "$repo" == oci://* ]]; then
  ref="$(rewrite_source "${repo#oci://}/$name"):$version"
  log "verifying chart $ref ($chart_provider)"
  cosign_verify "$ref" '.chart.verifyUpstream' "$m" || die "chart signature verification failed for $ref"
else
  die "chart verifyUpstream is only supported for oci:// repos (got $repo); use provider: none"
fi

# Image provenance: first matching rule wins; every image must match one.
rule_count="$(yq '.images.verifyUpstream | length' "$m")"
while IFS= read -r source; do
  digest="$(SRC="$source" yq '.images[] | select(.source == env(SRC)) | .digest' "$lock")"
  ref="$(rewrite_source "${source%%:*}")@$digest"
  matched=""
  for ((i = 0; i < rule_count; i++)); do
    pattern="$(yq ".images.verifyUpstream[$i].match" "$m")"
    glob_match "$pattern" "$source" || continue
    matched=1
    provider="$(yq ".images.verifyUpstream[$i].provider" "$m")"
    if [[ "$provider" == "none" ]]; then
      unverified+=("$source (rule: $pattern)")
    else
      log "verifying $source ($provider)"
      cosign_verify "$ref" ".images.verifyUpstream[$i]" "$m" \
        || die "image signature verification failed for $source"
    fi
    break
  done
  [[ -n "$matched" ]] || die "no verifyUpstream rule matches image $source; add a rule (provider: none to document a gap)"
done < <(yq '.images[].source' "$lock")

if ((${#unverified[@]} > 0)); then
  warn "upstream provenance gaps (documented, not failures):"
  printf '  - %s\n' "${unverified[@]}" >&2
fi
log "upstream verification complete"
