#!/usr/bin/env bash
# Copyright 2026 BitWise Media Group Ltd
# SPDX-License-Identifier: MIT

# Print the newest upstream chart version satisfying the manifest's versionConstraint,
# or nothing when the pin is already current. The update-check workflow turns a non-empty
# result into a vendored bump PR.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

chart="${1:?usage: check-updates.sh <chart>}"
need helm yq crane

repo="$(manifest "$chart" '.chart.repo')"
name="$(manifest "$chart" '.chart.name')"
current="$(manifest "$chart" '.chart.version')"
constraint="$(manifest_or "$chart" '.chart.versionConstraint' '')"

if [[ "$repo" == oci://* ]]; then
  versions="$(crane ls "$(rewrite_source "${repo#oci://}/$name")")"
else
  versions="$(helm show chart "$name" --repo "$repo" --version '>0.0.0-0' 2>/dev/null | yq '.version')"
  # helm show only returns the latest; fall back to the repo index for the full list.
  if index="$(curl -fsSL "${repo%/}/index.yaml" 2>/dev/null)"; then
    versions="$(CHART_NAME="$name" yq '.entries[env(CHART_NAME)][].version' <<< "$index")"
  fi
fi

best="$current"
while IFS= read -r v; do
  v="${v#v}"
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
  if [[ -n "$constraint" ]]; then
    semver_in_range "$v" "$constraint" || continue
  fi
  [[ "$(printf '%s\n%s\n' "$best" "$v" | sort -V | tail -1)" == "$v" && "$v" != "$best" ]] && best="$v"
done <<< "$versions"

if [[ "$best" != "$current" ]]; then
  log "update available: $current -> $best"
  echo "$best"
else
  log "already current ($current)"
fi
