#!/usr/bin/env bash
# ACSE gate: evaluate, annotate, report, decide. Run by action.yml, one subcommand per step.
#
# Tools: bash, opa (pinned below), jq, awk, grep, sed, sha256sum, git, curl. Nothing from ACSE runs here: the only
# ACSE-specific input is the policy bundle in this repository, and the only call to ACSE is the verdict-only report.
#
# Results go to "$RUNNER_TEMP/acse-gate/": finding.json (never leaves the runner), result.json, annotations.json,
# suggestions.json, report.json and report-outcome.json.
set -euo pipefail

# --- Pins -------------------------------------------------------------------------------------------------------------
# The release of the gate template this file belongs to (gate-run-report-2.0 gate.template_release).
TEMPLATE_RELEASE="1.0.0"
# OPA, by version and checksum: the same build the ACSE runtime evaluates detect with (one evaluator on both sides).
OPA_VERSION="1.20.1"
OPA_SHA256_LINUX_AMD64="0b3f152e61be276b70396cfbca49e39fc9d0c5089e0a8574e8f6a30f41a9187f"
OPA_URL="https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static"

# --- Limits -----------------------------------------------------------------------------------------------------------
MAX_ANNOTATIONS=50          # GitHub shows at most 10 per level per step and 50 per job; the summary lists everything.
MAX_SUGGESTION_COMMENTS=20  # Pull request review comments per run.
REPORT_ATTEMPTS=3           # Retry, then warn (never fail the job on the report).
REPORT_ATTEMPT_TIMEOUT=20   # Seconds per attempt; three attempts and the waits stay under two minutes.

ACTION_DIR="${ACSE_GATE_ACTION_DIR:?}"
POLICY_ROOT="$(cd "$ACTION_DIR/../../.." && pwd -P)"
WORKSPACE="${GITHUB_WORKSPACE:-$PWD}"
OUT="${RUNNER_TEMP:-/tmp}/acse-gate"
RESULT="$OUT/result.json"

log() { printf '%s\n' "$*" >&2; }

# Workflow command escaping (GitHub: data escapes %, CR, LF; properties also : and ,).
esc_data() { local s=${1//'%'/'%25'}; s=${s//$'\r'/'%0D'}; s=${s//$'\n'/'%0A'}; printf '%s' "$s"; }
esc_prop() { local s; s=$(esc_data "$1"); s=${s//':'/'%3A'}; s=${s//','/'%2C'}; printf '%s' "$s"; }

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

sha256_hex() { sha256sum | cut -d ' ' -f 1; }

abspath() {
  case "$1" in
    /*) printf '%s' "$1" ;;
    *) printf '%s/%s' "$WORKSPACE" "$1" ;;
  esac
}

# --- Digests (the reference recipes of acse-gate-template-1 and acse-class-digest-1) -----------------------------------

# acse-gate-template-1 over a repository root: .github/workflows/acse-gate.yml and every file under
# .github/actions/acse-gate/, sorted bytewise, {format, files: [{path, sha256}]}, canonical JSON, sha256.
template_digest() {
  local root=$1
  (
    cd "$root" || exit 2
    local workflow=.github/workflows/acse-gate.yml action=.github/actions/acse-gate
    if [ -h "$workflow" ] || [ ! -f "$workflow" ] || [ -h "$action" ] || [ ! -d "$action" ]; then exit 2; fi
    if [ -n "$(find "$action" ! -type f ! -type d -print)" ]; then exit 2; fi
    { printf '%s\n' "$workflow"; find "$action" -type f -print; } | LC_ALL=C sort | while IFS= read -r path; do
      printf '%s\t%s\n' "$path" "$(sha256sum -- "$path" | cut -d ' ' -f 1)"
    done | jq -R -n '{format: "acse-gate-template-1", files: [inputs | split("\t") | {path: .[0], sha256: .[1]}]}' \
      | jq -jcS . | sha256sum | cut -d ' ' -f 1 | sed 's/^/sha256:/'
  )
}

# acse-class-digest-1 over one class directory of the bundle.
class_digest() {
  local dir=$1 check_id=$2
  (
    cd "$dir" || exit 2
    if [ -n "$(find . ! -type f ! -type d -print)" ]; then exit 2; fi
    find . -type f -print | sed 's|^\./||' | LC_ALL=C sort | while IFS= read -r path; do
      printf '%s\t%s\n' "$path" "$(sha256sum -- "$path" | cut -d ' ' -f 1)"
    done | jq -R -n --arg check_id "$check_id" \
      '{algorithm: "acse-class-digest-1", check_id: $check_id, files: [inputs | split("\t") | {path: .[0], sha256: .[1]}]}' \
      | jq -jcS . | sha256sum | cut -d ' ' -f 1 | sed 's/^/sha256:/'
  )
}

# The git tree id of a directory, as git rev-parse <commit>:<dir> gives it in the policy repository. GitHub fetches
# the action as an archive (no .git), so the tree is rebuilt from the files in a scratch index.
tree_id() {
  local dir=$1 scratch id
  scratch=$(mktemp -d)
  git init -q "$scratch/r"
  id=$(cd "$dir" && GIT_DIR="$scratch/r/.git" GIT_WORK_TREE="$dir" GIT_INDEX_FILE="$scratch/index" \
    git -c core.autocrlf=false -c core.safecrlf=false -c core.fileMode=true add -A --force -- . >/dev/null \
    && GIT_DIR="$scratch/r/.git" GIT_INDEX_FILE="$scratch/index" git write-tree)
  rm -rf "$scratch"
  [ -n "$id" ] && printf '%s\n' "$id"
}

# --- evaluate ---------------------------------------------------------------------------------------------------------

# Writes result.json for a run that could not evaluate. enforce_known tells decide whether the bundle could be read.
write_error() {
  local code=$1 message=$2
  jq -n --arg code "$code" --arg message "$message" --arg started "$STARTED_AT" --arg finished "$(now)" \
    --arg release "$TEMPLATE_RELEASE" --arg tdigest "${TEMPLATE_DIGEST:-}" --arg opa "$OPA_VERSION" \
    --arg bundle_name "${BUNDLE_NAME:-}" --arg tree "${BUNDLE_TREE:-}" --argjson has_enforce "${HAS_ENFORCE:-null}" \
    '{verdict: "error", error_code: $code, message: $message, started_at: $started, finished_at: $finished,
      template_release: $release, template_digest: $tdigest, evaluator_version: $opa,
      bundle_name: $bundle_name, bundle_tree_id: $tree, bundle_has_enforce: $has_enforce,
      address_hashing: "off", classes: [], rows: []}' >"$RESULT"
  echo "::error title=ACSE gate could not evaluate ($code)::$(esc_data "$message")"
  echo "verdict=error" >>"${GITHUB_OUTPUT:-/dev/null}"
}

install_opa() {
  local bin
  if [ -n "${ACSE_GATE_OPA_PATH:-}" ]; then
    bin=$(abspath "$ACSE_GATE_OPA_PATH")
  else
    if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
      log "the gate's pinned opa build is linux/amd64; this runner is $(uname -s)/$(uname -m)"
      return 1
    fi
    bin="$OUT/bin/opa"
    mkdir -p "$OUT/bin"
    curl -fsSL --retry 3 --max-time 120 -o "$bin" "$OPA_URL" || return 1
  fi
  if [ "$(sha256_hex <"$bin")" != "$OPA_SHA256_LINUX_AMD64" ]; then
    log "opa does not match the pinned checksum for $OPA_VERSION"
    return 1
  fi
  chmod 0755 "$bin" 2>/dev/null || true
  OPA="$bin"
}

cmd_evaluate() {
  rm -rf "$OUT"
  mkdir -p "$OUT"
  STARTED_AT=$(now)
  echo "$STARTED_AT" >"$OUT/started_at"

  TEMPLATE_DIGEST=$(template_digest "$POLICY_ROOT" 2>/dev/null || true)

  # The input: the caller's plan, read here and never sent anywhere.
  local plan tfvars=""
  plan=$(abspath "${ACSE_GATE_PLAN:?}")
  if [ ! -f "$plan" ] || ! jq -e 'type == "object"' "$plan" >/dev/null 2>&1; then
    write_error INPUT_UNREADABLE "the plan is not a JSON object (expected terraform show -json output): ${ACSE_GATE_PLAN}"
    return 0
  fi
  if [ -n "${ACSE_GATE_TFVARS:-}" ]; then
    tfvars=$(abspath "$ACSE_GATE_TFVARS")
    if [ ! -f "$tfvars" ] || ! jq -e 'type == "object"' "$tfvars" >/dev/null 2>&1; then
      write_error INPUT_UNREADABLE "the variables file is not a JSON object: ${ACSE_GATE_TFVARS}"
      return 0
    fi
  fi

  # The bundle: bundles/current names bundles/<name>/ (policy-repo-layout-1.2).
  local pointer="$POLICY_ROOT/bundles/current"
  if [ -h "$pointer" ] || [ ! -f "$pointer" ]; then
    write_error BUNDLE_UNAVAILABLE "bundles/current is missing from the policy repository"
    return 0
  fi
  BUNDLE_NAME=$(head -c 200 "$pointer" | tr -d '\n')
  if ! printf '%s' "$BUNDLE_NAME" | grep -Eq '^[a-z0-9][a-z0-9_-]{0,62}$' || [ "$BUNDLE_NAME" = "current" ] \
    || [ "$(wc -l <"$pointer")" -gt 1 ]; then
    write_error BUNDLE_INVALID "bundles/current does not name a bundle directory"
    return 0
  fi
  local bundle="$POLICY_ROOT/bundles/$BUNDLE_NAME"
  if [ -h "$bundle" ] || [ ! -d "$bundle" ]; then
    write_error BUNDLE_UNAVAILABLE "bundles/$BUNDLE_NAME is missing"
    return 0
  fi
  if [ -n "$(find "$bundle" ! -type f ! -type d -print)" ] || [ ! -f "$bundle/bundle.json" ] \
    || [ ! -d "$bundle/gate" ] || [ ! -d "$bundle/classes" ] \
    || ! jq -e '.gate_bundle_version == "1.0" and (.default_mode == "observe" or .default_mode == "enforce")' \
      "$bundle/bundle.json" >/dev/null 2>&1; then
    write_error BUNDLE_INVALID "bundles/$BUNDLE_NAME does not follow the bundle layout (bundle.json, gate/, classes/)"
    return 0
  fi
  HAS_ENFORCE=$(jq '.default_mode == "enforce" or any(.classes[]?; .mode == "enforce" or any(.label_modes[]?; .mode == "enforce"))' "$bundle/bundle.json")
  BUNDLE_TREE=$(tree_id "$bundle") || { write_error BUNDLE_UNAVAILABLE "the bundle's tree id could not be computed"; return 0; }

  if ! install_opa; then
    write_error EVALUATION_FAILED "opa ${OPA_VERSION} could not be installed with its pinned checksum"
    return 0
  fi

  # The evaluation: plain opa, the plan as input, the bundle as data (the bundle's documented invocation).
  local args=(eval --format json --capabilities "$ACTION_DIR/opa_capabilities.json" --input "$plan"
    --data "acse_bundle.control:$bundle/bundle.json"
    --data "acse_bundle.classes:$bundle/classes"
    --data "$bundle/gate")
  if [ -n "$tfvars" ]; then args+=(--data "acse_bundle.tfvars:$tfvars"); fi
  args+=('data.acse.gate.finding')
  if ! "$OPA" "${args[@]}" >"$OUT/opa.json" 2>"$OUT/opa.err"; then
    log "$(head -c 4000 "$OUT/opa.err")"
    write_error EVALUATION_FAILED "opa could not evaluate the bundle against the plan"
    return 0
  fi
  if ! jq -e '.result[0].expressions[0].value | .gate_finding_version == "1.0" and (.classes | type == "array")
        and (.findings | type == "array")' "$OUT/opa.json" >/dev/null 2>&1; then
    write_error NORMALISE_FAILED "the bundle did not produce a gate finding document (acse-gate-finding-1.0)"
    return 0
  fi
  jq '.result[0].expressions[0].value' "$OUT/opa.json" >"$OUT/finding.json"
  rm -f "$OUT/opa.json"
  if [ "$(jq '.classes | length' "$OUT/finding.json")" -eq 0 ]; then
    write_error BUNDLE_INVALID "the bundle ran no class: bundles/$BUNDLE_NAME/classes holds no class the gate can run"
    return 0
  fi

  # Rows: one per class and mode, with counts; a class with nothing to evaluate keeps one row with zero counts.
  jq '
    .findings as $f
    | [ .classes[] | .check_id as $id | .mode as $m
        | ([ $f[] | select(.check_id == $id) ] | group_by(.mode)) as $groups
        | if ($groups | length) == 0
          then [{check_id: $id, mode: $m, counts: {evaluated: 0, passed: 0, failed: 0, unknown: 0}, failed_addresses: []}]
          else [ $groups[] | {
                   check_id: $id, mode: .[0].mode,
                   counts: {evaluated: length,
                            passed: (map(select(.outcome == "pass")) | length),
                            failed: (map(select(.outcome == "fail")) | length),
                            unknown: (map(select(.outcome == "unknown")) | length)},
                   failed_addresses: (map(select(.outcome == "fail") | .address) | unique)} ]
          end ]
    | add // []' "$OUT/finding.json" >"$OUT/rows.json"

  # Class digests, over bundles/<name>/classes/<id>/ exactly as detect computes them.
  local digests='{}' id d
  while IFS= read -r id; do
    if [ ! -d "$bundle/classes/$id" ] || [ -h "$bundle/classes/$id" ]; then
      write_error BUNDLE_INVALID "the bundle ran class $id but has no classes/$id directory"
      return 0
    fi
    d=$(class_digest "$bundle/classes/$id" "$id") || { write_error BUNDLE_INVALID "classes/$id holds something other than regular files"; return 0; }
    digests=$(jq -c --arg id "$id" --arg d "$d" '. + {($id): $d}' <<<"$digests")
  done < <(jq -r '.classes[].check_id' "$OUT/finding.json" | sort -u)

  # Optional salted address hashes (only when bundle.json sets a salt; the salt never leaves the repository).
  local salt hashing=off
  salt=$(jq -r '.address_hashing.salt // empty' "$bundle/bundle.json")
  local hashes='{}'
  if [ -n "$salt" ]; then
    hashing=salted
    local addr h
    while IFS= read -r addr; do
      [ -n "$addr" ] || continue
      h="ah-$(printf '%s\n%s' "$salt" "$addr" | sha256_hex)"
      hashes=$(jq -c --arg a "$addr" --arg h "$h" '. + {($a): $h}' <<<"$hashes")
    done < <(jq -r '.[].failed_addresses[]' "$OUT/rows.json" | sort -u)
  fi

  local verdict
  verdict=$(jq -r 'if any(.findings[]; .outcome == "fail" and .mode == "enforce") then "fail" else "pass" end' \
    "$OUT/finding.json")

  jq -n --arg verdict "$verdict" --arg started "$STARTED_AT" --arg finished "$(now)" \
    --arg release "$TEMPLATE_RELEASE" --arg tdigest "$TEMPLATE_DIGEST" --arg opa "$OPA_VERSION" \
    --arg bundle_name "$BUNDLE_NAME" --arg tree "$BUNDLE_TREE" --argjson has_enforce "$HAS_ENFORCE" \
    --arg hashing "$hashing" --argjson digests "$digests" --argjson hashes "$hashes" \
    --slurpfile rows "$OUT/rows.json" --slurpfile finding "$OUT/finding.json" '
    {verdict: $verdict, started_at: $started, finished_at: $finished,
     template_release: $release, template_digest: $tdigest, evaluator_version: $opa,
     bundle_name: $bundle_name, bundle_tree_id: $tree, bundle_has_enforce: $has_enforce,
     address_hashing: $hashing, input_kind: $finding[0].input_kind,
     rows: [ $rows[0][] | {check_id, mode, class_digest: $digests[.check_id], counts}
             + (if $hashing == "salted" and .counts.failed > 0
                then {failed_address_hashes: ([.failed_addresses[] | $hashes[.]] | unique | .[:200])}
                else {} end) ]}' >"$RESULT"
  rm -f "$OUT/rows.json"

  echo "verdict=$verdict" >>"${GITHUB_OUTPUT:-/dev/null}"
  log "ACSE gate: verdict $verdict (bundle $BUNDLE_NAME, tree $BUNDLE_TREE, template $TEMPLATE_RELEASE $TEMPLATE_DIGEST)"
}

# --- annotate ---------------------------------------------------------------------------------------------------------

# The plan's module call source for a module path, or empty. $1 is a jq path into .configuration.
module_source() {
  jq -r --argjson p "$1" --arg name "$2" 'getpath($p + ["module_calls", $name, "source"]) // empty' "$PLAN_FILE" 2>/dev/null
}

# Collapses ./, ../ and duplicate slashes in a relative path (no filesystem access).
normalise_path() {
  local IFS=/ part out=()
  for part in $1; do
    case "$part" in
      '' | .) ;;
      ..) if [ ${#out[@]} -gt 0 ]; then unset 'out[${#out[@]}-1]'; fi ;;
      *) out+=("$part") ;;
    esac
  done
  local joined="${out[*]}"
  printf '%s' "${joined:-.}"
}

# Finds the block a plan address was configured in, by the plan's configuration and grep (no ACSE code, no parser).
# Prints "<file relative to the workspace>\t<line>\t<note>" or nothing. A resource in a module whose source is not in
# this repository is placed at the module call.
locate() {
  local address=$1 stripped dir path='["configuration","root_module"]'
  stripped=$(printf '%s' "$address" | sed -E 's/\[("([^"\\]|\\.)*"|[0-9]+)\]//g')
  local IFS=.
  # shellcheck disable=SC2206
  local parts=($stripped)
  unset IFS
  dir=$(normalise_path "$WORKDIR_REL")
  local i=0 n=${#parts[@]} src hit
  while [ $((i + 1)) -lt "$n" ] && [ "${parts[$i]}" = module ]; do
    local name=${parts[$((i + 1))]}
    src=$(module_source "$path" "$name")
    case "$src" in
      ./* | ../*)
        dir=$(normalise_path "$dir/$src")
        path=$(jq -c --arg n "$name" '. + ["module_calls", $n, "module"]' <<<"$path")
        i=$((i + 2))
        ;;
      *)
        hit=$(grep_first "$dir" "^[[:space:]]*module[[:space:]]+\"$(re_escape "$name")\"[[:space:]]*\\{")
        if [ -n "$hit" ]; then printf '%s\tmodule %s (its source is not in this repository)\n' "$hit" "$name"; fi
        return 0
        ;;
    esac
  done
  if [ $((i + 1)) -lt "$n" ] && [ "${parts[$i]}" = data ]; then i=$((i + 1)); fi
  [ $((i + 1)) -lt "$n" ] || return 0
  local type=${parts[$i]} name=${parts[$((i + 1))]}
  hit=$(grep_first "$dir" "^[[:space:]]*resource[[:space:]]+\"$(re_escape "$type")\"[[:space:]]+\"$(re_escape "$name")\"[[:space:]]*\\{")
  if [ -n "$hit" ]; then printf '%s\t\n' "$hit"; fi
}

re_escape() { printf '%s' "$1" | sed -E 's/[]*.^$+?(){}|[\\]/\\&/g'; }

# First "<file>\t<line>" in <dir>/*.tf (sorted) matching an extended regex.
grep_first() {
  local dir=$1 re=$2 f line
  [ -d "$WORKSPACE/$dir" ] || return 0
  while IFS= read -r f; do
    line=$(grep -n -E -m 1 -- "$re" "$WORKSPACE/$dir/$f" 2>/dev/null | cut -d : -f 1 || true)
    if [ -n "$line" ]; then
      printf '%s\t%s' "$(normalise_path "$dir/$f")" "$line"
      return 0
    fi
  done < <(cd "$WORKSPACE/$dir" && find . -maxdepth 1 -type f -name '*.tf' -print | sed 's|^\./||' | LC_ALL=C sort)
}

# The line where the block opened at $2 closes (brace counting outside strings and comments).
block_end() {
  awk -v start="$2" '
    NR < start { next }
    {
      line = $0; n = length(line); instr = 0
      for (i = 1; i <= n; i++) {
        c = substr(line, i, 1)
        if (instr) { if (c == "\\") { i++ } else if (c == "\"") { instr = 0 }; continue }
        if (c == "\"") { instr = 1; continue }
        if (c == "#" || (c == "/" && substr(line, i + 1, 1) == "/")) break
        if (c == "{") { depth++; opened = 1 } else if (c == "}") { depth-- }
      }
      if (opened && depth <= 0) { print NR; exit }
    }' "$1"
}

# The replacement for lines start..end of a resource block that applies a this_resource suggestion: every member the
# directive sets is removed (an attribute, or a nested block holding only attributes the directive sets) and the
# rendered lines are added before the closing brace. Exits 3 when that cannot be done safely (a map the directive
# extends, a nested block with other settings, a dynamic block): the suggestion is then given as text only.
build_replacement() {
  local file=$1 start=$2 end=$3 spec=$4 lines=$5
  awk -v start="$start" -v end="$end" -v specfile="$spec" -v linesfile="$lines" '
    function depth_delta(s,   i, c, n, d, instr) {
      n = length(s); d = 0; instr = 0
      for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (instr) { if (c == "\\") { i++ } else if (c == "\"") { instr = 0 }; continue }
        if (c == "\"") { instr = 1; continue }
        if (c == "#" || (c == "/" && substr(s, i + 1, 1) == "/")) break
        if (c == "{" || c == "[" || c == "(") d++
        else if (c == "}" || c == "]" || c == ")") d--
      }
      return d
    }
    # A removed member leaves no doubled blank line behind.
    function drop_blank(j) {
      if (nk > 0 && kept[nk] ~ /^[ \t]*$/ && (j + 1 > nb || body[j + 1] ~ /^[ \t]*$/)) nk--
    }
    BEGIN {
      while ((getline l < specfile) > 0) {
        split(l, f, " ")
        if (f[1] == "attr") attr[f[2]] = 1
        else if (f[1] == "map") map[f[2]] = 1
        else if (f[1] == "block") { block[f[2]] = 1; sub_ok[f[2] SUBSEP f[3]] = 1 }
      }
      nr = 0
      while ((getline l < linesfile) > 0) rendered[++nr] = l
    }
    NR == start { opening = $0; match($0, /^[ \t]*/); base = substr($0, 1, RLENGTH); next }
    NR > start && NR < end { body[++nb] = $0; next }
    NR == end { closing = $0 }
    END {
      if (start == end) exit 3
      i = 1; nk = 0
      while (i <= nb) {
        l = body[i]; name = ""
        if (match(l, /^[ \t]*dynamic[ \t]+"[^"]+"/)) {
          s = substr(l, RSTART, RLENGTH); sub(/^[ \t]*dynamic[ \t]+"/, "", s); sub(/"$/, "", s)
          if ((s in attr) || (s in map) || (s in block)) exit 3
        } else if (match(l, /^[ \t]*[A-Za-z0-9_-]+[ \t]*(=|[{])/)) {
          name = substr(l, RSTART, RLENGTH); sub(/^[ \t]*/, "", name); sub(/[ \t]*(=|[{])$/, "", name)
        }
        # The member spans until its brackets close.
        j = i; d = depth_delta(body[i])
        while (d > 0 && j < nb) { j++; d += depth_delta(body[j]) }
        if (name != "" && (name in map)) exit 3
        if (name != "" && (name in attr)) { drop_blank(j); i = j + 1; continue }
        if (name != "" && (name in block)) {
          for (k = i + 1; k < j; k++) {
            t = body[k]
            if (t ~ /^[ \t]*$/ || t ~ /^[ \t]*(#|\/\/)/) continue
            if (!match(t, /^[ \t]*[A-Za-z0-9_-]+[ \t]*=/)) exit 3
            nm = substr(t, RSTART, RLENGTH); sub(/^[ \t]*/, "", nm); sub(/[ \t]*=$/, "", nm)
            if (!((name SUBSEP nm) in sub_ok)) exit 3
            if (depth_delta(t) != 0) exit 3
          }
          drop_blank(j); i = j + 1; continue
        }
        for (k = i; k <= j; k++) kept[++nk] = body[k]
        i = j + 1
      }
      print opening
      for (k = 1; k <= nk; k++) print kept[k]
      if (nk > 0 && kept[nk] !~ /^[ \t]*$/) print ""
      for (k = 1; k <= nr; k++) print (rendered[k] == "" ? "" : base rendered[k])
      print closing
    }' "$file"
}

cmd_annotate() {
  mkdir -p "$OUT"
  echo '[]' >"$OUT/annotations.json"
  echo '[]' >"$OUT/suggestions.json"
  if [ ! -f "$RESULT" ]; then return 0; fi
  if [ "$(jq -r .verdict "$RESULT")" = error ]; then
    summary
    return 0
  fi
  PLAN_FILE=$(abspath "${ACSE_GATE_PLAN:?}")
  WORKDIR_REL=${ACSE_GATE_WORKDIR:-.}
  case "$WORKDIR_REL" in /*) WORKDIR_REL=${WORKDIR_REL#"$WORKSPACE"/} ;; esac

  local annotations="$OUT/annotations.ndjson" suggestions="$OUT/suggestions.ndjson"
  : >"$annotations"
  : >"$suggestions"

  # Enforce failures first, then observe failures, then unknowns: the order GitHub's annotation limits keep.
  local finding check_id outcome mode address level loc file line note controls message title
  local count=0
  while IFS= read -r finding; do
    check_id=$(jq -r .check_id <<<"$finding")
    outcome=$(jq -r .outcome <<<"$finding")
    mode=$(jq -r .mode <<<"$finding")
    address=$(jq -r .address <<<"$finding")
    loc=$(locate "$address" || true)
    file=$(cut -f 1 <<<"$loc")
    line=$(cut -f 2 <<<"$loc")
    note=$(cut -f 3 <<<"$loc")
    controls=$(jq -r '(.controls | length) as $n
      | [.controls[:5][] | .framework_id + " " + .control_id + (if .control_title then " (" + .control_title + ")" else "" end)]
      | join("; ") + (if $n > 5 then "; and \($n - 5) more" else "" end)' <<<"$finding")
    [ -n "$controls" ] || controls="none mapped"

    if [ "$outcome" = fail ]; then
      if [ "$mode" = enforce ]; then level=error; else level=warning; fi
      title="ACSE ${check_id} (${mode})"
      local mode_note=""
      if [ "$mode" = observe ]; then mode_note="; reported, does not fail the job"; fi
      message="${check_id} failed on ${address} (mode: ${mode}${mode_note}).
Controls: ${controls}."
      if [ -n "$note" ]; then message="${message}
Found at ${note}."; fi
      local suggestion_text=""
      if jq -e '.suggestion' <<<"$finding" >/dev/null; then
        suggestion_text=$(suggest "$finding" "$file" "$line" "$address" || true)
        message="${message}
${suggestion_text}"
      else
        message="${message}
No suggested change: this class has no remediation directive. Fix it in code, or see the class in your policy repository."
      fi
    else
      level=notice
      title="ACSE ${check_id} unknown"
      message="${check_id} could not be decided from the plan for ${address} ($(jq -r .unknown_reason <<<"$finding")). Unknown never fails the job.
Controls: ${controls}."
    fi

    jq -n -c --arg level "$level" --arg title "$title" --arg message "$message" --arg file "$file" --arg line "$line" \
      --arg check_id "$check_id" --arg outcome "$outcome" --arg mode "$mode" --arg address "$address" \
      '{level: $level, title: $title, message: $message, file: (if $file == "" then null else $file end),
        line: (if $line == "" then null else ($line | tonumber) end), check_id: $check_id, outcome: $outcome,
        mode: $mode, address: $address}' >>"$annotations"

    count=$((count + 1))
    if [ "$count" -le "$MAX_ANNOTATIONS" ]; then
      local props
      props="title=$(esc_prop "$title")"
      if [ -n "$file" ]; then props="file=$(esc_prop "$file"),line=$line,${props}"; fi
      echo "::${level} ${props}::$(esc_data "$message")"
    fi
  done < <(jq -c '.findings | map(select(.outcome != "pass"))
      | sort_by((if .outcome == "fail" and .mode == "enforce" then 0 elif .outcome == "fail" then 1 else 2 end), .check_id, .address)
      | .[]' "$OUT/finding.json")

  jq -s . "$annotations" >"$OUT/annotations.json"
  jq -s . "$suggestions" >"$OUT/suggestions.json"
  rm -f "$annotations" "$suggestions"

  post_suggestions
  summary
}

# Builds the suggested change for one failing finding. Appends a one-click candidate to suggestions.ndjson when one
# can be placed in the file, and prints the text for the annotation either way.
suggest() {
  local finding=$1 file=$2 line=$3 address=$4
  local target complete lines_json text
  target=$(jq -r .suggestion.target <<<"$finding")
  complete=$(jq -r .suggestion.complete <<<"$finding")
  lines_json=$(jq -c '.suggestion.lines // []' <<<"$finding")
  local rendered
  rendered=$(jq -r '.[]' <<<"$lines_json")
  if [ "$target" = new_resource ]; then
    text="Suggested change: add a $(jq -r .suggestion.resource_type <<<"$finding") beside it:"
  else
    text="Suggested change: set in this resource:"
  fi
  if [ "$lines_json" = "[]" ]; then
    text="${text}
$(jq -r '.suggestion.changes[] | "  " + (.path | join(".")) + (if .key then "[\"" + .key + "\"]" else "" end) + " = " + (.value | tojson)' <<<"$finding")"
  else
    text="${text}
${rendered}"
  fi
  if [ "$complete" != true ]; then
    text="${text}
Replace each <PLACEHOLDER> with your own value before applying it."
  fi

  # A one-click suggestion needs: rendered lines, a complete change, the resource block itself (not a module call).
  if [ "$lines_json" = "[]" ] || [ "$complete" != true ] || [ -z "$file" ] || [ -z "$line" ]; then
    printf '%s' "$text"
    return 0
  fi
  local path_abs="$WORKSPACE/$file" start end replacement
  if ! sed -n "${line}p" "$path_abs" | grep -Eq '^[[:space:]]*resource[[:space:]]'; then
    printf '%s' "$text"
    return 0
  fi
  start=$line
  end=$(block_end "$path_abs" "$start")
  [ -n "$end" ] || { printf '%s' "$text"; return 0; }
  local spec linesfile
  spec=$(mktemp)
  linesfile=$(mktemp)
  jq -r '.suggestion.changes[] | if (.path | length) == 1 and .key then "map " + .path[0]
         elif (.path | length) == 1 then "attr " + .path[0]
         else "block " + .path[0] + " " + .path[1] end' <<<"$finding" >"$spec"
  jq -r '.suggestion.lines[]' <<<"$finding" >"$linesfile"
  if [ "$target" = new_resource ]; then
    replacement=$(
      sed -n "${end}p" "$path_abs"
      echo
      base=$(sed -n "${start}p" "$path_abs" | sed -E 's/^([[:space:]]*).*/\1/')
      while IFS= read -r l; do if [ -n "$l" ]; then printf '%s%s\n' "$base" "$l"; else echo; fi; done <"$linesfile"
    )
    start=$end
  elif ! replacement=$(build_replacement "$path_abs" "$start" "$end" "$spec" "$linesfile"); then
    rm -f "$spec" "$linesfile"
    printf '%s\n%s' "$text" "(Not offered as a one-click change: the resource already sets part of it differently; merge it by hand.)"
    return 0
  fi
  rm -f "$spec" "$linesfile"
  jq -n -c --arg file "$file" --argjson start "$start" --argjson end "$end" --arg replacement "$replacement" \
    --arg check_id "$(jq -r .check_id <<<"$finding")" --arg mode "$(jq -r .mode <<<"$finding")" --arg address "$address" \
    --arg text "$text" \
    '{file: $file, start_line: $start, end_line: $end, replacement: ($replacement | split("\n")),
      check_id: $check_id, mode: $mode, address: $address, text: $text}' >>"$OUT/suggestions.ndjson"
  printf '%s' "$text"
}

# Posts each one-click suggestion as a pull request review comment, when the run is for a pull request and the job's
# own token may write pull request comments. Otherwise the annotation's text is the suggestion.
post_suggestions() {
  local event=${GITHUB_EVENT_NAME:-}
  local status="skipped" reason=""
  if [ "$(jq 'length' "$OUT/suggestions.json")" -eq 0 ]; then
    reason="no one-click suggestion"
  elif [ "$event" != pull_request ] && [ "$event" != pull_request_target ]; then
    reason="not a pull request run"
  elif [ -z "${ACSE_GATE_GITHUB_TOKEN:-}" ]; then
    reason="no token"
  else
    local pr head api repo
    pr=$(jq -r '.pull_request.number // empty' "${GITHUB_EVENT_PATH:-/dev/null}" 2>/dev/null || true)
    head=$(jq -r '.pull_request.head.sha // empty' "${GITHUB_EVENT_PATH:-/dev/null}" 2>/dev/null || true)
    api=${GITHUB_API_URL:-https://api.github.com}
    repo=${GITHUB_REPOSITORY:-}
    if [ -z "$pr" ] || [ -z "$head" ] || [ -z "$repo" ]; then
      reason="the pull request is not in the event"
    else
      local existing
      existing=$(curl -fsS --max-time 20 -H "Authorization: Bearer $ACSE_GATE_GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" "$api/repos/$repo/pulls/$pr/comments?per_page=100" 2>/dev/null \
        | jq -r '.[].body' 2>/dev/null | grep -o 'acse-gate:[0-9a-f]\{24\}' || true)
      local posted=0 present=0 refused=0 s marker body code fence
      while IFS= read -r s; do
        [ "$((posted + present))" -lt "$MAX_SUGGESTION_COMMENTS" ] || break
        marker="acse-gate:$(jq -c '[.check_id, .address, .replacement]' <<<"$s" | sha256_hex | cut -c 1-24)"
        if grep -qx "$marker" <<<"$existing"; then present=$((present + 1)); continue; fi
        fence='```'
        if jq -r '.replacement[]' <<<"$s" | grep -q '```'; then fence='````'; fi
        body="**ACSE gate · $(jq -r .check_id <<<"$s")** ($(jq -r .mode <<<"$s")): suggested change for \`$(jq -r .address <<<"$s")\`.

${fence}suggestion
$(jq -r '.replacement | join("\n")' <<<"$s")
${fence}
<!-- ${marker} -->"
        code=$(jq -n --arg body "$body" --arg commit "$head" --argjson s "$s" '
            {body: $body, commit_id: $commit, path: $s.file, line: $s.end_line, side: "RIGHT"}
            + (if $s.start_line < $s.end_line then {start_line: $s.start_line, start_side: "RIGHT"} else {} end)' \
          | curl -sS --max-time 20 -o /dev/null -w '%{http_code}' -X POST \
            -H "Authorization: Bearer $ACSE_GATE_GITHUB_TOKEN" -H "Accept: application/vnd.github+json" \
            "$api/repos/$repo/pulls/$pr/comments" --data-binary @- 2>/dev/null || echo 000)
        case "$code" in
          201) posted=$((posted + 1)) ;;
          403) reason="the job's token cannot write pull request comments (grant pull-requests: write to post suggestions)"; refused=$((refused + 1)); break ;;
          *) refused=$((refused + 1)) ;;
        esac
      done < <(jq -c '.[]' "$OUT/suggestions.json")
      if [ "$posted" -gt 0 ] || [ "$present" -gt 0 ]; then status="posted"; else status="text_only"; fi
      reason="${reason:-posted $posted, already present $present, not placed $refused (lines outside the diff stay as annotation text)}"
    fi
  fi
  jq -n --arg status "$status" --arg reason "$reason" '{status: $status, reason: $reason}' >"$OUT/suggestions-posted.json"
  if [ "$status" != posted ] && [ "$(jq 'length' "$OUT/suggestions.json")" -gt 0 ]; then
    echo "::notice title=ACSE gate::suggested changes are in the annotations as text ($(esc_data "$reason"))"
  fi
}

summary() {
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] || return 0
  {
    echo "### ACSE gate: $(jq -r .verdict "$RESULT")"
    echo
    echo "Bundle \`$(jq -r .bundle_name "$RESULT")\` (tree \`$(jq -r .bundle_tree_id "$RESULT")\`) · template $(jq -r .template_release "$RESULT") \`$(jq -r .template_digest "$RESULT")\` · opa $(jq -r .evaluator_version "$RESULT")"
    echo
    if [ "$(jq -r .verdict "$RESULT")" = error ]; then
      echo "The gate could not evaluate: \`$(jq -r .error_code "$RESULT")\` — $(jq -r .message "$RESULT")"
      return 0
    fi
    echo "| Class | Mode | Evaluated | Passed | Failed | Unknown |"
    echo "|---|---|---:|---:|---:|---:|"
    jq -r '.rows[] | "| \(.check_id) | \(.mode) | \(.counts.evaluated) | \(.counts.passed) | \(.counts.failed) | \(.counts.unknown) |"' "$RESULT"
    if [ "$(jq length "$OUT/annotations.json")" -gt 0 ]; then
      echo
      echo "| Outcome | Class | Mode | Resource | Where |"
      echo "|---|---|---|---|---|"
      jq -r '.[] | "| \(.outcome) | \(.check_id) | \(.mode) | `\(.address)` | \(if .file then "\(.file):\(.line)" else "—" end) |"' \
        "$OUT/annotations.json"
    fi
    echo
    echo "Enforce failures fail the job; observe failures and unknowns are reported and pass."
  } >>"$GITHUB_STEP_SUMMARY"
}

# --- report -----------------------------------------------------------------------------------------------------------

report_outcome() {
  jq -n --arg state "$1" --arg detail "$2" --argjson attempts "${3:-0}" --arg report_id "${4:-}" \
    '{state: $state, detail: $detail, attempts: $attempts, report_id: $report_id}' >"$OUT/report-outcome.json"
  echo "state=$1" >>"${GITHUB_OUTPUT:-/dev/null}"
}

trigger_of() {
  case "${GITHUB_EVENT_NAME:-}" in
    pull_request | pull_request_target | merge_group) echo change_request ;;
    push) echo push ;;
    schedule) echo schedule ;;
    workflow_dispatch | repository_dispatch) echo manual ;;
    *) echo other ;;
  esac
}

# Only fixed text from ACSE's answer is shown, cut to printable ASCII.
printable() { tr -cd '\40-\176' | cut -c 1-300; }

cmd_report() {
  mkdir -p "$OUT"
  if [ ! -f "$RESULT" ]; then report_outcome skipped "the gate produced no result"; return 0; fi
  local url=${ACSE_GATE_REPORT_URL:-} audience=${ACSE_GATE_AUDIENCE:-} tenant=${ACSE_GATE_TENANT_ID:-}
  if [ -z "$url" ] || [ -z "$audience" ] || [ -z "$tenant" ]; then
    report_outcome skipped "report-url, audience or tenant-id is not set"
    echo "::notice title=ACSE gate::no report sent (report-url, audience and tenant-id are needed); the verdict stands"
    return 0
  fi
  case "$url" in
    https://*) ;;
    http://127.0.0.1:* | http://127.0.0.1/* | http://localhost:* | http://localhost/*) ;;
    *)
      report_outcome skipped "the report URL must be https"
      echo "::warning title=ACSE gate report not sent::the report URL must be https; the verdict stands"
      return 0
      ;;
  esac
  if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
    report_outcome undelivered "no OIDC token: the calling job must grant id-token: write"
    echo "::warning title=ACSE gate report not sent::the job has no OIDC token (grant id-token: write); the verdict stands"
    return 0
  fi
  if ! printf '%s' "${ACSE_GATE_CHECK_RUN_ID:-}" | grep -Eq '^[0-9]{1,20}$'; then
    report_outcome undelivered "the runner does not expose the job's check run id"
    echo "::warning title=ACSE gate report not sent::this runner does not expose job.check_run_id; the verdict stands"
    return 0
  fi
  local commit=${GITHUB_SHA:-}
  if ! printf '%s' "$commit" | grep -Eq '^[0-9a-f]{40}([0-9a-f]{24})?$'; then
    report_outcome undelivered "no commit"
    return 0
  fi

  # gate-run-report-2.0, without oidc and keep_names_in_cloud (ACSE writes those from the verified token).
  local report_id finished
  report_id="grr-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  finished=$(now)
  jq -n --arg tenant "$tenant" --arg report_id "$report_id" --arg trigger "$(trigger_of)" --arg commit "$commit" \
    --arg finished "$finished" --arg check_run_id "$ACSE_GATE_CHECK_RUN_ID" --slurpfile r "$RESULT" '
    $r[0] as $r
    | {gate_report_format_version: "2.0", tenant_id: $tenant, report_id: $report_id, sent_at: "",
       run: {trigger: $trigger, commit: $commit, started_at: $r.started_at, finished_at: $finished},
       job: {check_run_id: $check_run_id},
       step: {input_kind: ($r.input_kind // "terraform_plan")},
       gate: {template_release: $r.template_release, template_digest: $r.template_digest,
              evaluator: "opa", evaluator_version: $r.evaluator_version},
       bundle: {tree_id: $r.bundle_tree_id, object_format: (if ($r.bundle_tree_id | length) == 64 then "sha256" else "sha1" end)},
       verdict: $r.verdict, address_hashing: $r.address_hashing}
    + (if $r.verdict == "error" then {error_code: $r.error_code} else {classes: $r.rows} end)' >"$OUT/report.json"

  # A report that cannot be well formed (no template digest or tree id) is not sent.
  if ! jq -e '(.gate.template_digest | test("^sha256:[0-9a-f]{64}$")) and (.bundle.tree_id | test("^[0-9a-f]{40}([0-9a-f]{24})?$"))' \
    "$OUT/report.json" >/dev/null 2>&1; then
    report_outcome undelivered "the template digest or the bundle tree id is unknown"
    echo "::warning title=ACSE gate report not sent::the template or bundle could not be identified; the verdict stands"
    return 0
  fi

  local attempt=0 wait=0 code body token detail state
  while [ "$attempt" -lt "$REPORT_ATTEMPTS" ]; do
    attempt=$((attempt + 1))
    [ "$wait" -eq 0 ] || sleep "$wait"
    wait=$((attempt * 10))
    # A fresh token per attempt, the same report_id (a 409 then means an earlier attempt was accepted).
    token=$(curl -sS --max-time 15 -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=$(jq -rn --arg a "$audience" '$a | @uri')" 2>/dev/null \
      | jq -r '.value // empty' 2>/dev/null || true)
    if [ -z "$token" ]; then detail="no OIDC token"; continue; fi
    echo "::add-mask::$token"
    jq --arg sent "$(now)" '.sent_at = $sent' "$OUT/report.json" >"$OUT/report.send.json"
    code=$(curl -sS --max-time "$REPORT_ATTEMPT_TIMEOUT" -o "$OUT/report.answer" -w '%{http_code}' -X POST \
      -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
      --data-binary "@$OUT/report.send.json" "$url" 2>/dev/null || true)
    token=""
    body=$(head -c 4096 "$OUT/report.answer" 2>/dev/null || true)
    rm -f "$OUT/report.answer" "$OUT/report.send.json"
    case "$code" in
      202)
        state=$(jq -r '.state // "counted"' <<<"$body" 2>/dev/null | printable)
        report_outcome "${state:-counted}" "accepted" "$attempt" "$report_id"
        echo "::notice title=ACSE gate::report accepted (${state:-counted})"
        return 0
        ;;
      409)
        if [ "$(jq -r '.code // empty' <<<"$body" 2>/dev/null)" = REPORT_DUPLICATE ]; then
          report_outcome counted "an earlier attempt was accepted" "$attempt" "$report_id"
          return 0
        fi
        ;;
    esac
    case "$code" in
      400 | 401 | 403 | 404 | 409 | 413)
        local rcode rmessage
        rcode=$(jq -r '.code // empty' <<<"$body" 2>/dev/null | printable)
        rmessage=$(jq -r '.message // empty' <<<"$body" 2>/dev/null | printable)
        report_outcome refused "${rcode:-HTTP $code}: ${rmessage}" "$attempt" "$report_id"
        echo "::warning title=ACSE refused the report (${rcode:-HTTP $code})::$(esc_data "${rmessage:-the report was refused}") The gate's verdict stands; only the report is lost."
        return 0
        ;;
      *) detail="HTTP ${code:-000}" ;;
    esac
  done
  report_outcome undelivered "${detail:-no answer}" "$attempt" "$report_id"
  echo "::warning title=ACSE gate report not delivered::$(esc_data "after $attempt attempts (${detail:-no answer}); the verdict stands, this run is not counted as seen")"
  return 0
}

# --- decide -----------------------------------------------------------------------------------------------------------

cmd_decide() {
  if [ ! -f "$RESULT" ]; then
    echo "::error title=ACSE gate::the gate did not run"
    exit 1
  fi
  local verdict
  verdict=$(jq -r .verdict "$RESULT")
  case "$verdict" in
    pass) echo "ACSE gate: pass" ;;
    fail)
      echo "::error title=ACSE gate failed::a class in enforce mode failed; see the annotations"
      exit 1
      ;;
    *)
      # The gate could not evaluate. Fail unless the bundle was read and enforces nothing (observe only).
      if [ "$(jq -r '.bundle_has_enforce' "$RESULT")" = false ]; then
        echo "::warning title=ACSE gate::could not evaluate, and the bundle enforces nothing: the job passes"
      else
        exit 1
      fi
      ;;
  esac
}

case "${1:-}" in
  evaluate) cmd_evaluate ;;
  annotate) cmd_annotate ;;
  report) cmd_report ;;
  decide) cmd_decide ;;
  *)
    echo "usage: gate.sh evaluate|annotate|report|decide" >&2
    exit 2
    ;;
esac
