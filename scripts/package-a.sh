#!/bin/bash
# Package A - Execution Identity & Capability Matrix.
#
# Independently probes the Claude, Codex and GitHub CLIs and writes durable
# evidence under <repo>/evidence/package-a/<run_id>/.
#
# Read-only by design: no logins, no installs, no writes to remote services.
#
# Deliberately no global `set -e`: a failing check must never stop the
# remaining checks from running.
#
# Hardening notes (Package A hardening pass):
#   * required completions must match EXACTLY: CRLF->LF and a single
#     trailing EOF newline are the only accepted transport normalizations
#   * every external probe runs in its own process GROUP (via setsid); a
#     harness-owned watcher sends TERM then KILL to the whole group so
#     descendants can never strand a hung run
#   * exit 137 is classified as TIMEOUT only when the harness watcher itself
#     proves it fired the kill; an unexplained 137 is a FAIL, not a timeout
#   * evidence.json is serialized by node, validated, then atomically renamed
#   * raw model/CLI stdout+stderr are redacted for known credential shapes
#     BEFORE anything is written into the canonical evidence directory
#   * the evidence destination must resolve inside the repo evidence root
#   * GitHub capability requires the authenticated login to exactly equal
#     the expected account, verified via a harmless read-only API call
#   * Claude runs from an isolated, repo-free temporary directory
#
# Exit codes: 0 harness ok + all capabilities pass, 1 harness ok + capability
# failure, 2 harness error.

set -uo pipefail

SCHEMA_VERSION="3.0.0"
PACKAGE="A"

CLAUDE_TIMEOUT_SECONDS="${LOOP_PACKAGE_A_CLAUDE_TIMEOUT_SECONDS:-30}"
CODEX_TIMEOUT_SECONDS="${LOOP_PACKAGE_A_CODEX_TIMEOUT_SECONDS:-120}"
GITHUB_TIMEOUT_SECONDS="${LOOP_PACKAGE_A_GITHUB_TIMEOUT_SECONDS:-30}"
VERSION_TIMEOUT_SECONDS="${LOOP_PACKAGE_A_VERSION_TIMEOUT_SECONDS:-15}"
GRACE_SECONDS="${LOOP_PACKAGE_A_GRACE_SECONDS:-10}"

# LOOP_PACKAGE_A_*_TIMEOUT_SECONDS / _GRACE_SECONDS are timing-only tuning
# knobs (used by --self-test to run fault-injection scenarios quickly). They
# cannot weaken any gate: they only change how long the harness waits, never
# what counts as PASS.

CLAUDE_REQUIRED_OUTPUT="CLAUDE_OK"
CODEX_REQUIRED_OUTPUT="CODEX_OK"
CLAUDE_PROMPT="Reply with exactly: ${CLAUDE_REQUIRED_OUTPUT}"
CODEX_PROMPT="Reply with exactly: ${CODEX_REQUIRED_OUTPUT}. Do not inspect files and do not run commands."
EXPECTED_GITHUB_LOGIN="Ciupanezulflipper"

SENTINEL_NAME="package-a-sentinel.txt"

# ---------- bootstrap: resolve script location using only bash builtins ----------
# dirname/realpath are external commands; REPO_ROOT/SELF_PATH must be
# resolvable before the dependency preflight below has even run, so only
# parameter expansion plus the cd/pwd builtins are used here.
SELF_SOURCE="${BASH_SOURCE[0]}"
case "$SELF_SOURCE" in
  */*) SELF_SOURCE_DIR="${SELF_SOURCE%/*}" ;;
  *) SELF_SOURCE_DIR="." ;;
esac
REPO_ROOT="$(cd "${SELF_SOURCE_DIR}/.." && pwd)"
SELF_PATH="${REPO_ROOT}/scripts/package-a.sh"

CHECK_ORDER=(claude_cli codex_cli github_cli)

# Every external executable invoked anywhere in this script - main path,
# helpers, cleanup/error paths, and self-test paths - must be listed here so
# a missing dependency surfaces as an explicit ERROR/BLOCKED, never a raw
# "command not found" or a false capability result. Bash builtins (cd, pwd,
# printf, echo, read, wait, trap, [[, mapfile, command) are deliberately
# excluded; `kill` is listed even though bash also has a kill builtin,
# since `command -v` accepts either.
REQUIRED_DEPS=(mktemp realpath sha256sum date od setsid kill node grep sed awk find sort cmp base64 wc cut tr mkdir rm mv head chmod cat id uname sleep env ln rmdir bash cp)

HARNESS_ERRORS=0
declare -A STATUSES EXIT_CODES

preflight_missing_deps() {
  local dep missing=()
  for dep in "${REQUIRED_DEPS[@]}"; do
    command -v "$dep" >/dev/null 2>&1 || missing+=("$dep")
  done
  printf '%s' "${missing[*]:-}"
}

# Preflight runs BEFORE any external command - including realpath, used just
# below to compute EVIDENCE_ROOT_CANONICAL - is relied upon. The process only
# exits here when executed directly, so sourcing the script for negative
# testing of individual helpers keeps working regardless.
BOOTSTRAP_MISSING_DEPS="$(preflight_missing_deps)"
if [[ -n "$BOOTSTRAP_MISSING_DEPS" && "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "HARNESS_STATUS=ERROR"
  echo "CAPABILITY_STATUS=NOT_RUN"
  echo "REASON=MISSING_DEPENDENCIES:${BOOTSTRAP_MISSING_DEPS}"
  echo "EVIDENCE_JSON=none"
  exit 2
fi

# ---------- lexical evidence-root symlink safety (must run BEFORE realpath) ----------
#
# `realpath -m` below would canonicalize straight through any symlink
# placed at <repo>/evidence or <repo>/evidence/package-a, silently following
# it to whatever it points at. Testing `-L` only AFTER that canonicalization
# (as before) inspects the resolved target, never the original symlink, so
# a pre-existing symlink at either path component would go undetected. These
# checks use pure Bash string construction and the `-L` test builtin - no
# external command, no canonicalization - and must run first.
EVIDENCE_LEXICAL_PARENT="${REPO_ROOT}/evidence"
EVIDENCE_LEXICAL_ROOT="${REPO_ROOT}/evidence/package-a"

evidence_lexical_unsafe_reason() {
  if [[ -L "$EVIDENCE_LEXICAL_PARENT" ]]; then
    printf 'EVIDENCE_PARENT_IS_SYMLINK:%s' "$EVIDENCE_LEXICAL_PARENT"
    return 0
  fi
  if [[ -L "$EVIDENCE_LEXICAL_ROOT" ]]; then
    printf 'EVIDENCE_ROOT_IS_SYMLINK:%s' "$EVIDENCE_LEXICAL_ROOT"
    return 0
  fi
  printf ''
  return 0
}

EVIDENCE_LEXICAL_UNSAFE_REASON="$(evidence_lexical_unsafe_reason)"
if [[ -n "$EVIDENCE_LEXICAL_UNSAFE_REASON" && "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "HARNESS_STATUS=ERROR"
  echo "CAPABILITY_STATUS=NOT_RUN"
  echo "REASON=EVIDENCE_ROOT_UNSAFE:${EVIDENCE_LEXICAL_UNSAFE_REASON}"
  echo "EVIDENCE_JSON=none"
  exit 2
fi

# Only after the lexical checks above have passed is it safe to canonicalize
# (and, later, mkdir -p / create-and-use) the evidence root: neither path
# component was a symlink at the moment this ran. The post-create
# containment/symlink re-checks further down (ensure_evidence_root_safe,
# verify_run_dir_containment) remain in place as documented, residual
# Bash-level defenses against the check-to-use window that follows - no
# stronger, kernel-level/race-free guarantee is claimed anywhere here.
EVIDENCE_ROOT_CANONICAL="$(realpath -m "${EVIDENCE_LEXICAL_ROOT}")"

# ---------- small helpers ----------

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
now_ms() { echo $(( $(date +%s%N) / 1000000 )); }

harness_error() {
  HARNESS_ERRORS=$(( HARNESS_ERRORS + 1 ))
  echo "harness-error: $1" >&2
}

check_index() {
  local i=0 name
  for name in "${CHECK_ORDER[@]}"; do
    [[ "$name" == "$1" ]] && { printf '%s' "$i"; return 0; }
    i=$(( i + 1 ))
  done
  printf '0'
  return 1
}

count_lines() { [[ -s "$1" ]] && wc -l <"$1" | tr -d ' ' || echo 0; }
file_sha256() { sha256sum -- "$1" 2>/dev/null | cut -d' ' -f1; }

# ---------- process-group bounded execution (fixes: 137 provenance, descendant termination) ----------

# run_bounded <timeout_s> <grace_s> <stdout_file> <stderr_file> <cmd...>
# Runs <cmd...> in its own session/process-group via setsid. If it has not
# exited after <timeout_s>, the harness sends TERM to the whole group; if it
# is still alive after <grace_s> more seconds, it sends KILL to the whole
# group. Echoes "<rc> <deadline_fired> <pgid>". deadline_fired=true is only
# ever set by this harness's own watcher actually acting, so it is
# deterministic proof the harness's deadline (not something external) caused
# any termination.
run_bounded() {
  local timeout_s="$1" grace_s="$2" out="$3" err="$4"; shift 4
  local marker="${out}.deadline_marker.$$"
  rm -f "$marker"
  setsid "$@" </dev/null >"$out" 2>"$err" &
  local pid=$!
  (
    sleep "$timeout_s"
    if kill -0 -- "-$pid" 2>/dev/null; then
      kill -TERM -- "-$pid" 2>/dev/null
      : >"$marker"
      sleep "$grace_s"
      kill -KILL -- "-$pid" 2>/dev/null
    fi
  ) </dev/null >/dev/null 2>&1 &
  local watcher=$!
  wait "$pid" 2>/dev/null
  local rc=$?
  kill "$watcher" 2>/dev/null
  wait "$watcher" 2>/dev/null
  local deadline_fired=false
  [[ -f "$marker" ]] && deadline_fired=true
  rm -f "$marker"
  printf '%s %s %s\n' "$rc" "$deadline_fired" "$pid"
}

# First line of `<cli> --version`, bounded, or "unavailable".
tool_version() {
  local bin="$1" out rc fired pid vout verr
  command -v "$bin" >/dev/null 2>&1 || { printf 'unavailable'; return; }
  vout="$(mktemp "${PKGA_TMP_ROOT}/version.XXXXXX")"
  verr="$(mktemp "${PKGA_TMP_ROOT}/version.XXXXXX")"
  read -r rc fired pid < <(run_bounded "$VERSION_TIMEOUT_SECONDS" 3 "$vout" "$verr" "$bin" --version)
  out="$(head -n 1 "$vout" 2>/dev/null)"
  rm -f "$vout" "$verr"
  redact_line "${out:-unknown}"
}

# ---------- exact completion matching ----------

# Echoes: exact | inexact_contains_token | inexact_no_token | absent.
# Only "exact" may pass. Allowed normalization is limited to exactly what is
# documented: CRLF->LF, and a single trailing newline at EOF may be ignored.
# No leading/trailing prose, no extra lines, no substring-only match.
classify_exact_output() {
  local file="$1" token="$2" payload
  [[ -f "$file" ]] || { printf 'absent'; return; }
  payload="$(cat -- "$file"; printf 'x')"
  payload="${payload%x}"
  [[ -z "$payload" ]] && { printf 'absent'; return; }
  payload="${payload//$'\r\n'/$'\n'}"
  payload="${payload//$'\r'/$'\n'}"
  if [[ "${payload: -1}" == $'\n' ]]; then
    payload="${payload%$'\n'}"
  fi
  if [[ "$payload" == "$token" ]]; then printf 'exact'; return; fi
  if [[ "$payload" == *"$token"* ]]; then printf 'inexact_contains_token'; return; fi
  printf 'inexact_no_token'
}

# ---------- structured completion extraction ----------

# extract_claude_completion <raw_stdout_file> <completion_out_file>
# Claude is invoked with --output-format json, so the completion is a field
# inside a structured envelope rather than raw stdout. Only that field is
# written to <completion_out_file>, which is what the exact matcher then
# sees: MCP banners and other diagnostic chatter on stdout/stderr can never
# become part of completion matching.
#
# A candidate is accepted only when it structurally matches the real Claude
# Code result envelope: an object with type === "result",
# subtype === "success", is_error === false, and a string `result` field.
# A generic object that merely happens to contain a `result` key (e.g.
# unrelated diagnostic JSON) is never accepted.
#
# Returns 0 with exactly one genuine envelope written to <completion_out_file>.
# Returns 3 when zero genuine envelopes are found (STRUCTURED_OUTPUT_UNPARSEABLE).
# Returns 4 when more than one genuine envelope is found: this is treated as
# ambiguous and deliberately NOT resolved by "last one wins" or any other
# guess, since the installed CLI's contract does not document a case where a
# single invocation legitimately emits more than one success envelope.
# There is deliberately NO last-line or substring fallback, so an
# unparseable or ambiguous response can never produce a PASS.
extract_claude_completion() {
  local raw="$1" out="$2" rc
  rm -f "$out"
  [[ -s "$raw" ]] || return 3
  PKGA_RAW_STDOUT="$raw" PKGA_COMPLETION_OUT="$out" node - <<'NODE_EOF' 2>/dev/null
const fs = require("fs");
const text = fs.readFileSync(process.env.PKGA_RAW_STDOUT, "utf8");
const isGenuineResultEnvelope = (e) =>
  e !== null &&
  typeof e === "object" &&
  !Array.isArray(e) &&
  e.type === "result" &&
  e.subtype === "success" &&
  e.is_error === false &&
  typeof e.result === "string";
const collect = (doc, out) => {
  if (Array.isArray(doc)) {
    for (const item of doc) if (isGenuineResultEnvelope(item)) out.push(item);
  } else if (isGenuineResultEnvelope(doc)) {
    out.push(doc);
  }
};
const envelopes = [];
try {
  collect(JSON.parse(text), envelopes);
} catch (e) {
  // The envelope is not alone on stdout: parse each line as its own JSON
  // document and keep every structurally genuine result envelope found.
  // This is still structured parsing - a non-JSON line, or a JSON object
  // that is not a genuine envelope, is never treated as completion text,
  // so diagnostics can never satisfy the match.
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      collect(JSON.parse(trimmed), envelopes);
    } catch (inner) { /* not an envelope line */ }
  }
}
if (envelopes.length === 0) process.exit(3);
if (envelopes.length > 1) process.exit(4);
fs.writeFileSync(process.env.PKGA_COMPLETION_OUT, envelopes[0].result);
NODE_EOF
  rc=$?
  [[ $rc -eq 0 && -f "$out" ]] && return 0
  [[ $rc -eq 3 || $rc -eq 4 ]] && return $rc
  return 3
}

# ---------- timeout / 137 disambiguation ----------

# classify_process_result <rc> <deadline_fired>
# Echoes "<STATUS> <REASON_CODE> <EVIDENCE_NOTE>".
# TIMEOUT is reserved for cases where THIS harness's own watcher proves it
# fired the kill (see run_bounded). An unexplained 137 (e.g. an external
# OOM-killer or operator `kill -9`) is a FAIL, never a TIMEOUT.
classify_process_result() {
  local rc="$1" fired="$2"
  if [[ "$fired" == true ]]; then
    printf 'TIMEOUT DEADLINE_EXCEEDED harness_watcher_fired_kill'
    return
  fi
  if [[ "$rc" -eq 137 ]]; then
    printf 'FAIL SIGKILL_BEFORE_DEADLINE external_sigkill_not_harness_timeout'
    return
  fi
  if [[ "$rc" -ne 0 ]]; then
    printf 'FAIL EXIT_NONZERO process_exit_nonzero'
    return
  fi
  printf 'OK OK normal_exit'
}

# ---------- content-sensitive filesystem snapshots ----------

# snapshot_dir <dir> <manifest_out> <error_out>
# Manifest line: type|relpath|size|sha256|symlink_target
# Returns non-zero on ANY failure and never leaves a manifest that could be
# mistaken for "empty and fine".
snapshot_dir() {
  local dir="$1" out="$2" errfile="$3"
  local raw="${out}.raw" names_hash type path size link hash

  : >"$errfile"
  rm -f "$out" "$raw"

  # Test-only fault injection hook: can only ever force a failure (never a
  # false success), so it cannot be used to manufacture a PASS. Only ever
  # set by `--self-test`.
  if [[ "${LOOP_PACKAGE_A_SELFTEST_FORCE_SNAPSHOT_FAIL:-}" == "1" ]]; then
    echo "snapshot: self-test injected fault (LOOP_PACKAGE_A_SELFTEST_FORCE_SNAPSHOT_FAIL=1)" >>"$errfile"
    return 1
  fi

  if [[ ! -d "$dir" ]]; then
    echo "snapshot: not a directory: $dir" >>"$errfile"
    return 1
  fi
  if ! ( cd "$dir" && find . -mindepth 1 -printf '%y|%p|%s|%l\n' | LC_ALL=C sort ) >"$raw" 2>>"$errfile"; then
    echo "snapshot: find enumeration failed" >>"$errfile"
    rm -f "$raw"
    return 1
  fi
  names_hash="$( ( cd "$dir" && find . -mindepth 1 -print0 | LC_ALL=C sort -z | sha256sum ) 2>>"$errfile" | cut -d' ' -f1 )"
  if [[ -z "$names_hash" ]]; then
    echo "snapshot: name-set hash failed" >>"$errfile"
    rm -f "$raw"
    return 1
  fi

  : >"$out"
  while IFS='|' read -r type path size link; do
    hash="-"
    if [[ "$type" == "f" ]]; then
      hash="$(sha256sum -- "${dir}/${path}" 2>>"$errfile" | cut -d' ' -f1)"
      if [[ -z "$hash" ]]; then
        echo "snapshot: content hash failed for ${path}" >>"$errfile"
        rm -f "$out" "$raw"
        return 1
      fi
    fi
    printf '%s|%s|%s|%s|%s\n' "$type" "$path" "$size" "$hash" "${link:--}" >>"$out"
  done <"$raw"
  printf '#names_sha256=%s\n' "$names_hash" >>"$out"
  rm -f "$raw"
  return 0
}

# cleanup_path <dir> [allowed_root]
# Only ever removes a path proven to be underneath a known-safe,
# harness-owned root (defaults to PKGA_TMP_ROOT if not given explicitly;
# self-test contexts pass their own scratch root). Never accepts an
# arbitrary target, and refuses (recording the failure) rather than
# guessing when no allowed root is configured.
cleanup_path() {
  local dir="$1" allowed_root="${2:-${PKGA_TMP_ROOT:-}}" resolved resolved_root
  [[ -n "$dir" && -e "$dir" ]] || return 0
  if [[ -z "$allowed_root" ]]; then
    harness_error "cleanup: no allowed root configured for: $dir"
    return 1
  fi
  resolved="$(realpath -m "$dir" 2>/dev/null)" || { harness_error "cleanup: could not resolve path: $dir"; return 1; }
  resolved_root="$(realpath -m "$allowed_root" 2>/dev/null)" || { harness_error "cleanup: could not resolve allowed root: $allowed_root"; return 1; }
  if [[ "$resolved" == "$resolved_root" || "$resolved" == "${resolved_root}/"* ]]; then
    rm -rf -- "$resolved"
    return 0
  fi
  harness_error "refusing to remove path outside allowed root (${resolved_root}): ${resolved}"
  return 1
}

# ---------- secret redaction (before persistence) ----------

SECRET_PATTERNS=(
  'gh[pousr]_[A-Za-z0-9]{20,}'
  'github_pat_[A-Za-z0-9_]{20,}'
  'sk-[A-Za-z0-9_-]{20,}'
  'xox[baprs]-[A-Za-z0-9-]{10,}'
  'AKIA[0-9A-Z]{16}'
  '(Authorization|authorization):[[:space:]]*(Bearer|token)[[:space:]]+[A-Za-z0-9._-]{10,}'
)

# redact_stream: reads text on stdin, writes redacted text on stdout. Shared
# by every path that can embed external-process output into evidence,
# including tool-version strings, so nothing bypasses redaction.
redact_stream() {
  LC_ALL=C awk '
    BEGIN { inkey = 0 }
    /BEGIN [A-Z ]*PRIVATE KEY/ { print "[REDACTED_PRIVATE_KEY_BLOCK]"; inkey = 1; next }
    /END [A-Z ]*PRIVATE KEY/ { inkey = 0; next }
    inkey == 1 { next }
    { print }
  ' 2>/dev/null | LC_ALL=C sed -E \
    -e 's/gh[pousr]_[A-Za-z0-9]{20,}/[REDACTED_TOKEN]/g' \
    -e 's/github_pat_[A-Za-z0-9_]{20,}/[REDACTED_TOKEN]/g' \
    -e 's/sk-[A-Za-z0-9_-]{20,}/[REDACTED_TOKEN]/g' \
    -e 's/xox[baprs]-[A-Za-z0-9-]{10,}/[REDACTED_TOKEN]/g' \
    -e 's/AKIA[0-9A-Z]{16}/[REDACTED_TOKEN]/g' \
    -e 's/(Authorization|authorization):[[:space:]]*(Bearer|token)[[:space:]]+[A-Za-z0-9._-]{10,}/\1: [REDACTED_TOKEN]/g' \
    2>/dev/null
}

# redact_line <string> -> echoes the redacted string (single-line values,
# e.g. `<cli> --version` output, that are embedded directly into evidence).
redact_line() {
  printf '%s' "$1" | redact_stream
}

# redact_to_evidence <raw_file> <dest_evidence_file>
# Writes a redacted copy of raw_file to dest_evidence_file (dest is always
# created, even if raw_file is absent). Echoes the count of redacted
# matches. The matched values themselves are never written anywhere and
# never printed.
redact_to_evidence() {
  local raw="$1" dest="$2" count=0 pattern n
  : >"$dest"
  [[ -f "$raw" ]] || { printf '0'; return; }
  redact_stream <"$raw" >"$dest"
  for pattern in "${SECRET_PATTERNS[@]}"; do
    n="$(grep --binary-files=text -cE "$pattern" -- "$raw" 2>/dev/null)"
    [[ "$n" =~ ^[0-9]+$ ]] || n=0
    count=$(( count + n ))
  done
  printf '%s' "$count"
}

# scan_secrets <target...> -> echoes finding count; report records file:line
# only, never the matched value. Defense-in-depth over already-redacted
# canonical evidence.
scan_secrets() {
  local report="${EVIDENCE_DIR}/secret-scan.txt" pattern target findings hits
  hits="$(mktemp "${PKGA_TMP_ROOT}/scan.XXXXXX")"
  for pattern in "${SECRET_PATTERNS[@]}"; do
    for target in "$@"; do
      [[ -e "$target" ]] || continue
      grep -rEn --binary-files=without-match "$pattern" "$target" 2>/dev/null \
        | grep -v "secret-scan.txt" | cut -d: -f1,2 >>"$hits"
    done
  done
  findings="$(count_lines "$hits")"
  cat "$hits" >>"$report"
  printf 'scan pass: patterns_checked=%d findings=%d\n' "${#SECRET_PATTERNS[@]}" "$findings" >>"$report"
  rm -f "$hits"
  printf '%s' "$findings"
}

# ---------- field capture for node-side JSON encoding ----------
# Values are base64-encoded on the way in, so quotes, backslashes, newlines,
# tabs, control characters and invalid byte sequences cannot corrupt the
# evidence file. Node decodes, validates UTF-8 and serializes.

kv() {
  printf '%s\t%s\t%s\n' "$1" "$2" "$(printf '%s' "$3" | base64 | tr -d '\n')" >>"$FIELDS_FILE"
}
kv_s() { kv s "$1" "$2"; }
kv_n() { kv n "$1" "$2"; }
kv_b() { kv b "$1" "$2"; }
kv_z() { kv z "$1" ""; }
kv_arr() { kv a "$1" ""; }

# Warning/error lines from an already-redacted stderr artifact, preserved
# verbatim as an array (never fatal by itself; see run_* PASS logic).
emit_stderr_warnings() {
  local base="$1" file="$2" i=0 line
  kv_arr "$base"
  if [[ -s "$file" ]]; then
    while IFS= read -r line; do
      kv_s "${base}.${i}" "$line"
      i=$(( i + 1 ))
    done < <(grep --binary-files=text -E 'ERROR|WARN|error:|warning:' "$file" 2>/dev/null | head -n 50)
  fi
  kv_n "${base}_count" "$i"
}

emit_check_common() {
  local idx="$1" name="$2" attempted="$3" process_started="$4" status="$5" reason="$6"
  kv_s  "checks.${idx}.name" "$name"
  kv_b  "checks.${idx}.attempted" "$attempted"
  kv_b  "checks.${idx}.process_started" "$process_started"
  kv_s  "checks.${idx}.status" "$status"
  kv_s  "checks.${idx}.reason_code" "$reason"
}

seed_not_run_fields() {
  local idx=0 name
  for name in "${CHECK_ORDER[@]}"; do
    emit_check_common "$idx" "$name" false false "NOT_RUN" "NOT_ATTEMPTED"
    kv_z "checks.${idx}.started_at"
    kv_z "checks.${idx}.completed_at"
    kv_z "checks.${idx}.duration_ms"
    kv_z "checks.${idx}.exit_code"
    kv_z "checks.${idx}.timeout_seconds"
    kv_z "checks.${idx}.stdout_artifact"
    kv_z "checks.${idx}.stderr_artifact"
    kv_z "checks.${idx}.required_output"
    kv_z "checks.${idx}.required_output_observed"
    kv_s "checks.${idx}.required_output_match" "not_applicable"
    STATUSES["$name"]="NOT_RUN"
    EXIT_CODES["$name"]=""
    idx=$(( idx + 1 ))
  done
}

record_result() {
  STATUSES["$1"]="$2"
  EXIT_CODES["$1"]="$3"
}

blocked_check() {
  local idx="$1" name="$2" timeout_s="$3" prereq="$4" required_output="${5:-}"
  local t1 completed_at
  t1="$(now_ms)"; completed_at="$(now_iso)"
  emit_check_common "$idx" "$name" true false "BLOCKED" "CLI_NOT_FOUND"
  kv_s "checks.${idx}.started_at" "$completed_at"
  kv_s "checks.${idx}.completed_at" "$completed_at"
  kv_n "checks.${idx}.duration_ms" 0
  kv_z "checks.${idx}.exit_code"
  kv_n "checks.${idx}.timeout_seconds" "$timeout_s"
  kv_z "checks.${idx}.stdout_artifact"
  kv_z "checks.${idx}.stderr_artifact"
  if [[ -n "$required_output" ]]; then
    kv_s "checks.${idx}.required_output" "$required_output"
  else
    kv_z "checks.${idx}.required_output"
  fi
  kv_b "checks.${idx}.required_output_observed" false
  kv_s "checks.${idx}.required_output_match" "not_executed"
  kv_s "checks.${idx}.metadata.blocked_prerequisite" "$prereq"
  record_result "$name" "BLOCKED" ""
}

# ---------- checks ----------

run_claude_check() {
  local name="claude_cli" idx rc fired pid started_at completed_at t0 t1 elapsed match status reason evidence_note extract_rc
  local out="${EVIDENCE_DIR}/claude.stdout.txt" err="${EVIDENCE_DIR}/claude.stderr.txt"
  local raw_out="${PKGA_TMP_ROOT}/raw/claude.stdout.txt" raw_err="${PKGA_TMP_ROOT}/raw/claude.stderr.txt"
  local raw_completion="${PKGA_TMP_ROOT}/raw/claude.completion.txt"
  local completion="${EVIDENCE_DIR}/claude.completion.txt"
  local parsed=false redacted_completion
  local redacted_out redacted_err workdir
  idx="$(check_index "$name")"

  if ! command -v claude >/dev/null 2>&1; then
    blocked_check "$idx" "$name" "$CLAUDE_TIMEOUT_SECONDS" "claude executable not on PATH" "$CLAUDE_REQUIRED_OUTPUT"
    return
  fi

  workdir="$(mktemp -d "${PKGA_TMP_ROOT}/claude-workdir.XXXXXX")"

  started_at="$(now_iso)"; t0="$(now_ms)"
  read -r rc fired pid < <( cd "$workdir" && run_bounded "$CLAUDE_TIMEOUT_SECONDS" "$GRACE_SECONDS" "$raw_out" "$raw_err" \
    claude -p --max-turns 1 --permission-mode default --tools "" --output-format json "$CLAUDE_PROMPT" )
  t1="$(now_ms)"; completed_at="$(now_iso)"
  elapsed=$(( t1 - t0 ))

  read -r status reason evidence_note < <(classify_process_result "$rc" "$fired")
  extract_claude_completion "$raw_out" "$raw_completion"
  extract_rc=$?
  if [[ $extract_rc -eq 0 ]]; then
    parsed=true
    match="$(classify_exact_output "$raw_completion" "$CLAUDE_REQUIRED_OUTPUT")"
  elif [[ $extract_rc -eq 4 ]]; then
    match="ambiguous_multiple_result_envelopes"
  else
    match="structured_output_unparseable"
  fi

  if [[ "$status" == "OK" ]]; then
    if [[ "$parsed" != true ]]; then
      if [[ $extract_rc -eq 4 ]]; then
        status="FAIL"; reason="AMBIGUOUS_MULTIPLE_RESULT_ENVELOPES"
      else
        status="FAIL"; reason="STRUCTURED_OUTPUT_UNPARSEABLE"
      fi
    elif [[ "$match" == "exact" ]]; then
      status="PASS"; reason="OK"
    else
      status="FAIL"; reason="REQUIRED_OUTPUT_NOT_EXACT"
    fi
  fi

  redacted_out="$(redact_to_evidence "$raw_out" "$out")"
  redacted_err="$(redact_to_evidence "$raw_err" "$err")"
  redacted_completion="$(redact_to_evidence "$raw_completion" "$completion")"

  emit_check_common "$idx" "$name" true true "$status" "$reason"
  kv_s "checks.${idx}.started_at" "$started_at"
  kv_s "checks.${idx}.completed_at" "$completed_at"
  kv_n "checks.${idx}.duration_ms" "$elapsed"
  kv_n "checks.${idx}.exit_code" "$rc"
  kv_n "checks.${idx}.timeout_seconds" "$CLAUDE_TIMEOUT_SECONDS"
  kv_s "checks.${idx}.stdout_artifact" "claude.stdout.txt"
  kv_s "checks.${idx}.stderr_artifact" "claude.stderr.txt"
  kv_s "checks.${idx}.required_output" "$CLAUDE_REQUIRED_OUTPUT"
  kv_b "checks.${idx}.required_output_observed" "$([[ "$match" == "exact" ]] && echo true || echo false)"
  kv_s "checks.${idx}.required_output_match" "$match"
  kv_s "checks.${idx}.completion_artifact" "claude.completion.txt"
  kv_s "checks.${idx}.metadata.completion_source" "structured_json_envelope_result_field"
  kv_s "checks.${idx}.metadata.output_format" "json"
  kv_b "checks.${idx}.metadata.structured_output_parsed" "$parsed"
  kv_s "checks.${idx}.metadata.completion_matching_policy" "exact match against the extracted result field only; stdout/stderr diagnostics are never matched and there is no last-line fallback"
  kv_n "checks.${idx}.metadata.redacted_count_completion" "$redacted_completion"
  kv_s "checks.${idx}.metadata.cwd" "$workdir"
  kv_s "checks.${idx}.metadata.cwd_isolation" "isolated_tmp_dir_no_repo_files"
  kv_s "checks.${idx}.metadata.mode" "default"
  kv_n "checks.${idx}.metadata.max_turns" 1
  kv_s "checks.${idx}.metadata.timeout_mechanism" "setsid process-group watcher: TERM at deadline, KILL after ${GRACE_SECONDS}s grace"
  kv_s "checks.${idx}.metadata.timeout_evidence" "$evidence_note"
  kv_b "checks.${idx}.metadata.deadline_fired" "$fired"
  kv_n "checks.${idx}.metadata.deadline_ms" "$(( CLAUDE_TIMEOUT_SECONDS * 1000 ))"
  kv_n "checks.${idx}.metadata.redacted_count_stdout" "$redacted_out"
  kv_n "checks.${idx}.metadata.redacted_count_stderr" "$redacted_err"
  kv_n "checks.${idx}.metadata.stderr_lines" "$(count_lines "$err")"
  emit_stderr_warnings "checks.${idx}.metadata.stderr_warnings" "$err"

  cleanup_path "$workdir"
  record_result "$name" "$status" "$rc"
}

run_codex_check() {
  local name="codex_cli" idx rc fired pid started_at completed_at t0 t1 elapsed match status reason evidence_note
  local out="${EVIDENCE_DIR}/codex.stdout.txt" err="${EVIDENCE_DIR}/codex.stderr.txt"
  local raw_out="${PKGA_TMP_ROOT}/raw/codex.stdout.txt" raw_err="${PKGA_TMP_ROOT}/raw/codex.stderr.txt"
  # Codex writes its final agent message to a dedicated file (-o /
  # --output-last-message). It lives outside the monitored workdir, so
  # requesting it cannot dirty the filesystem snapshot.
  local raw_final="${PKGA_TMP_ROOT}/raw/codex.final-message.txt"
  local final="${EVIDENCE_DIR}/codex.final-message.txt"
  local final_present=false redacted_final
  local redacted_out redacted_err
  local before="${EVIDENCE_DIR}/codex.fs-before.txt" after="${EVIDENCE_DIR}/codex.fs-after.txt"
  local snap_err="${EVIDENCE_DIR}/codex.fs-snapshot-errors.txt"
  local workdir sentinel sentinel_hash_before sentinel_hash_after
  local before_ok=false after_ok=false fs_unchanged_known=false fs_unchanged=false
  local sentinel_present_after=false sentinel_hash_matches=false retained=false
  local sentinel_link symlink_sentinel_supported=false
  idx="$(check_index "$name")"

  if ! command -v codex >/dev/null 2>&1; then
    blocked_check "$idx" "$name" "$CODEX_TIMEOUT_SECONDS" "codex executable not on PATH" "$CODEX_REQUIRED_OUTPUT"
    kv_s "checks.${idx}.metadata.sandbox_mode" "read-only"
    kv_b "checks.${idx}.metadata.ephemeral_requested" true
    kv_z "checks.${idx}.metadata.workdir"
    kv_z "checks.${idx}.metadata.filesystem.final_workdir_state_unchanged"
    kv_s "checks.${idx}.metadata.filesystem.verification" "not_executed"
    return
  fi

  workdir="$(mktemp -d "${PKGA_TMP_ROOT}/codex-workdir.XXXXXX")"
  if [[ ! -d "$workdir" ]]; then
    harness_error "could not create isolated codex workdir"
    started_at="$(now_iso)"
    emit_check_common "$idx" "$name" true false "ERROR" "WORKDIR_CREATE_FAILED"
    kv_s "checks.${idx}.started_at" "$started_at"
    kv_s "checks.${idx}.completed_at" "$started_at"
    kv_n "checks.${idx}.duration_ms" 0
    kv_z "checks.${idx}.exit_code"
    kv_n "checks.${idx}.timeout_seconds" "$CODEX_TIMEOUT_SECONDS"
    kv_z "checks.${idx}.stdout_artifact"
    kv_z "checks.${idx}.stderr_artifact"
    kv_s "checks.${idx}.required_output" "$CODEX_REQUIRED_OUTPUT"
    kv_b "checks.${idx}.required_output_observed" false
    kv_s "checks.${idx}.required_output_match" "not_executed"
    kv_z "checks.${idx}.metadata.filesystem.final_workdir_state_unchanged"
    kv_s "checks.${idx}.metadata.filesystem.verification" "workdir_create_failed"
    record_result "$name" "ERROR" ""
    return
  fi

  # Seed a known sentinel so an unchanged manifest is a positive statement
  # about real content, not an artifact of an empty directory. Also makes
  # same-size content mutation detectable via content hash, not just size.
  sentinel="${workdir}/${SENTINEL_NAME}"
  printf 'package-a sentinel %s\n' "$RUN_ID" >"$sentinel"
  sentinel_hash_before="$(file_sha256 "$sentinel")"

  # Also seed a symlink sentinel, when this environment supports symlinks at
  # all: its target is captured in the manifest's symlink_target column, so
  # a process that repoints it (without adding/removing any directory
  # entry, and without changing the sentinel file's own bytes) is still
  # caught by the before/after manifest comparison below.
  sentinel_link="${workdir}/${SENTINEL_NAME}.link"
  if ln -s "$SENTINEL_NAME" "$sentinel_link" 2>/dev/null; then
    symlink_sentinel_supported=true
  fi

  if snapshot_dir "$workdir" "$before" "${snap_err}.before"; then before_ok=true; fi

  started_at="$(now_iso)"; t0="$(now_ms)"
  read -r rc fired pid < <( cd "$workdir" && run_bounded "$CODEX_TIMEOUT_SECONDS" "$GRACE_SECONDS" "$raw_out" "$raw_err" \
    codex exec --ephemeral --skip-git-repo-check --sandbox read-only \
      --output-last-message "$raw_final" "$CODEX_PROMPT" )
  t1="$(now_ms)"; completed_at="$(now_iso)"
  elapsed=$(( t1 - t0 ))

  if snapshot_dir "$workdir" "$after" "${snap_err}.after"; then after_ok=true; fi
  cat "${snap_err}.before" "${snap_err}.after" >"$snap_err" 2>/dev/null
  rm -f "${snap_err}.before" "${snap_err}.after"

  # final_workdir_state_unchanged is only knowable when BOTH snapshots
  # succeeded. This is a before/after comparison of the monitored workdir
  # only: it cannot prove no transient file was created+deleted between
  # snapshots, and it cannot prove nothing was written outside the workdir.
  if [[ "$before_ok" == true && "$after_ok" == true ]]; then
    fs_unchanged_known=true
    cmp -s "$before" "$after" && fs_unchanged=true || fs_unchanged=false
  fi

  if [[ -f "$sentinel" ]]; then
    sentinel_present_after=true
    sentinel_hash_after="$(file_sha256 "$sentinel")"
    [[ -n "$sentinel_hash_after" && "$sentinel_hash_after" == "$sentinel_hash_before" ]] && sentinel_hash_matches=true
  else
    sentinel_hash_after=""
  fi

  read -r status reason evidence_note < <(classify_process_result "$rc" "$fired")
  [[ -s "$raw_final" ]] && final_present=true
  # Matched against the dedicated final-message file only: never stdout,
  # never a substring, never a last line.
  match="$(classify_exact_output "$raw_final" "$CODEX_REQUIRED_OUTPUT")"

  if [[ "$status" == "OK" ]]; then
    if [[ "$fs_unchanged_known" != true ]]; then
      harness_error "codex filesystem snapshot failed (before_ok=${before_ok} after_ok=${after_ok})"
      status="ERROR"; reason="SNAPSHOT_FAILED"
    elif [[ "$final_present" != true ]]; then
      status="FAIL"; reason="FINAL_OUTPUT_MISSING"
    elif [[ "$match" != "exact" ]]; then
      status="FAIL"; reason="REQUIRED_OUTPUT_NOT_EXACT"
    elif [[ "$fs_unchanged" != true ]]; then
      status="FAIL"; reason="WORKDIR_MUTATED"
    elif [[ "$sentinel_present_after" != true || "$sentinel_hash_matches" != true ]]; then
      status="FAIL"; reason="SENTINEL_VIOLATED"
    else
      status="PASS"; reason="OK"
    fi
  elif [[ "$fs_unchanged_known" != true ]]; then
    harness_error "codex filesystem snapshot failed (before_ok=${before_ok} after_ok=${after_ok})"
  fi

  redacted_out="$(redact_to_evidence "$raw_out" "$out")"
  redacted_err="$(redact_to_evidence "$raw_err" "$err")"
  redacted_final="$(redact_to_evidence "$raw_final" "$final")"

  emit_check_common "$idx" "$name" true true "$status" "$reason"
  kv_s "checks.${idx}.started_at" "$started_at"
  kv_s "checks.${idx}.completed_at" "$completed_at"
  kv_n "checks.${idx}.duration_ms" "$elapsed"
  kv_n "checks.${idx}.exit_code" "$rc"
  kv_n "checks.${idx}.timeout_seconds" "$CODEX_TIMEOUT_SECONDS"
  kv_s "checks.${idx}.stdout_artifact" "codex.stdout.txt"
  kv_s "checks.${idx}.stderr_artifact" "codex.stderr.txt"
  kv_s "checks.${idx}.required_output" "$CODEX_REQUIRED_OUTPUT"
  kv_b "checks.${idx}.required_output_observed" "$([[ "$match" == "exact" ]] && echo true || echo false)"
  kv_s "checks.${idx}.required_output_match" "$match"
  kv_s "checks.${idx}.completion_artifact" "codex.final-message.txt"
  kv_s "checks.${idx}.metadata.completion_source" "codex_output_last_message_file"
  kv_b "checks.${idx}.metadata.final_output_present" "$final_present"
  kv_s "checks.${idx}.metadata.completion_matching_policy" "exact match against the dedicated --output-last-message file only; stdout/stderr are never matched, and a missing or unreadable file is a FAIL"
  kv_n "checks.${idx}.metadata.redacted_count_completion" "$redacted_final"
  kv_s "checks.${idx}.metadata.sandbox_mode" "read-only"
  kv_b "checks.${idx}.metadata.ephemeral_requested" true
  kv_b "checks.${idx}.metadata.skip_git_repo_check" true
  kv_s "checks.${idx}.metadata.workdir" "$workdir"
  kv_s "checks.${idx}.metadata.cwd_isolation" "isolated_tmp_dir_no_repo_files"
  kv_s "checks.${idx}.metadata.timeout_mechanism" "setsid process-group watcher: TERM at deadline, KILL after ${GRACE_SECONDS}s grace"
  kv_s "checks.${idx}.metadata.timeout_evidence" "$evidence_note"
  kv_b "checks.${idx}.metadata.deadline_fired" "$fired"
  kv_n "checks.${idx}.metadata.deadline_ms" "$(( CODEX_TIMEOUT_SECONDS * 1000 ))"
  kv_n "checks.${idx}.metadata.redacted_count_stdout" "$redacted_out"
  kv_n "checks.${idx}.metadata.redacted_count_stderr" "$redacted_err"
  kv_s "checks.${idx}.metadata.filesystem.method" "type|relpath|size|sha256|symlink_target manifest plus NUL-safe name-set hash"
  kv_b "checks.${idx}.metadata.filesystem.snapshot_before_ok" "$before_ok"
  kv_b "checks.${idx}.metadata.filesystem.snapshot_after_ok" "$after_ok"
  if [[ "$fs_unchanged_known" == true ]]; then
    kv_b "checks.${idx}.metadata.filesystem.final_workdir_state_unchanged" "$fs_unchanged"
  else
    kv_z "checks.${idx}.metadata.filesystem.final_workdir_state_unchanged"
  fi
  kv_b "checks.${idx}.metadata.filesystem.unchanged_known" "$fs_unchanged_known"
  kv_s "checks.${idx}.metadata.filesystem.claim_scope" "before_after_snapshot_of_monitored_workdir_only"
  kv_s "checks.${idx}.metadata.filesystem.claim_caveat" "cannot prove absence of a transient create+delete between snapshots, and cannot prove nothing was written outside the monitored workdir; see Package A.5 for OS-enforced isolation proof"
  kv_n "checks.${idx}.metadata.filesystem.entries_before" "$(count_lines "$before")"
  kv_n "checks.${idx}.metadata.filesystem.entries_after" "$(count_lines "$after")"
  kv_s "checks.${idx}.metadata.filesystem.manifest_before_sha256" "$(file_sha256 "$before")"
  kv_s "checks.${idx}.metadata.filesystem.manifest_after_sha256" "$(file_sha256 "$after")"
  kv_s "checks.${idx}.metadata.filesystem.manifest_before_artifact" "codex.fs-before.txt"
  kv_s "checks.${idx}.metadata.filesystem.manifest_after_artifact" "codex.fs-after.txt"
  kv_s "checks.${idx}.metadata.filesystem.snapshot_error_artifact" "codex.fs-snapshot-errors.txt"
  kv_n "checks.${idx}.metadata.filesystem.snapshot_error_lines" "$(count_lines "$snap_err")"
  kv_s "checks.${idx}.metadata.filesystem.sentinel_name" "$SENTINEL_NAME"
  kv_b "checks.${idx}.metadata.filesystem.symlink_sentinel_supported" "$symlink_sentinel_supported"
  kv_s "checks.${idx}.metadata.filesystem.sentinel_hash_before" "$sentinel_hash_before"
  kv_s "checks.${idx}.metadata.filesystem.sentinel_hash_after" "${sentinel_hash_after:-absent}"
  kv_b "checks.${idx}.metadata.filesystem.sentinel_present_after" "$sentinel_present_after"
  kv_b "checks.${idx}.metadata.filesystem.sentinel_hash_matches" "$sentinel_hash_matches"
  kv_n "checks.${idx}.metadata.stderr_lines" "$(count_lines "$err")"
  emit_stderr_warnings "checks.${idx}.metadata.stderr_warnings_non_fatal" "$err"

  # Retain the workdir for forensics whenever it is not provably clean.
  if [[ "$fs_unchanged_known" == true && "$fs_unchanged" == true ]]; then
    cleanup_path "$workdir"
  else
    retained=true
  fi
  kv_b "checks.${idx}.metadata.workdir_retained_for_forensics" "$retained"

  record_result "$name" "$status" "$rc"
}

run_github_check() {
  local name="github_cli" idx started_at completed_at t0 t1 elapsed status reason
  local auth_rc auth_fired auth_pid ident_rc ident_fired ident_pid
  local auth_raw_out auth_raw_err ident_raw_out ident_raw_err
  local aout="${EVIDENCE_DIR}/github-auth.stdout.txt" aerr="${EVIDENCE_DIR}/github-auth.stderr.txt"
  local iout="${EVIDENCE_DIR}/github-identity.stdout.txt" ierr="${EVIDENCE_DIR}/github-identity.stderr.txt"
  local hostname_flag_supported=false active_flag_supported=false
  local auth_status_args=() identity_login="" identity_match=false
  local auth_status auth_reason auth_note ident_status ident_reason ident_note
  idx="$(check_index "$name")"

  if ! command -v gh >/dev/null 2>&1; then
    blocked_check "$idx" "$name" "$GITHUB_TIMEOUT_SECONDS" "gh executable not on PATH"
    kv_z "checks.${idx}.metadata.auth_exit_code"
    kv_z "checks.${idx}.metadata.identity_exit_code"
    kv_s "checks.${idx}.metadata.identity_expected" "$EXPECTED_GITHUB_LOGIN"
    kv_z "checks.${idx}.metadata.identity_actual"
    return
  fi

  # Feature-detect optional flags: gh 2.46.0 does not support
  # `auth status --active`; newer versions might. Never assume.
  local help_out help_err
  help_out="$(mktemp "${PKGA_TMP_ROOT}/gh-help.XXXXXX")"
  help_err="$(mktemp "${PKGA_TMP_ROOT}/gh-help.XXXXXX")"
  run_bounded 5 2 "$help_out" "$help_err" gh auth status --help >/dev/null 2>&1
  if grep -q -- '--hostname' "$help_out" 2>/dev/null; then hostname_flag_supported=true; fi
  if grep -q -- '--active' "$help_out" 2>/dev/null; then active_flag_supported=true; fi
  rm -f "$help_out" "$help_err"

  [[ "$hostname_flag_supported" == true ]] && auth_status_args+=(--hostname github.com)
  [[ "$active_flag_supported" == true ]] && auth_status_args+=(--active)

  auth_raw_out="${PKGA_TMP_ROOT}/raw/github-auth.stdout.txt"
  auth_raw_err="${PKGA_TMP_ROOT}/raw/github-auth.stderr.txt"
  ident_raw_out="${PKGA_TMP_ROOT}/raw/github-identity.stdout.txt"
  ident_raw_err="${PKGA_TMP_ROOT}/raw/github-identity.stderr.txt"

  started_at="$(now_iso)"; t0="$(now_ms)"

  # Authentication proof: never prints token values (gh masks them itself).
  read -r auth_rc auth_fired auth_pid < <( cd "$PKGA_TMP_ROOT" && run_bounded "$GITHUB_TIMEOUT_SECONDS" "$GRACE_SECONDS" \
    "$auth_raw_out" "$auth_raw_err" gh auth status "${auth_status_args[@]}" )

  # Harmless authenticated read-only capability + identity probe.
  read -r ident_rc ident_fired ident_pid < <( cd "$PKGA_TMP_ROOT" && run_bounded "$GITHUB_TIMEOUT_SECONDS" "$GRACE_SECONDS" \
    "$ident_raw_out" "$ident_raw_err" gh api user --jq .login )

  t1="$(now_ms)"; completed_at="$(now_iso)"
  elapsed=$(( t1 - t0 ))

  identity_login="$(head -n 1 "$ident_raw_out" 2>/dev/null | tr -d '\r\n')"
  [[ "$identity_login" == "$EXPECTED_GITHUB_LOGIN" ]] && identity_match=true

  read -r auth_status auth_reason auth_note < <(classify_process_result "$auth_rc" "$auth_fired")
  read -r ident_status ident_reason ident_note < <(classify_process_result "$ident_rc" "$ident_fired")

  if [[ "$auth_status" == "TIMEOUT" || "$ident_status" == "TIMEOUT" ]]; then
    status="TIMEOUT"; reason="DEADLINE_EXCEEDED"
  elif [[ "$auth_rc" -ne 0 ]]; then
    status="FAIL"; reason="AUTH_CHECK_FAILED"
  elif [[ "$ident_rc" -ne 0 ]]; then
    status="FAIL"; reason="IDENTITY_READ_FAILED"
  elif [[ -z "$identity_login" ]]; then
    status="FAIL"; reason="IDENTITY_EMPTY"
  elif [[ "$identity_match" != true ]]; then
    status="FAIL"; reason="IDENTITY_MISMATCH"
  else
    status="PASS"; reason="OK"
  fi

  redact_to_evidence "$auth_raw_out" "$aout" >/dev/null
  redact_to_evidence "$auth_raw_err" "$aerr" >/dev/null
  redact_to_evidence "$ident_raw_out" "$iout" >/dev/null
  redact_to_evidence "$ident_raw_err" "$ierr" >/dev/null

  emit_check_common "$idx" "$name" true true "$status" "$reason"
  kv_s "checks.${idx}.started_at" "$started_at"
  kv_s "checks.${idx}.completed_at" "$completed_at"
  kv_n "checks.${idx}.duration_ms" "$elapsed"
  kv_n "checks.${idx}.exit_code" "$([[ "$auth_rc" -ne 0 ]] && echo "$auth_rc" || echo "$ident_rc")"
  kv_n "checks.${idx}.timeout_seconds" "$GITHUB_TIMEOUT_SECONDS"
  kv_z "checks.${idx}.required_output"
  kv_z "checks.${idx}.required_output_observed"
  kv_s "checks.${idx}.required_output_match" "not_applicable"
  kv_s "checks.${idx}.stdout_artifact" "github-auth.stdout.txt"
  kv_s "checks.${idx}.stderr_artifact" "github-auth.stderr.txt"
  kv_s "checks.${idx}.metadata.auth_command" "gh auth status $(printf '%s ' "${auth_status_args[@]}")"
  kv_n "checks.${idx}.metadata.auth_exit_code" "$auth_rc"
  kv_s "checks.${idx}.metadata.auth_classification" "$auth_status"
  kv_b "checks.${idx}.metadata.auth_deadline_fired" "$auth_fired"
  kv_s "checks.${idx}.metadata.identity_command" "gh api user --jq .login"
  kv_n "checks.${idx}.metadata.identity_exit_code" "$ident_rc"
  kv_s "checks.${idx}.metadata.identity_classification" "$ident_status"
  kv_b "checks.${idx}.metadata.identity_deadline_fired" "$ident_fired"
  kv_s "checks.${idx}.metadata.identity_expected" "$EXPECTED_GITHUB_LOGIN"
  kv_s "checks.${idx}.metadata.identity_actual" "${identity_login:-empty}"
  kv_b "checks.${idx}.metadata.identity_match" "$identity_match"
  kv_b "checks.${idx}.metadata.hostname_flag_supported" "$hostname_flag_supported"
  kv_b "checks.${idx}.metadata.active_flag_supported" "$active_flag_supported"
  kv_b "checks.${idx}.metadata.read_only" true
  kv_b "checks.${idx}.metadata.token_values_captured" false
  kv_s "checks.${idx}.metadata.timeout_mechanism" "setsid process-group watcher: TERM at deadline, KILL after ${GRACE_SECONDS}s grace"
  kv_n "checks.${idx}.metadata.combined_max_seconds" "$(( GITHUB_TIMEOUT_SECONDS * 2 + GRACE_SECONDS * 2 ))"
  kv_arr "checks.${idx}.metadata.artifacts"
  kv_s "checks.${idx}.metadata.artifacts.0" "github-auth.stdout.txt"
  kv_s "checks.${idx}.metadata.artifacts.1" "github-auth.stderr.txt"
  kv_s "checks.${idx}.metadata.artifacts.2" "github-identity.stdout.txt"
  kv_s "checks.${idx}.metadata.artifacts.3" "github-identity.stderr.txt"
  kv_n "checks.${idx}.metadata.stderr_lines" "$(( $(count_lines "$aerr") + $(count_lines "$ierr") ))"

  record_result "$name" "$status" "$([[ "$auth_rc" -ne 0 ]] && echo "$auth_rc" || echo "$ident_rc")"
}

# ---------- node serialization, validation, atomic rename ----------

# render_evidence <fields_file> <out_file>
# Writes validated JSON to <out_file> (never to the canonical evidence.json
# path itself - callers are responsible for publishing via
# publish_evidence_atomic). Returns non-zero without leaving a usable
# <out_file> on any failure.
render_evidence() {
  if [[ "${LOOP_PACKAGE_A_SELFTEST_FORCE_RENDER_FAIL:-}" == "1" ]]; then
    echo "self-test injected render failure (LOOP_PACKAGE_A_SELFTEST_FORCE_RENDER_FAIL=1)" >&2
    return 1
  fi
  PKGA_FIELDS="$1" PKGA_OUT="$2" node - <<'NODE_EOF'
const fs = require("fs");

const fieldsPath = process.env.PKGA_FIELDS;
const outPath = process.env.PKGA_OUT;
const root = {};
const lossyFields = [];

function setPath(target, path, value) {
  const parts = path.split(".");
  let cursor = target;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    const nextIsIndex = /^\d+$/.test(parts[i + 1]);
    if (cursor[key] === undefined || cursor[key] === null || typeof cursor[key] !== "object") {
      cursor[key] = nextIsIndex ? [] : {};
    }
    cursor = cursor[key];
  }
  const last = parts[parts.length - 1];
  cursor[last] = value;
}

const raw = fs.readFileSync(fieldsPath, "utf8");
const lines = raw.split("\n").filter((line) => line.length > 0);
for (const line of lines) {
  const [type, path, b64 = ""] = line.split("\t");
  const buf = Buffer.from(b64, "base64");
  const text = buf.toString("utf8");
  if (Buffer.compare(Buffer.from(text, "utf8"), buf) !== 0) {
    lossyFields.push(path);
  }
  let value;
  switch (type) {
    case "s":
      value = text;
      break;
    case "n": {
      const num = Number(text);
      value = Number.isFinite(num) ? num : null;
      break;
    }
    case "b":
      value = text === "true";
      break;
    case "z":
      value = null;
      break;
    case "a":
      value = [];
      break;
    default:
      throw new Error(`unknown field type: ${type}`);
  }
  setPath(root, path, value);
}

root.encoding = {
  serializer: "node JSON.stringify",
  fields_encoded: lines.length,
  lossy_fields: lossyFields,
  note: lossyFields.length
    ? "some captured bytes were not valid UTF-8 and were replaced deterministically"
    : "all captured values were valid UTF-8",
};

const json = `${JSON.stringify(root, null, 2)}\n`;
JSON.parse(json);
fs.writeFileSync(outPath, json);
const fd = fs.openSync(outPath, "r+");
fs.fsyncSync(fd);
fs.closeSync(fd);
JSON.parse(fs.readFileSync(outPath, "utf8"));
console.log(`JSON_OK fields=${lines.length} lossy=${lossyFields.length}`);
NODE_EOF
}

# compute_process_exit_code <harness_status> <capability_status>
# Single source of truth for the aggregate process exit contract:
#   0 = harness PASS + capability PASS
#   1 = harness PASS + capability FAIL
#   2 = harness ERROR (regardless of capability_status)
# Both the persisted evidence field and the shell's actual return value are
# always derived by calling this same function, so they can never drift
# apart.
compute_process_exit_code() {
  local hstatus="$1" cstatus="$2"
  if [[ "$hstatus" != "PASS" ]]; then printf '2'; return; fi
  if [[ "$cstatus" != "PASS" ]]; then printf '1'; return; fi
  printf '0'
}

# render_fallback_evidence <out_file> <reason_code> <process_exit_code>
# Minimal evidence payload used when the full evidence could not be
# serialized. Written to <out_file> (never directly to evidence.json) so it
# can be published through the same publish_evidence_atomic path as normal
# evidence.
render_fallback_evidence() {
  local out="$1" reason="$2" exit_code="$3"
  if [[ "${LOOP_PACKAGE_A_SELFTEST_FORCE_FALLBACK_RENDER_FAIL:-}" == "1" ]]; then
    echo "self-test injected fallback render failure (LOOP_PACKAGE_A_SELFTEST_FORCE_FALLBACK_RENDER_FAIL=1)" >&2
    return 1
  fi
  PKGA_RUN_ID="$RUN_ID" PKGA_DIR="$EVIDENCE_DIR" PKGA_REASON="$reason" PKGA_EXIT="$exit_code" PKGA_OUT="$out" node - <<'NODE_EOF'
const fs = require("fs");
const payload = {
  schema_version: "3.0.0",
  package: "A",
  run_id: process.env.PKGA_RUN_ID,
  evidence_dir: process.env.PKGA_DIR,
  harness_status: "ERROR",
  capability_status: "UNKNOWN",
  reason_code: process.env.PKGA_REASON || "EVIDENCE_SERIALIZATION_FAILED",
  process_exit_code: Number(process.env.PKGA_EXIT),
  note: "full evidence could not be serialized; this is a minimal fallback record; check artifacts in evidence_dir",
};
const json = `${JSON.stringify(payload, null, 2)}\n`;
JSON.parse(json);
fs.writeFileSync(process.env.PKGA_OUT, json);
JSON.parse(fs.readFileSync(process.env.PKGA_OUT, "utf8"));
NODE_EOF
}

# publish_evidence_atomic <tmp_json> <final_json> [force_fail_marker]
# The ONLY way canonical evidence.json is ever written: <tmp_json> must
# already exist in the SAME directory as <final_json> and contain validated
# JSON. Publication is a same-directory rename. On any failure this never
# falls back to writing <final_json> directly - it reports the failure and
# leaves a non-canonically-named forensic artifact instead, so stdout can
# never claim a canonical evidence.json that was never actually published.
# [force_fail_marker], when non-empty, is a self-test-only hook that forces
# a deterministic publish failure without touching real filesystem
# semantics; it is passed explicitly by call sites, never read from a
# process-wide flag, so a fault injected for the primary publish call can
# never silently also break the fallback publish call.
publish_evidence_atomic() {
  local tmp="$1" final="$2" force_fail="${3:-}"
  if [[ ! -s "$tmp" ]]; then
    harness_error "evidence publish: source file missing or empty: $tmp"
    return 1
  fi
  if ! node -e "JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))" "$tmp" >/dev/null 2>&1; then
    harness_error "evidence publish: source file is not valid JSON: $tmp"
    mv -f "$tmp" "${tmp}.invalid-json" 2>/dev/null || rm -f "$tmp"
    return 1
  fi
  if [[ -n "$force_fail" ]]; then
    harness_error "evidence publish: self-test injected atomic-rename failure (${force_fail})"
    mv -f "$tmp" "${tmp}.rename-failed" 2>/dev/null || rm -f "$tmp"
    return 1
  fi
  if ! mv -f "$tmp" "$final"; then
    harness_error "evidence publish: atomic rename failed: ${tmp} -> ${final}"
    mv -f "$tmp" "${tmp}.rename-failed" 2>/dev/null || rm -f "$tmp"
    return 1
  fi
  return 0
}

# publish_fallback_evidence <reason_code> <process_exit_code>
# Renders fallback evidence to a same-directory temp file, then publishes it
# through the exact same atomic-rename mechanism as normal evidence. Returns
# non-zero (with EVIDENCE_JSON left unpublished) if either step fails -
# never bypasses the rename to write evidence.json directly.
publish_fallback_evidence() {
  local reason="$1" exit_code="$2" tmp="${EVIDENCE_DIR}/.evidence.json.fallback.tmp"
  rm -f "$tmp"
  if ! render_fallback_evidence "$tmp" "$reason" "$exit_code"; then
    harness_error "fallback evidence rendering failed"
    rm -f "$tmp"
    return 1
  fi
  publish_evidence_atomic "$tmp" "$EVIDENCE_JSON"
}

emit_status_fields() {
  kv_s "harness_status" "$1"
  kv_s "capability_status" "$2"
  kv_n "secret_scan.findings" "$3"
  kv_n "secret_scan.patterns_checked" "${#SECRET_PATTERNS[@]}"
  kv_s "secret_scan.artifact" "secret-scan.txt"
  kv_s "secret_scan.policy" "raw artifacts are redacted before canonical persistence; this scan is defense-in-depth over already-redacted evidence and matched values are never recorded"
  kv_n "harness_internal_errors" "$HARNESS_ERRORS"
  kv_n "process_exit_code" "$4"
}

# ---------- evidence root containment ----------
#
# Permitted override locations: LOOP_PACKAGE_A_EVIDENCE_DIR, if set, MUST
# canonicalize (via realpath -m, so it need not exist yet) to
# <repo>/evidence/package-a or a path underneath it. Nothing else is
# accepted: no root, no HOME, no repo root itself, no parent-traversal
# tricks, no unrelated arbitrary location.

record_containment_rejection() {
  local requested="$1" resolved="$2"
  mkdir -p "$EVIDENCE_ROOT_CANONICAL" 2>/dev/null
  printf '%s rejected requested=%s resolved=%s expected_root=%s\n' \
    "$(now_iso)" "$requested" "$resolved" "$EVIDENCE_ROOT_CANONICAL" \
    >>"${EVIDENCE_ROOT_CANONICAL}/containment-rejections.log" 2>/dev/null
  echo "harness-error: evidence destination outside ${EVIDENCE_ROOT_CANONICAL}: ${resolved}" >&2
}

# Resolves the evidence root and run directory, rejecting anything that
# escapes <repo>/evidence/package-a. Echoes the run directory on success.
resolve_run_dir() {
  local requested="${LOOP_PACKAGE_A_EVIDENCE_DIR:-$EVIDENCE_ROOT_CANONICAL}" resolved run_dir
  resolved="$(realpath -m "$requested")"
  if [[ "$resolved" != "$EVIDENCE_ROOT_CANONICAL" && "$resolved" != "${EVIDENCE_ROOT_CANONICAL}/"* ]]; then
    record_containment_rejection "$requested" "$resolved"
    return 1
  fi
  if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    record_containment_rejection "$requested" "invalid run_id: ${RUN_ID}"
    return 1
  fi
  run_dir="$(realpath -m "${resolved}/${RUN_ID}")"
  if [[ "$run_dir" != "${EVIDENCE_ROOT_CANONICAL}/"* ]]; then
    record_containment_rejection "$requested" "$run_dir"
    return 1
  fi
  printf '%s' "$run_dir"
}

# ensure_evidence_root_safe: the canonical evidence root must exist and must
# not itself be a symlink before anything is created underneath it. This
# closes the case where an attacker with prior filesystem access replaces
# the root itself with a symlink pointing elsewhere.
ensure_evidence_root_safe() {
  mkdir -p "$EVIDENCE_ROOT_CANONICAL" 2>/dev/null
  if [[ -L "$EVIDENCE_ROOT_CANONICAL" ]]; then
    harness_error "canonical evidence root is a symlink, refusing to use it: $EVIDENCE_ROOT_CANONICAL"
    return 1
  fi
  [[ -d "$EVIDENCE_ROOT_CANONICAL" ]] || { harness_error "canonical evidence root is not a directory: $EVIDENCE_ROOT_CANONICAL"; return 1; }
  return 0
}

# verify_run_dir_containment <dir>
# Re-resolves <dir> AFTER it has actually been created (closing the
# resolve-then-create window between resolve_run_dir's realpath -m call,
# which does not require the path to exist, and the mkdir that follows it)
# and confirms it is still strictly inside the canonical evidence root, is a
# real directory, and is not itself a symlink. Echoes the re-resolved path
# on success.
#
# Residual scope: this closes the specific resolve-then-create race for the
# run directory itself, and is re-run immediately before the terminal
# publish step. It cannot give an atomic, kernel-enforced guarantee against
# every concurrent-writer race (e.g. a directory component being replaced by
# a symlink in the instant between this check and the rename syscall a few
# lines later) - Bash has no O_NOFOLLOW|O_EXCL-style directory primitive
# without a compiled helper, and none is introduced here per the "keep it
# dead-simple, no new framework/compiled helper" constraint. No stronger
# guarantee than this is claimed anywhere in evidence or CLI output.
verify_run_dir_containment() {
  local dir="$1" resolved
  if [[ -L "$dir" ]]; then
    harness_error "run directory is a symlink, refusing to use it: $dir"
    return 1
  fi
  resolved="$(realpath -e "$dir" 2>/dev/null)" || { harness_error "run directory does not resolve to a real path: $dir"; return 1; }
  if [[ "$resolved" != "$EVIDENCE_ROOT_CANONICAL" && "$resolved" != "${EVIDENCE_ROOT_CANONICAL}/"* ]]; then
    harness_error "run directory escaped canonical evidence root after creation: $resolved"
    return 1
  fi
  [[ -d "$resolved" ]] || { harness_error "run directory is not a real directory after creation: $resolved"; return 1; }
  printf '%s' "$resolved"
}

# ---------- main ----------

main() {
  RUN_LABEL="${LOOP_PACKAGE_A_RUN_LABEL:-live}"
  # Dependency preflight already ran at bootstrap (top of file, before any
  # external command including realpath was relied on) - main() is only
  # ever reached when it passed, so there is no second, driftable copy of
  # that decision here.
  RUN_ID="pkgA-$(date -u +%Y%m%dT%H%M%SZ)-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"

  PKGA_TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/package-a-run.XXXXXX")"
  mkdir -p "${PKGA_TMP_ROOT}/raw"
  trap 'cleanup_path "$PKGA_TMP_ROOT" >/dev/null 2>&1 || rmdir "$PKGA_TMP_ROOT" 2>/dev/null || true' EXIT

  if ! ensure_evidence_root_safe; then
    echo "RUN_ID=${RUN_ID}"
    echo "HARNESS_STATUS=ERROR"
    echo "CAPABILITY_STATUS=NOT_RUN"
    echo "REASON=EVIDENCE_ROOT_UNSAFE"
    echo "EVIDENCE_JSON=none"
    return 2
  fi

  if ! EVIDENCE_DIR="$(resolve_run_dir)"; then
    echo "RUN_ID=${RUN_ID}"
    echo "HARNESS_STATUS=ERROR"
    echo "CAPABILITY_STATUS=NOT_RUN"
    echo "REASON=EVIDENCE_CONTAINMENT_REJECTED"
    echo "EVIDENCE_JSON=none"
    return 2
  fi

  EVIDENCE_JSON="${EVIDENCE_DIR}/evidence.json"
  FIELDS_FILE="${EVIDENCE_DIR}/.fields.kv"

  if ! mkdir -p "$EVIDENCE_DIR"; then
    echo "RUN_ID=${RUN_ID}"
    echo "HARNESS_STATUS=ERROR"
    echo "CAPABILITY_STATUS=NOT_RUN"
    echo "REASON=EVIDENCE_DIR_CREATE_FAILED"
    echo "EVIDENCE_JSON=none"
    return 2
  fi

  # Re-resolve the directory AFTER creation and re-verify containment,
  # closing the resolve-then-create window between the realpath -m call
  # inside resolve_run_dir (which does not require the path to exist yet)
  # and the mkdir just above.
  if ! EVIDENCE_DIR="$(verify_run_dir_containment "$EVIDENCE_DIR")"; then
    echo "RUN_ID=${RUN_ID}"
    echo "HARNESS_STATUS=ERROR"
    echo "CAPABILITY_STATUS=NOT_RUN"
    echo "REASON=RUN_DIR_CONTAINMENT_REJECTED_POST_CREATE"
    echo "EVIDENCE_JSON=none"
    return 2
  fi
  EVIDENCE_JSON="${EVIDENCE_DIR}/evidence.json"
  FIELDS_FILE="${EVIDENCE_DIR}/.fields.kv"
  : >"$FIELDS_FILE"

  local run_started_at run_t0 run_t1 run_completed_at total_ms
  run_started_at="$(now_iso)"; run_t0="$(now_ms)"

  seed_not_run_fields

  # Each check is independent; a failure here never short-circuits the rest.
  run_claude_check
  run_codex_check
  run_github_check

  run_t1="$(now_ms)"; run_completed_at="$(now_iso)"
  total_ms=$(( run_t1 - run_t0 ))

  kv_s "schema_version" "$SCHEMA_VERSION"
  kv_s "package" "$PACKAGE"
  kv_s "run_id" "$RUN_ID"
  kv_s "run_label" "$RUN_LABEL"
  kv_s "started_at" "$run_started_at"
  kv_s "completed_at" "$run_completed_at"
  kv_n "total_duration_ms" "$total_ms"
  kv_s "host.hostname" "${HOSTNAME:-$(uname -n 2>/dev/null)}"
  kv_s "host.user" "$(id -un 2>/dev/null)"
  kv_s "host.os" "$(uname -s 2>/dev/null)"
  kv_s "host.kernel" "$(uname -r 2>/dev/null)"
  kv_s "host.arch" "$(uname -m 2>/dev/null)"
  kv_s "host.shell" "bash ${BASH_VERSION}"
  kv_s "host.repo_root" "$REPO_ROOT"
  kv_s "executable_versions.claude" "$(tool_version claude)"
  kv_s "executable_versions.codex" "$(tool_version codex)"
  kv_s "executable_versions.gh" "$(tool_version gh)"
  kv_s "executable_versions.node" "$(tool_version node)"
  kv_n "configured_timeouts_seconds.claude_cli" "$CLAUDE_TIMEOUT_SECONDS"
  kv_n "configured_timeouts_seconds.codex_cli" "$CODEX_TIMEOUT_SECONDS"
  kv_n "configured_timeouts_seconds.github_cli" "$GITHUB_TIMEOUT_SECONDS"
  kv_n "configured_timeouts_seconds.grace" "$GRACE_SECONDS"
  kv_s "evidence_root" "$EVIDENCE_ROOT_CANONICAL"
  kv_s "evidence_dir" "$EVIDENCE_DIR"
  kv_s "github.expected_identity" "$EXPECTED_GITHUB_LOGIN"

  # Statuses are finalized BEFORE serialization; nothing may change them after.
  local scan_a scan_b scan_total harness_status capability_status name
  scan_a="$(scan_secrets "$EVIDENCE_DIR")"
  [[ "$scan_a" =~ ^[0-9]+$ ]] || scan_a=0

  capability_status="PASS"
  harness_status="PASS"
  for name in "${CHECK_ORDER[@]}"; do
    [[ "${STATUSES[$name]}" == "PASS" ]] || capability_status="FAIL"
    case "${STATUSES[$name]}" in
      ERROR|NOT_RUN) harness_status="ERROR" ;;
    esac
  done
  [[ "$HARNESS_ERRORS" -eq 0 ]] || harness_status="ERROR"
  [[ "$scan_a" -eq 0 ]] || harness_status="ERROR"

  scan_total="$scan_a"
  local process_exit_code
  process_exit_code="$(compute_process_exit_code "$harness_status" "$capability_status")"
  emit_status_fields "$harness_status" "$capability_status" "$scan_total" "$process_exit_code"

  local tmp_json="${EVIDENCE_DIR}/.evidence.json.tmp" render_log
  render_log="$(render_evidence "$FIELDS_FILE" "$tmp_json" 2>&1)"
  if [[ $? -ne 0 || ! -s "$tmp_json" ]]; then
    harness_error "evidence serialization failed: ${render_log}"
    harness_status="ERROR"
    rm -f "$tmp_json" "$FIELDS_FILE"
    process_exit_code="$(compute_process_exit_code "$harness_status" "$capability_status")"
    echo "RUN_ID=${RUN_ID}"
    echo "HARNESS_STATUS=ERROR"
    echo "CAPABILITY_STATUS=${capability_status}"
    if publish_fallback_evidence "EVIDENCE_SERIALIZATION_FAILED" "$process_exit_code"; then
      echo "EVIDENCE_JSON=${EVIDENCE_JSON}"
    else
      echo "EVIDENCE_JSON=none"
    fi
    return "$process_exit_code"
  fi

  # Second scan pass covers the serialized evidence itself (defense in depth;
  # raw artifacts were already redacted before this file was ever built).
  scan_b="$(scan_secrets "$tmp_json")"
  [[ "$scan_b" =~ ^[0-9]+$ ]] || scan_b=0
  if [[ "$scan_b" -gt 0 ]]; then
    harness_error "secret pattern found in serialized evidence"
    harness_status="ERROR"
    scan_total=$(( scan_a + scan_b ))
    process_exit_code="$(compute_process_exit_code "$harness_status" "$capability_status")"
    emit_status_fields "$harness_status" "$capability_status" "$scan_total" "$process_exit_code"
    rm -f "$tmp_json"
    render_log="$(render_evidence "$FIELDS_FILE" "$tmp_json" 2>&1)"
    if [[ $? -ne 0 || ! -s "$tmp_json" ]]; then
      harness_error "evidence re-serialization failed: ${render_log}"
      rm -f "$tmp_json" "$FIELDS_FILE"
      echo "RUN_ID=${RUN_ID}"
      echo "HARNESS_STATUS=ERROR"
      echo "CAPABILITY_STATUS=${capability_status}"
      if publish_fallback_evidence "SECRET_SCAN_RESERIALIZATION_FAILED" "$process_exit_code"; then
        echo "EVIDENCE_JSON=${EVIDENCE_JSON}"
      else
        echo "EVIDENCE_JSON=none"
      fi
      return "$process_exit_code"
    fi
  fi

  rm -f "$FIELDS_FILE"

  # Re-check containment one last time immediately before the terminal
  # publish step (see verify_run_dir_containment's residual-scope note).
  if ! verify_run_dir_containment "$EVIDENCE_DIR" >/dev/null; then
    harness_error "run directory containment re-check failed immediately before publish"
    harness_status="ERROR"
    process_exit_code="$(compute_process_exit_code "$harness_status" "$capability_status")"
    rm -f "$tmp_json"
    echo "RUN_ID=${RUN_ID}"
    echo "HARNESS_STATUS=ERROR"
    echo "CAPABILITY_STATUS=${capability_status}"
    echo "REASON=RUN_DIR_CONTAINMENT_REJECTED_PRE_PUBLISH"
    echo "EVIDENCE_JSON=none"
    return "$process_exit_code"
  fi

  local publish_force_fail=""
  [[ "${LOOP_PACKAGE_A_SELFTEST_FORCE_RENAME_FAIL:-}" == "1" ]] && publish_force_fail="LOOP_PACKAGE_A_SELFTEST_FORCE_RENAME_FAIL"
  local published=true
  if ! publish_evidence_atomic "$tmp_json" "$EVIDENCE_JSON" "$publish_force_fail"; then
    harness_status="ERROR"
    process_exit_code="$(compute_process_exit_code "$harness_status" "$capability_status")"
    published=false
    if publish_fallback_evidence "EVIDENCE_PUBLISH_RENAME_FAILED" "$process_exit_code"; then
      published=true
    fi
  fi

  process_exit_code="$(compute_process_exit_code "$harness_status" "$capability_status")"

  echo "RUN_ID=${RUN_ID}"
  echo "RUN_LABEL=${RUN_LABEL}"
  for name in "${CHECK_ORDER[@]}"; do
    echo "$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')_STATUS=${STATUSES[$name]} EXIT=${EXIT_CODES[$name]:-none}"
  done
  echo "SECRET_SCAN_FINDINGS=${scan_total}"
  echo "HARNESS_STATUS=${harness_status}"
  echo "CAPABILITY_STATUS=${capability_status}"
  if [[ "$published" == true ]]; then
    echo "EVIDENCE_JSON=${EVIDENCE_JSON}"
  else
    echo "EVIDENCE_JSON=none"
  fi

  return "$process_exit_code"
}

# ---------- fault-injection self-test ----------
# `scripts/package-a.sh --self-test` proves the acceptance contract
# deterministically using fake claude/codex/gh executables, with no real
# credentials or network calls. Each scenario re-invokes this same script as
# a full subprocess (LOOP_PACKAGE_A_RUN_LABEL=fault_injection), so every
# scenario's own evidence.json is persisted under evidence/package-a/ too.

self_test_write_fakes() {
  local bindir="$1"
  cat >"${bindir}/claude" <<'EOF'
#!/bin/bash
if [[ "${1:-}" == "--version" ]]; then printf 'claude 0.0.0 (fake)\n'; exit 0; fi
mode="${FAKE_CLAUDE_MODE:-pass}"
# Mirrors `claude --output-format json`: a single result envelope on stdout.
emit_envelope() {
  printf '{"type":"result","subtype":"success","is_error":false,"result":%s}\n' "$1"
}
case "$mode" in
  pass)
    echo '[mcp] connected 3 servers' >&2
    printf 'diagnostic chatter that is not the completion\n' >&2
    emit_envelope '"CLAUDE_OK"'; exit 0 ;;
  prefix) emit_envelope '"Sure thing! CLAUDE_OK"'; exit 0 ;;
  suffix) emit_envelope '"CLAUDE_OK\nAnything else?"'; exit 0 ;;
  malformed_json) printf 'CLAUDE_OK\nthis is not a json envelope\n'; exit 0 ;;
  nonzero) emit_envelope '"CLAUDE_OK"'; exit 1 ;;
  # Envelope-hardening negative fixtures: none of these are the genuine
  # structural envelope (object + type=result + subtype=success +
  # is_error=false + string result), so none may be accepted as completion.
  raw_result_only) printf '{"result":"CLAUDE_OK"}\n'; exit 0 ;;
  wrong_type) printf '{"type":"diagnostic","subtype":"success","is_error":false,"result":"CLAUDE_OK"}\n'; exit 0 ;;
  is_error_true) printf '{"type":"result","subtype":"success","is_error":true,"result":"CLAUDE_OK"}\n'; exit 0 ;;
  wrong_subtype) printf '{"type":"result","subtype":"error","is_error":false,"result":"CLAUDE_OK"}\n'; exit 0 ;;
  diagnostic_plus_genuine)
    printf '{"result":"CLAUDE_OK"}\n'
    emit_envelope '"CLAUDE_OK"'
    exit 0 ;;
  multiple_envelopes)
    emit_envelope '"CLAUDE_OK"'
    emit_envelope '"CLAUDE_OK"'
    exit 0 ;;
  invalid_utf8_stderr)
    printf 'ERROR: invalid utf8 byte follows -> \x80\xfe end\n' >&2
    emit_envelope '"CLAUDE_OK"'; exit 0 ;;
  invalid_utf8_completion)
    printf '{"type":"result","subtype":"success","is_error":false,"result":"CLAUDE_OK\x80\xfe"}\n'
    exit 0 ;;
  selfkill) kill -9 $$ ;;
  hang_ignore_term)
    trap '' TERM
    sleep 300 &
    echo $! > "${FAKE_STATE_DIR}/claude_grandchild.pid"
    wait
    ;;
  *) printf 'unknown-mode\n'; exit 9 ;;
esac
EOF
  cat >"${bindir}/codex" <<'EOF'
#!/bin/bash
if [[ "${1:-}" == "--version" ]]; then printf 'codex-cli 0.0.0 (fake)\n'; exit 0; fi
mode="${FAKE_CODEX_MODE:-pass}"
# Mirrors `codex exec -o/--output-last-message <FILE>`: the final agent
# message goes to the dedicated file, not to stdout.
final_file=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    -o|--output-last-message) final_file="${args[$((i + 1))]}" ;;
  esac
done
emit_final() { [[ -n "$final_file" ]] && printf '%s\n' "$1" > "$final_file"; }
case "$mode" in
  pass) printf 'codex diagnostic chatter, not the completion\n'; emit_final 'CODEX_OK'; exit 0 ;;
  extra_text) emit_final 'CODEX_OK and one more thing'; exit 0 ;;
  no_final_output) printf 'CODEX_OK\n'; exit 0 ;;
  nonzero) emit_final 'CODEX_OK'; exit 1 ;;
  mutate_sentinel)
    if [[ -f ./package-a-sentinel.txt ]]; then
      sz=$(wc -c < ./package-a-sentinel.txt)
      head -c "$sz" /dev/zero | tr '\0' 'x' > ./package-a-sentinel.txt
    fi
    emit_final 'CODEX_OK'; exit 0 ;;
  add_file)
    printf 'unexpected extra file\n' > ./package-a-unexpected-extra-file.txt
    emit_final 'CODEX_OK'; exit 0 ;;
  delete_sentinel)
    rm -f ./package-a-sentinel.txt
    emit_final 'CODEX_OK'; exit 0 ;;
  retarget_symlink)
    if [[ -L ./package-a-sentinel.txt.link ]]; then
      rm -f ./package-a-sentinel.txt.link
      ln -s /etc/hostname ./package-a-sentinel.txt.link
    fi
    emit_final 'CODEX_OK'; exit 0 ;;
  secret_fixture)
    printf 'debug token=ghp_FAKEFIXTURE1234567890ABCDEF not the real output\n'
    emit_final 'CODEX_OK'
    exit 0 ;;
  *) emit_final 'CODEX_OK'; exit 0 ;;
esac
EOF
  cat >"${bindir}/gh" <<'EOF'
#!/bin/bash
mode="${FAKE_GH_MODE:-pass}"
login="${FAKE_GH_LOGIN:-Ciupanezulflipper}"
if [[ "${1:-}" == "--version" ]]; then
  printf 'gh version 2.46.0 (fake)\n'
  exit 0
fi
if [[ "${1:-}" == "auth" && "${2:-}" == "status" ]]; then
  if [[ "$*" == *--help* ]]; then
    printf -- '--hostname string   The hostname of the GitHub instance\n'
    exit 0
  fi
  if [[ "$mode" == "authfail" ]]; then
    echo "You are not logged into any GitHub hosts." >&2
    exit 1
  fi
  printf 'github.com\n  Logged in to github.com account %s (fake)\n' "$login"
  exit 0
fi
if [[ "${1:-}" == "api" && "${2:-}" == "user" ]]; then
  if [[ "$mode" == "identityfail" ]]; then
    exit 1
  fi
  printf '%s\n' "$login"
  exit 0
fi
printf '{}\n'
exit 0
EOF
  chmod +x "${bindir}/claude" "${bindir}/codex" "${bindir}/gh"
}

ST_PASS=0
ST_FAIL=0

st_assert() {
  local desc="$1" ok="$2"
  if [[ "$ok" == true ]]; then
    ST_PASS=$(( ST_PASS + 1 ))
    printf '  PASS  %s\n' "$desc"
  else
    ST_FAIL=$(( ST_FAIL + 1 ))
    printf '  FAIL  %s\n' "$desc"
  fi
}

st_assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    st_assert "$desc" true
  else
    st_assert "${desc} (expected='${expected}' actual='${actual}')" false
  fi
}

HS_STDOUT=""
HS_RC=0

run_fake_harness() {
  local -a envs=("$@")
  HS_STDOUT="$(env "${envs[@]}" bash "$SELF_PATH" 2>"${SELFTEST_TMP}/last.stderr.txt")"
  HS_RC=$?
}

# run_fake_harness_at <script_path> [env=val ...]
# Same as run_fake_harness but against an arbitrary copy of the script, so
# lexical-path scenarios (e.g. evidence-root symlink safety) can exercise an
# isolated temporary repo layout instead of this real repository's own
# evidence root.
run_fake_harness_at() {
  local script_path="$1"; shift
  local -a envs=("$@")
  HS_STDOUT="$(env "${envs[@]}" bash "$script_path" 2>"${SELFTEST_TMP}/last.stderr.txt")"
  HS_RC=$?
}

hs_field() {
  printf '%s\n' "$HS_STDOUT" | grep -m1 -oE "^${1}=[^ ]*" | cut -d= -f2-
}

node_json_valid() {
  node -e "JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))" "$1" >/dev/null 2>&1
}

node_json_field() {
  node -e "
const d = JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));
const v = process.argv[2].split('.').reduce((o,k)=> (o==null?undefined:o[k]), d);
process.stdout.write(String(v));
" "$1" "$2" 2>/dev/null
}

self_test_base_env() {
  printf '%s\n' \
    "PATH=${FAKE_BIN}:${PATH}" \
    "LOOP_PACKAGE_A_RUN_LABEL=fault_injection" \
    "LOOP_PACKAGE_A_CLAUDE_TIMEOUT_SECONDS=3" \
    "LOOP_PACKAGE_A_CODEX_TIMEOUT_SECONDS=3" \
    "LOOP_PACKAGE_A_GITHUB_TIMEOUT_SECONDS=3" \
    "LOOP_PACKAGE_A_GRACE_SECONDS=2" \
    "FAKE_STATE_DIR=${SELFTEST_TMP}" \
    "FAKE_CLAUDE_MODE=pass" \
    "FAKE_CODEX_MODE=pass" \
    "FAKE_GH_MODE=pass" \
    "FAKE_GH_LOGIN=Ciupanezulflipper"
}

run_self_test() {
  echo "=== Package A self-test / fault-injection suite ==="

  echo "--- bash syntax ---"
  if bash -n "$SELF_PATH" 2>"${SELFTEST_TMP:-/tmp}/syntax.err"; then
    st_assert "bash syntax valid" true
  else
    st_assert "bash syntax valid" false
  fi

  SELFTEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/package-a-selftest.XXXXXX")"
  FAKE_BIN="${SELFTEST_TMP}/bin"
  mkdir -p "$FAKE_BIN"
  self_test_write_fakes "$FAKE_BIN"

  local -a base_env
  mapfile -t base_env < <(self_test_base_env)

  # Scenario: baseline PASS path (also covers exact-token-accepted).
  echo "--- baseline PASS path ---"
  run_fake_harness "${base_env[@]}"
  local baseline_stdout="$HS_STDOUT"
  st_assert_eq "claude PASS path" "PASS" "$(hs_field CLAUDE_CLI_STATUS)"
  st_assert_eq "codex PASS path" "PASS" "$(hs_field CODEX_CLI_STATUS)"
  st_assert_eq "github PASS path with expected identity" "PASS" "$(hs_field GITHUB_CLI_STATUS)"
  st_assert_eq "harness status PASS" "PASS" "$(hs_field HARNESS_STATUS)"
  st_assert_eq "capability status PASS" "PASS" "$(hs_field CAPABILITY_STATUS)"

  local baseline_evidence baseline_persisted_harness baseline_persisted_cap
  baseline_evidence="$(printf '%s\n' "$baseline_stdout" | grep -m1 -oE '^EVIDENCE_JSON=.*' | cut -d= -f2-)"
  if node_json_valid "$baseline_evidence"; then
    st_assert "evidence json parses (baseline)" true
  else
    st_assert "evidence json parses (baseline)" false
  fi
  baseline_persisted_harness="$(node_json_field "$baseline_evidence" harness_status)"
  baseline_persisted_cap="$(node_json_field "$baseline_evidence" capability_status)"
  st_assert_eq "stdout status matches persisted harness_status" "$(hs_field HARNESS_STATUS)" "$baseline_persisted_harness"
  st_assert_eq "stdout status matches persisted capability_status" "$(hs_field CAPABILITY_STATUS)" "$baseline_persisted_cap"
  st_assert_eq "baseline PASS+PASS persists process_exit_code 0" "0" "$(node_json_field "$baseline_evidence" process_exit_code)"
  st_assert_eq "baseline PASS+PASS actual shell exit is 0" "0" "$HS_RC"

  # Scenario: envelope hardening - a generic object that merely contains a
  # `result` key is not a genuine Claude result envelope.
  echo "--- envelope hardening: unrelated JSON with a bare result field ---"
  run_fake_harness "${base_env[@]}" "FAKE_CLAUDE_MODE=raw_result_only"
  st_assert_eq "bare {result:...} object is not accepted as completion" "FAIL" "$(hs_field CLAUDE_CLI_STATUS)"

  echo "--- envelope hardening: wrong type field ---"
  run_fake_harness "${base_env[@]}" "FAKE_CLAUDE_MODE=wrong_type"
  st_assert_eq "envelope with type!=result rejected" "FAIL" "$(hs_field CLAUDE_CLI_STATUS)"

  echo "--- envelope hardening: is_error=true ---"
  run_fake_harness "${base_env[@]}" "FAKE_CLAUDE_MODE=is_error_true"
  st_assert_eq "envelope with is_error=true rejected" "FAIL" "$(hs_field CLAUDE_CLI_STATUS)"

  echo "--- envelope hardening: subtype!=success ---"
  run_fake_harness "${base_env[@]}" "FAKE_CLAUDE_MODE=wrong_subtype"
  st_assert_eq "envelope with subtype!=success rejected" "FAIL" "$(hs_field CLAUDE_CLI_STATUS)"

  echo "--- envelope hardening: diagnostic noise plus one genuine envelope still PASSes ---"
  run_fake_harness "${base_env[@]}" "FAKE_CLAUDE_MODE=diagnostic_plus_genuine"
  st_assert_eq "genuine envelope accepted despite preceding diagnostic JSON" "PASS" "$(hs_field CLAUDE_CLI_STATUS)"

  echo "--- envelope hardening: multiple genuine envelopes is ambiguous, never an arbitrary PASS ---"
  run_fake_harness "${base_env[@]}" "FAKE_CLAUDE_MODE=multiple_envelopes"
  st_assert_eq "multiple valid envelopes does not silently pass" "FAIL" "$(hs_field CLAUDE_CLI_STATUS)"
  local multi_envelope_evidence
  multi_envelope_evidence="$(hs_field EVIDENCE_JSON)"
  st_assert_eq "multiple valid envelopes reason code recorded" "AMBIGUOUS_MULTIPLE_RESULT_ENVELOPES" "$(node_json_field "$multi_envelope_evidence" checks.0.reason_code)"

  # Scenario: invalid UTF-8 bytes must never corrupt evidence JSON or
  # silently satisfy an exact-match requirement.
  echo "--- invalid UTF-8: stderr bytes are isolated, not corrupting, and flagged ---"
  run_fake_harness "${base_env[@]}" "FAKE_CLAUDE_MODE=invalid_utf8_stderr"
  local badutf8_evidence
  badutf8_evidence="$(hs_field EVIDENCE_JSON)"
  st_assert "evidence json remains parseable with invalid utf8 stderr bytes" "$(node_json_valid "$badutf8_evidence" && echo true || echo false)"
  st_assert_eq "claude still PASSes on a clean completion despite invalid utf8 elsewhere" "PASS" "$(hs_field CLAUDE_CLI_STATUS)"
  local badutf8_lossy_len
  badutf8_lossy_len="$(node_json_field "$badutf8_evidence" encoding.lossy_fields.length)"
  st_assert "encoding.lossy_fields records the affected field" "$([[ "$badutf8_lossy_len" =~ ^[1-9] ]] && echo true || echo false)"

  echo "--- invalid UTF-8: corrupted required-output field cannot false-PASS ---"
  run_fake_harness "${base_env[@]}" "FAKE_CLAUDE_MODE=invalid_utf8_completion"
  st_assert_eq "invalid utf8 inside the required completion field is rejected, not falsely passed" "FAIL" "$(hs_field CLAUDE_CLI_STATUS)"
  local badcompletion_evidence
  badcompletion_evidence="$(hs_field EVIDENCE_JSON)"
  st_assert "evidence json still parses despite invalid utf8 in the completion" "$(node_json_valid "$badcompletion_evidence" && echo true || echo false)"

  # Scenario: token with preceding prose.
  echo "--- token with preceding output ---"
  run_fake_harness "${base_env[@]}" "FAKE_CLAUDE_MODE=prefix"
  st_assert_eq "token with preceding output rejected" "FAIL" "$(hs_field CLAUDE_CLI_STATUS)"
  st_assert_eq "codex still runs when claude output malformed" "PASS" "$(hs_field CODEX_CLI_STATUS)"
  st_assert_eq "github still runs when claude output malformed" "PASS" "$(hs_field GITHUB_CLI_STATUS)"

  # Scenario: token with following prose.
  echo "--- token with following output ---"
  run_fake_harness "${base_env[@]}" "FAKE_CLAUDE_MODE=suffix"
  st_assert_eq "token with following output rejected" "FAIL" "$(hs_field CLAUDE_CLI_STATUS)"

  # Scenario: unparseable structured output cannot pass; there is no
  # last-line fallback, so a bare CLAUDE_OK line outside an envelope fails.
  echo "--- malformed claude structured output ---"
  run_fake_harness "${base_env[@]}" "FAKE_CLAUDE_MODE=malformed_json"
  st_assert_eq "unparseable structured output rejected" "FAIL" "$(hs_field CLAUDE_CLI_STATUS)"

  # Scenario: missing codex final-output file cannot pass, even when the
  # token appears on stdout.
  echo "--- missing codex final-output file ---"
  run_fake_harness "${base_env[@]}" "FAKE_CODEX_MODE=no_final_output"
  st_assert_eq "missing dedicated final output rejected" "FAIL" "$(hs_field CODEX_CLI_STATUS)"

  # Scenario: extra text in the codex final output cannot pass.
  echo "--- codex final output with extra text ---"
  run_fake_harness "${base_env[@]}" "FAKE_CODEX_MODE=extra_text"
  st_assert_eq "codex final output with extra text rejected" "FAIL" "$(hs_field CODEX_CLI_STATUS)"

  # Scenario: nonzero model exit despite correct text.
  echo "--- nonzero model exit ---"
  run_fake_harness "${base_env[@]}" "FAKE_CLAUDE_MODE=nonzero"
  st_assert_eq "nonzero model exit rejected" "FAIL" "$(hs_field CLAUDE_CLI_STATUS)"

  # Scenario: controlled timeout with a hung process tree (grandchild).
  echo "--- controlled timeout / hung process tree ---"
  run_fake_harness "${base_env[@]}" "FAKE_CLAUDE_MODE=hang_ignore_term"
  st_assert_eq "controlled timeout recognized as TIMEOUT" "TIMEOUT" "$(hs_field CLAUDE_CLI_STATUS)"
  st_assert_eq "provider independence: codex runs after claude timeout" "PASS" "$(hs_field CODEX_CLI_STATUS)"
  st_assert_eq "provider independence: github runs after claude timeout" "PASS" "$(hs_field GITHUB_CLI_STATUS)"
  if [[ -f "${SELFTEST_TMP}/claude_grandchild.pid" ]]; then
    local gpid
    gpid="$(cat "${SELFTEST_TMP}/claude_grandchild.pid" 2>/dev/null)"
    sleep 0.3
    if [[ -n "$gpid" ]] && kill -0 "$gpid" 2>/dev/null; then
      st_assert "hung grandchild process terminated" false
    else
      st_assert "hung grandchild process terminated" true
    fi
    rm -f "${SELFTEST_TMP}/claude_grandchild.pid"
  else
    st_assert "hung grandchild process terminated" false
  fi

  # Scenario: arbitrary SIGKILL is NOT auto-classified as timeout.
  echo "--- arbitrary 137 is not timeout ---"
  run_fake_harness "${base_env[@]}" "FAKE_CLAUDE_MODE=selfkill"
  st_assert_eq "arbitrary 137 classified as FAIL, not TIMEOUT" "FAIL" "$(hs_field CLAUDE_CLI_STATUS)"

  # Scenario: codex failure does not suppress github.
  echo "--- codex failure does not suppress github ---"
  run_fake_harness "${base_env[@]}" "FAKE_CODEX_MODE=nonzero"
  st_assert_eq "codex failure recorded" "FAIL" "$(hs_field CODEX_CLI_STATUS)"
  st_assert_eq "github still runs after codex failure" "PASS" "$(hs_field GITHUB_CLI_STATUS)"

  # Scenario: wrong GitHub identity cannot pass.
  echo "--- wrong github identity rejected ---"
  run_fake_harness "${base_env[@]}" "FAKE_GH_LOGIN=someone-else"
  st_assert_eq "wrong identity rejected" "FAIL" "$(hs_field GITHUB_CLI_STATUS)"
  st_assert_eq "capability status reflects identity mismatch" "FAIL" "$(hs_field CAPABILITY_STATUS)"
  st_assert_eq "harness PASS + capability FAIL -> shell exit 1" "1" "$HS_RC"
  local wrongid_evidence
  wrongid_evidence="$(hs_field EVIDENCE_JSON)"
  st_assert_eq "harness PASS + capability FAIL persists process_exit_code 1" "1" "$(node_json_field "$wrongid_evidence" process_exit_code)"

  # Scenario: snapshot failure cannot produce a false PASS.
  echo "--- snapshot failure cannot false-pass ---"
  run_fake_harness "${base_env[@]}" "LOOP_PACKAGE_A_SELFTEST_FORCE_SNAPSHOT_FAIL=1"
  st_assert_eq "snapshot failure yields ERROR, not PASS" "ERROR" "$(hs_field CODEX_CLI_STATUS)"
  st_assert_eq "harness status reflects snapshot failure" "ERROR" "$(hs_field HARNESS_STATUS)"
  st_assert_eq "harness ERROR -> shell exit 2" "2" "$HS_RC"
  local snapfail_evidence
  snapfail_evidence="$(hs_field EVIDENCE_JSON)"
  st_assert_eq "harness ERROR persists process_exit_code 2" "2" "$(node_json_field "$snapfail_evidence" process_exit_code)"

  # Scenario: same-size content mutation is detectable via content hash.
  echo "--- same-size content mutation detectable ---"
  run_fake_harness "${base_env[@]}" "FAKE_CODEX_MODE=mutate_sentinel"
  st_assert_eq "same-size sentinel mutation detected" "FAIL" "$(hs_field CODEX_CLI_STATUS)"

  # Scenario: added regular file is detected.
  echo "--- filesystem integrity: added regular file detected ---"
  run_fake_harness "${base_env[@]}" "FAKE_CODEX_MODE=add_file"
  st_assert_eq "added file causes NOT PASS" "FAIL" "$(hs_field CODEX_CLI_STATUS)"

  # Scenario: deleted sentinel file is detected.
  echo "--- filesystem integrity: deleted sentinel file detected ---"
  run_fake_harness "${base_env[@]}" "FAKE_CODEX_MODE=delete_sentinel"
  st_assert_eq "deleted file causes NOT PASS" "FAIL" "$(hs_field CODEX_CLI_STATUS)"

  # Scenario: changed symlink target is detected, when this environment
  # actually supports symlinks. Documented residual scope, not assumed.
  local symlinks_supported=false
  if ln -s "x" "${SELFTEST_TMP}/symlink-probe" 2>/dev/null; then
    symlinks_supported=true
    rm -f "${SELFTEST_TMP}/symlink-probe"
  fi
  if [[ "$symlinks_supported" == true ]]; then
    echo "--- filesystem integrity: changed symlink target detected ---"
    run_fake_harness "${base_env[@]}" "FAKE_CODEX_MODE=retarget_symlink"
    st_assert_eq "symlink target mutation causes NOT PASS" "FAIL" "$(hs_field CODEX_CLI_STATUS)"
  else
    echo "--- filesystem integrity: symlink target test SKIPPED (symlinks unsupported here) ---"
  fi

  # Scenario: secret-like fixture is redacted before canonical persistence.
  echo "--- secret fixture redacted before persistence ---"
  run_fake_harness "${base_env[@]}" "FAKE_CODEX_MODE=secret_fixture"
  local fixture_evidence_json fixture_evidence_dir
  fixture_evidence_json="$(printf '%s\n' "$HS_STDOUT" | grep -m1 -oE '^EVIDENCE_JSON=.*' | cut -d= -f2-)"
  case "$fixture_evidence_json" in
    */*) fixture_evidence_dir="${fixture_evidence_json%/*}" ;;
    *) fixture_evidence_dir="." ;;
  esac
  if [[ -n "$fixture_evidence_dir" && -d "$fixture_evidence_dir" ]] && ! grep -rq 'FAKEFIXTURE1234567890ABCDEF' "$fixture_evidence_dir" 2>/dev/null; then
    st_assert "secret-like fixture not retained in canonical evidence" true
  else
    st_assert "secret-like fixture not retained in canonical evidence" false
  fi

  # Scenario: evidence containment rejects paths outside the evidence root.
  echo "--- evidence containment ---"
  run_fake_harness "${base_env[@]}" "LOOP_PACKAGE_A_EVIDENCE_DIR=/etc/pkgA-selftest-evil"
  st_assert_eq "containment rejects outside path" "ERROR" "$(hs_field HARNESS_STATUS)"
  st_assert_eq "containment rejection reason recorded" "EVIDENCE_CONTAINMENT_REJECTED" "$(hs_field REASON)"

  run_fake_harness "${base_env[@]}" "LOOP_PACKAGE_A_EVIDENCE_DIR=${EVIDENCE_ROOT_CANONICAL}/selftest-subdir"
  st_assert_eq "containment accepts valid subdir" "PASS" "$(hs_field HARNESS_STATUS)"

  # Scenario: lexical evidence-root symlink safety. Uses an isolated
  # temporary repo copy (never this real repository's own evidence root) so
  # a symlink at <repo>/evidence or <repo>/evidence/package-a can be planted
  # and proven rejected BEFORE canonicalization ever follows it.
  echo "--- lexical evidence root symlink safety ---"
  local lex_repo="${SELFTEST_TMP}/lexrepo" lex_outside="${SELFTEST_TMP}/lexoutside" lex_script
  mkdir -p "${lex_repo}/scripts" "$lex_outside"
  lex_script="${lex_repo}/scripts/package-a.sh"
  cp "$SELF_PATH" "$lex_script"
  chmod +x "$lex_script"

  # Case: <repo>/evidence itself is a symlink.
  ln -s "$lex_outside" "${lex_repo}/evidence"
  run_fake_harness_at "$lex_script" "${base_env[@]}"
  st_assert_eq "evidence parent symlink -> harness ERROR" "ERROR" "$(hs_field HARNESS_STATUS)"
  st_assert_eq "evidence parent symlink -> shell exit 2" "2" "$HS_RC"
  case "$(hs_field REASON)" in
    EVIDENCE_ROOT_UNSAFE:EVIDENCE_PARENT_IS_SYMLINK:*) st_assert "evidence parent symlink reason names the parent symlink" true ;;
    *) st_assert "evidence parent symlink reason names the parent symlink" false ;;
  esac
  st_assert "evidence parent symlink target was never traversed into" "$([[ ! -e "${lex_outside}/package-a" ]] && echo true || echo false)"
  rm -f "${lex_repo}/evidence"

  # Case: <repo>/evidence is an ordinary directory, but
  # <repo>/evidence/package-a is a symlink.
  mkdir -p "${lex_repo}/evidence"
  ln -s "$lex_outside" "${lex_repo}/evidence/package-a"
  run_fake_harness_at "$lex_script" "${base_env[@]}"
  st_assert_eq "evidence root symlink -> harness ERROR" "ERROR" "$(hs_field HARNESS_STATUS)"
  st_assert_eq "evidence root symlink -> shell exit 2" "2" "$HS_RC"
  case "$(hs_field REASON)" in
    EVIDENCE_ROOT_UNSAFE:EVIDENCE_ROOT_IS_SYMLINK:*) st_assert "evidence root symlink reason names the root symlink" true ;;
    *) st_assert "evidence root symlink reason names the root symlink" false ;;
  esac
  rm -f "${lex_repo}/evidence/package-a"

  # Case: ordinary real directories are accepted and the run proceeds
  # normally end-to-end (using the same fakes as every other scenario).
  run_fake_harness_at "$lex_script" "${base_env[@]}"
  st_assert_eq "ordinary evidence dir accepted -> harness PASS" "PASS" "$(hs_field HARNESS_STATUS)"
  st_assert "ordinary evidence dir: a real directory was created, not a symlink" "$([[ -d "${lex_repo}/evidence/package-a" && ! -L "${lex_repo}/evidence/package-a" ]] && echo true || echo false)"

  # Regression: traversal rejection (LOOP_PACKAGE_A_EVIDENCE_DIR escaping the
  # evidence root) still works against this same isolated repo layout, so
  # the new lexical pre-check has not weakened it.
  run_fake_harness_at "$lex_script" "${base_env[@]}" "LOOP_PACKAGE_A_EVIDENCE_DIR=${lex_outside}"
  st_assert_eq "traversal outside evidence root still rejected" "ERROR" "$(hs_field HARNESS_STATUS)"
  st_assert_eq "traversal rejection reason still recorded" "EVIDENCE_CONTAINMENT_REJECTED" "$(hs_field REASON)"

  rm -rf "$lex_repo" 2>/dev/null || true

  # Scenario: a missing harness dependency is a deterministic structured
  # error, never raw "command not found" noise or a false capability result.
  echo "--- missing dependency detected before any use ---"
  local mdep_bin="${SELFTEST_TMP}/mdep-bin" dep mdep_src mdep_out mdep_rc
  mkdir -p "$mdep_bin"
  for dep in "${REQUIRED_DEPS[@]}"; do
    [[ "$dep" == "sha256sum" ]] && continue
    mdep_src="$(command -v "$dep" 2>/dev/null)" && ln -sf "$mdep_src" "${mdep_bin}/${dep}"
  done
  # $BASH (the absolute path of the currently-running interpreter) is used
  # here instead of the bare `bash` command word: PATH is being replaced
  # for this exact invocation, and bash resolves a command word against the
  # NEW value being assigned, so a bare `bash` would itself go missing.
  mdep_out="$(PATH="$mdep_bin" "$BASH" "$SELF_PATH" 2>&1)"
  mdep_rc=$?
  st_assert_eq "missing dependency exit code is 2" "2" "$mdep_rc"
  st_assert "missing dependency reports HARNESS_STATUS=ERROR" "$([[ "$mdep_out" == *"HARNESS_STATUS=ERROR"* ]] && echo true || echo false)"
  st_assert "missing dependency reports CAPABILITY_STATUS=NOT_RUN" "$([[ "$mdep_out" == *"CAPABILITY_STATUS=NOT_RUN"* ]] && echo true || echo false)"
  st_assert "missing dependency reason names the missing tool" "$([[ "$mdep_out" == *"MISSING_DEPENDENCIES"*"sha256sum"* ]] && echo true || echo false)"
  st_assert "missing dependency never surfaces raw command-not-found noise" "$([[ "$mdep_out" != *"command not found"* ]] && echo true || echo false)"

  # Scenario: one of the newly-covered REQUIRED_DEPS entries (ln) missing is
  # also a deterministic structured error - proves REQUIRED_DEPS actually
  # covers ln/rmdir/bash now, not just the pre-existing dependency set.
  echo "--- newly covered missing dependency (ln) detected before any use ---"
  local mdep2_bin="${SELFTEST_TMP}/mdep2-bin" dep2 mdep2_src mdep2_out mdep2_rc
  mkdir -p "$mdep2_bin"
  for dep2 in "${REQUIRED_DEPS[@]}"; do
    [[ "$dep2" == "ln" ]] && continue
    mdep2_src="$(command -v "$dep2" 2>/dev/null)" && ln -sf "$mdep2_src" "${mdep2_bin}/${dep2}"
  done
  mdep2_out="$(PATH="$mdep2_bin" "$BASH" "$SELF_PATH" 2>&1)"
  mdep2_rc=$?
  st_assert_eq "newly covered dep (ln) missing exit code is 2" "2" "$mdep2_rc"
  st_assert "newly covered dep (ln) missing reports HARNESS_STATUS=ERROR" "$([[ "$mdep2_out" == *"HARNESS_STATUS=ERROR"* ]] && echo true || echo false)"
  st_assert "newly covered dep (ln) missing reports CAPABILITY_STATUS=NOT_RUN" "$([[ "$mdep2_out" == *"CAPABILITY_STATUS=NOT_RUN"* ]] && echo true || echo false)"
  st_assert "newly covered dep (ln) missing reason names ln" "$([[ "$mdep2_out" == *"MISSING_DEPENDENCIES"*"ln"* ]] && echo true || echo false)"
  st_assert "newly covered dep (ln) missing never surfaces raw command-not-found noise" "$([[ "$mdep2_out" != *"command not found"* ]] && echo true || echo false)"

  # Scenario: one of the newly-covered REQUIRED_DEPS entries (cp) missing is
  # also a deterministic structured error - proves REQUIRED_DEPS actually
  # covers cp now, not just the pre-existing dependency set.
  echo "--- newly covered missing dependency (cp) detected before any use ---"
  local mdep3_bin="${SELFTEST_TMP}/mdep3-bin" dep3 mdep3_src mdep3_out mdep3_rc
  mkdir -p "$mdep3_bin"
  for dep3 in "${REQUIRED_DEPS[@]}"; do
    [[ "$dep3" == "cp" ]] && continue
    mdep3_src="$(command -v "$dep3" 2>/dev/null)" && ln -sf "$mdep3_src" "${mdep3_bin}/${dep3}"
  done
  mdep3_out="$(PATH="$mdep3_bin" "$BASH" "$SELF_PATH" 2>&1)"
  mdep3_rc=$?
  st_assert_eq "newly covered dep (cp) missing exit code is 2" "2" "$mdep3_rc"
  st_assert "newly covered dep (cp) missing reports HARNESS_STATUS=ERROR" "$([[ "$mdep3_out" == *"HARNESS_STATUS=ERROR"* ]] && echo true || echo false)"
  st_assert "newly covered dep (cp) missing reports CAPABILITY_STATUS=NOT_RUN" "$([[ "$mdep3_out" == *"CAPABILITY_STATUS=NOT_RUN"* ]] && echo true || echo false)"
  st_assert "newly covered dep (cp) missing reason names cp" "$([[ "$mdep3_out" == *"MISSING_DEPENDENCIES"*"cp"* ]] && echo true || echo false)"
  st_assert "newly covered dep (cp) missing never surfaces raw command-not-found noise" "$([[ "$mdep3_out" != *"command not found"* ]] && echo true || echo false)"

  # Scenario: primary evidence serialization fails -> atomic fallback
  # publishes a minimal, valid, canonical evidence.json (never a direct
  # write, and never leaving a stray unpublished tmp artifact behind).
  echo "--- atomic fallback: primary serialization failure recovers via fallback publish ---"
  run_fake_harness "${base_env[@]}" "LOOP_PACKAGE_A_SELFTEST_FORCE_RENDER_FAIL=1"
  st_assert_eq "primary render failure -> harness ERROR" "ERROR" "$(hs_field HARNESS_STATUS)"
  st_assert_eq "primary render failure -> shell exit 2" "2" "$HS_RC"
  local render_fail_evidence render_fail_dir
  render_fail_evidence="$(hs_field EVIDENCE_JSON)"
  st_assert "fallback evidence published and parseable" "$([[ "$render_fail_evidence" != "none" ]] && node_json_valid "$render_fail_evidence" && echo true || echo false)"
  st_assert_eq "fallback evidence records ERROR harness_status" "ERROR" "$(node_json_field "$render_fail_evidence" harness_status)"
  st_assert_eq "fallback evidence persists process_exit_code 2" "2" "$(node_json_field "$render_fail_evidence" process_exit_code)"
  case "$render_fail_evidence" in
    */*) render_fail_dir="${render_fail_evidence%/*}" ;;
    *) render_fail_dir="." ;;
  esac
  st_assert "no stray unpublished tmp evidence artifact left behind" "$([[ ! -e "${render_fail_dir}/.evidence.json.tmp" ]] && echo true || echo false)"

  # Scenario: BOTH primary and fallback serialization fail -> no evidence is
  # ever published, and there is no direct-write bypass to evidence.json.
  echo "--- atomic fallback: fallback serialization also fails -> no direct-write bypass ---"
  run_fake_harness "${base_env[@]}" "LOOP_PACKAGE_A_SELFTEST_FORCE_RENDER_FAIL=1" "LOOP_PACKAGE_A_SELFTEST_FORCE_FALLBACK_RENDER_FAIL=1"
  st_assert_eq "double failure -> EVIDENCE_JSON none" "none" "$(hs_field EVIDENCE_JSON)"
  st_assert_eq "double failure -> harness ERROR" "ERROR" "$(hs_field HARNESS_STATUS)"
  st_assert_eq "double failure -> shell exit 2" "2" "$HS_RC"
  local double_fail_run_id double_fail_dir
  double_fail_run_id="$(hs_field RUN_ID)"
  double_fail_dir="${EVIDENCE_ROOT_CANONICAL}/${double_fail_run_id}"
  st_assert "no evidence.json exists when both primary and fallback fail" "$([[ ! -f "${double_fail_dir}/evidence.json" ]] && echo true || echo false)"

  # Scenario: the final atomic rename itself fails -> recovers via fallback
  # publish (which is not subject to the same forced-fail marker, since it
  # is passed explicitly only at the primary call site).
  echo "--- atomic fallback: primary rename failure recovers via fallback publish ---"
  run_fake_harness "${base_env[@]}" "LOOP_PACKAGE_A_SELFTEST_FORCE_RENAME_FAIL=1"
  st_assert_eq "primary rename failure -> harness ERROR" "ERROR" "$(hs_field HARNESS_STATUS)"
  local rename_fail_evidence
  rename_fail_evidence="$(hs_field EVIDENCE_JSON)"
  st_assert "rename failure recovers via fallback publish" "$([[ "$rename_fail_evidence" != "none" ]] && node_json_valid "$rename_fail_evidence" && echo true || echo false)"
  st_assert_eq "fallback-after-rename-failure reason recorded" "EVIDENCE_PUBLISH_RENAME_FAILED" "$(node_json_field "$rename_fail_evidence" reason_code)"

  # Scenario: the self-test aggregate summary itself must publish through
  # the same publish_evidence_atomic primitive as canonical main-run
  # evidence - never a direct fs.writeFileSync onto evidence.json.
  echo "--- self-test summary: atomic publication ---"
  # Built from two fragments so the needle itself (the historical direct-
  # write pattern) never appears as one contiguous literal in this script's
  # own source - otherwise this very assertion line would self-match.
  local dw_needle_a='PKGA_OUT="${dir}' dw_needle_b='/evidence.json"' dw_needle
  dw_needle="${dw_needle_a}${dw_needle_b}"
  st_assert "self-test summary render/publish never writes canonical evidence.json directly (no dir/evidence.json target literal in source)" \
    "$(grep -Fq -- "$dw_needle" "$SELF_PATH" && echo false || echo true)"

  local sts_out sts_run_id sts_published sts_dir
  sts_out="$(self_test_write_summary 5 0)"
  sts_run_id="$(printf '%s\n' "$sts_out" | grep -m1 -oE '^RUN_ID=.*' | cut -d= -f2-)"
  sts_published="$(printf '%s\n' "$sts_out" | grep -m1 -oE '^PUBLISHED=.*' | cut -d= -f2-)"
  sts_dir="${EVIDENCE_ROOT_CANONICAL}/${sts_run_id}"
  st_assert "self-test summary publication succeeds through atomic path" "$([[ "$sts_published" != "none" && -f "$sts_published" ]] && echo true || echo false)"
  st_assert "self-test summary JSON parses" "$(node_json_valid "$sts_published" && echo true || echo false)"
  st_assert_eq "self-test summary records scenarios_passed" "5" "$(node_json_field "$sts_published" scenarios_passed)"
  st_assert "self-test summary leaves no stray unpublished tmp artifact" "$([[ ! -e "${sts_dir}/.evidence.json.selftest-summary.tmp" ]] && echo true || echo false)"
  rm -rf "$sts_dir" 2>/dev/null || true

  echo "--- self-test summary: forced publish failure cannot create canonical evidence.json ---"
  local sts_fail_out sts_fail_run_id sts_fail_published sts_fail_dir
  sts_fail_out="$(LOOP_PACKAGE_A_SELFTEST_FORCE_SUMMARY_RENAME_FAIL=1 self_test_write_summary 3 1)"
  sts_fail_run_id="$(printf '%s\n' "$sts_fail_out" | grep -m1 -oE '^RUN_ID=.*' | cut -d= -f2-)"
  sts_fail_published="$(printf '%s\n' "$sts_fail_out" | grep -m1 -oE '^PUBLISHED=.*' | cut -d= -f2-)"
  sts_fail_dir="${EVIDENCE_ROOT_CANONICAL}/${sts_fail_run_id}"
  st_assert_eq "forced summary publish failure reports PUBLISHED=none" "none" "$sts_fail_published"
  st_assert "forced summary publish failure leaves no canonical evidence.json" "$([[ ! -f "${sts_fail_dir}/evidence.json" ]] && echo true || echo false)"
  rm -rf "$sts_fail_dir" 2>/dev/null || true

  cleanup_path "$SELFTEST_TMP" "$SELFTEST_TMP" >/dev/null 2>&1 || true

  echo "=== self-test summary: ${ST_PASS} passed, ${ST_FAIL} failed ==="

  if ! self_test_write_summary "$ST_PASS" "$ST_FAIL" >/dev/null; then
    echo "self-test summary publication FAILED - no canonical evidence.json was written for this aggregate summary" >&2
  fi

  [[ "$ST_FAIL" -eq 0 ]]
}

# render_self_test_summary <out_file> <passed> <failed> <run_id>
# Renders the aggregate self-test summary to <out_file> (never to the
# canonical evidence.json path itself - self_test_write_summary is
# responsible for publishing via the same publish_evidence_atomic primitive
# main-run evidence uses). Mirrors render_fallback_evidence's contract.
render_self_test_summary() {
  local out="$1" passed="$2" failed="$3" run_id="$4"
  if [[ "${LOOP_PACKAGE_A_SELFTEST_FORCE_SUMMARY_RENDER_FAIL:-}" == "1" ]]; then
    echo "self-test injected summary render failure (LOOP_PACKAGE_A_SELFTEST_FORCE_SUMMARY_RENDER_FAIL=1)" >&2
    return 1
  fi
  PKGA_RUN_ID="$run_id" PKGA_PASSED="$passed" PKGA_FAILED="$failed" PKGA_OUT="$out" node - <<'NODE_EOF'
const fs = require("fs");
const payload = {
  schema_version: "3.0.0",
  package: "A",
  run_id: process.env.PKGA_RUN_ID,
  run_label: "fault_injection_summary",
  scenarios_passed: Number(process.env.PKGA_PASSED),
  scenarios_failed: Number(process.env.PKGA_FAILED),
  overall_pass: Number(process.env.PKGA_FAILED) === 0,
  note: "aggregate self-test summary; each individual scenario also persisted its own evidence.json under evidence/package-a/ with run_label=fault_injection",
};
const json = `${JSON.stringify(payload, null, 2)}\n`;
JSON.parse(json);
fs.writeFileSync(process.env.PKGA_OUT, json);
JSON.parse(fs.readFileSync(process.env.PKGA_OUT, "utf8"));
NODE_EOF
}

# self_test_write_summary <passed> <failed>
# Renders the aggregate self-test summary to a same-directory temp file and
# publishes it through the exact same publish_evidence_atomic primitive that
# canonical main-run evidence uses - never a direct fs.writeFileSync onto
# evidence.json. Prints RUN_ID=<id> and PUBLISHED=<final path>|none so
# callers (and self-tests of this very function) can tell whether the
# canonical file actually exists; a publish failure is reported, never
# silently bypassed by a direct canonical write.
self_test_write_summary() {
  local passed="$1" failed="$2" run_id dir tmp final force_fail=""
  run_id="pkgA-selftest-$(date -u +%Y%m%dT%H%M%SZ)-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
  dir="${EVIDENCE_ROOT_CANONICAL}/${run_id}"
  echo "RUN_ID=${run_id}"
  mkdir -p "$dir" 2>/dev/null || { echo "PUBLISHED=none"; return 1; }
  final="${dir}/evidence.json"
  tmp="${dir}/.evidence.json.selftest-summary.tmp"
  rm -f "$tmp"
  [[ "${LOOP_PACKAGE_A_SELFTEST_FORCE_SUMMARY_RENAME_FAIL:-}" == "1" ]] && force_fail="LOOP_PACKAGE_A_SELFTEST_FORCE_SUMMARY_RENAME_FAIL"
  if ! render_self_test_summary "$tmp" "$passed" "$failed" "$run_id"; then
    harness_error "self-test summary rendering failed"
    rm -f "$tmp"
    echo "PUBLISHED=none"
    return 1
  fi
  if ! publish_evidence_atomic "$tmp" "$final" "$force_fail"; then
    echo "PUBLISHED=none"
    return 1
  fi
  echo "PUBLISHED=${final}"
  return 0
}

# Sourcing exposes the helpers for negative testing without running a probe.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if [[ "${1:-}" == "--self-test" ]]; then
    run_self_test
    exit $?
  fi
  main "$@"
  exit $?
fi
