#!/bin/bash
# Package B - Single-repository read-only implementer -> verifier loop.
#
# Deterministic orchestrator around exactly two real agents:
#   1. an implementer (default: Claude Code) that reads this repository
#      read-only and writes a structured proposal artifact
#   2. an independent verifier (default: Codex) that judges the proposal
#      without ever talking to the implementer
#
# The two agents never communicate directly - all handoff is via evidence
# files on disk. The orchestrator (this script), not either model, decides
# PASS / FAIL / BLOCKED / TIMEOUT / ERROR.
#
# This is a READ-ONLY simulation: the implementer's tool access is limited to
# Read/Glob/Grep, the verifier runs inside Codex's read-only sandbox, and -
# regardless of what either agent claims - the orchestrator captures a
# before/after snapshot of the target repository and fails closed if
# anything in the tracked tree or untracked-but-not-ignored files changed.
#
# Package A (scripts/package-a.sh) is invoked unmodified as an execution
# capability gate before any agent runs; Package B never reimplements its
# claude/codex/gh capability checks.
#
# Deliberately no global `set -e`: a failing step must be classified, not
# silently abort the script before evidence is written.
#
# Exit codes: 0 harness healthy + Package B PASS, 1 harness healthy +
# Package B FAIL/BLOCKED/TIMEOUT, 2 Package B harness ERROR.

set -uo pipefail

SCHEMA_VERSION="1.0.0"
PACKAGE="B"
ARTIFACT_SCHEMA_VERSION="1.0.0"

IMPLEMENTER_TIMEOUT_SECONDS="${LOOP_PACKAGE_B_IMPLEMENTER_TIMEOUT_SECONDS:-240}"
VERIFIER_TIMEOUT_SECONDS="${LOOP_PACKAGE_B_VERIFIER_TIMEOUT_SECONDS:-180}"
GATE_TIMEOUT_SECONDS="${LOOP_PACKAGE_B_GATE_TIMEOUT_SECONDS:-300}"
GRACE_SECONDS="${LOOP_PACKAGE_B_GRACE_SECONDS:-10}"

# Fixed by design (see PACKAGE_B spec section H): bounded, non-configurable,
# so no invocation can accidentally grant unbounded retries.
readonly MAX_ITERATIONS=2

IMPLEMENTER_COMPLETION_SIGNAL="IMPLEMENTER_COMPLETE"
VERIFIER_COMPLETION_SIGNAL="VERIFIER_COMPLETE"
IMPLEMENTER_CLI="claude"
VERIFIER_CLI="codex"

# ---------- bootstrap: resolve script location using only bash builtins ----------
SELF_SOURCE="${BASH_SOURCE[0]}"
case "$SELF_SOURCE" in
  */*) SELF_SOURCE_DIR="${SELF_SOURCE%/*}" ;;
  *) SELF_SOURCE_DIR="." ;;
esac
REPO_ROOT="$(cd "${SELF_SOURCE_DIR}/.." && pwd)"
SELF_PATH="${REPO_ROOT}/scripts/package-b.sh"
PACKAGE_A_SCRIPT="${LOOP_PACKAGE_B_PACKAGE_A_SCRIPT:-${REPO_ROOT}/scripts/package-a.sh}"

# Every external executable this script (main path, helpers, self-test) may
# invoke must be listed here so a missing dependency surfaces as an explicit
# ERROR, never a raw "command not found". claude/codex are intentionally
# excluded: their absence is a normal, evidenced BLOCKED outcome, not a
# harness dependency failure.
REQUIRED_DEPS=(mktemp realpath sha256sum date od setsid kill node git grep sed awk cut tr mkdir rm mv head chmod cat wc find sort bash env)

preflight_missing_deps() {
  local dep missing=()
  for dep in "${REQUIRED_DEPS[@]}"; do
    command -v "$dep" >/dev/null 2>&1 || missing+=("$dep")
  done
  printf '%s' "${missing[*]:-}"
}

BOOTSTRAP_MISSING_DEPS="$(preflight_missing_deps)"
if [[ -n "$BOOTSTRAP_MISSING_DEPS" && "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "HARNESS_STATUS=ERROR"
  echo "FINAL_STATUS=NOT_RUN"
  echo "REASON=MISSING_DEPENDENCIES:${BOOTSTRAP_MISSING_DEPS}"
  echo "EVIDENCE_JSON=none"
  exit 2
fi

# ---------- small helpers ----------

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
now_ms() { echo $(( $(date +%s%N) / 1000000 )); }

HARNESS_ERRORS=0
harness_error() {
  HARNESS_ERRORS=$(( HARNESS_ERRORS + 1 ))
  echo "harness-error: $1" >&2
}

count_lines() { [[ -s "$1" ]] && wc -l <"$1" | tr -d ' ' || echo 0; }
file_sha256() { sha256sum -- "$1" 2>/dev/null | cut -d' ' -f1; }

# ---------- process-group bounded execution (same contract as Package A) ----------

# run_bounded <timeout_s> <grace_s> <stdout_file> <stderr_file> <cmd...>
# Echoes "<rc> <deadline_fired> <pgid>". deadline_fired=true is only ever set
# by this harness's own watcher actually acting, so it is deterministic
# proof the harness's deadline (not something external) caused termination.
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

# classify_process_result <rc> <deadline_fired> -> "<STATUS> <REASON_CODE> <NOTE>"
# TIMEOUT is reserved for cases where THIS harness's own watcher proves it
# fired the kill. An unexplained 137 is a FAIL, never a TIMEOUT.
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

# compute_process_exit_code <harness_status> <final_status>
compute_process_exit_code() {
  local hstatus="$1" fstatus="$2"
  if [[ "$hstatus" != "PASS" ]]; then printf '2'; return; fi
  if [[ "$fstatus" != "PASS" ]]; then printf '1'; return; fi
  printf '0'
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

# redact_to_evidence <raw_file> <dest_evidence_file> -> echoes redacted match count
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

# scan_secrets <target...> -> echoes finding count; records file:line only.
scan_secrets() {
  local report="${EVIDENCE_DIR}/secret-scan.txt" pattern target findings hits
  hits="$(mktemp "${PKGB_TMP_ROOT}/scan.XXXXXX")"
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

# ---------- evidence field capture / atomic publication ----------
# Same base64-in / node-decode-out mechanism as Package A: values are
# base64-encoded on the way in so quotes, backslashes, newlines, tabs and
# invalid byte sequences can never corrupt the evidence file. Node decodes,
# validates UTF-8 and serializes.

kv() {
  printf '%s\t%s\t%s\n' "$1" "$2" "$(printf '%s' "$3" | base64 | tr -d '\n')" >>"$FIELDS_FILE"
}
kv_s() { kv s "$1" "$2"; }
kv_n() { kv n "$1" "$2"; }
kv_b() { kv b "$1" "$2"; }
kv_z() { kv z "$1" ""; }
kv_arr() { kv a "$1" ""; }

render_evidence() {
  PKGB_FIELDS="$1" PKGB_OUT="$2" node - <<'NODE_EOF'
const fs = require("fs");
const fieldsPath = process.env.PKGB_FIELDS;
const outPath = process.env.PKGB_OUT;
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
    case "s": value = text; break;
    case "n": { const num = Number(text); value = Number.isFinite(num) ? num : null; break; }
    case "b": value = text === "true"; break;
    case "z": value = null; break;
    case "a": value = []; break;
    default: throw new Error(`unknown field type: ${type}`);
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

render_fallback_evidence() {
  local out="$1" reason="$2" exit_code="$3"
  PKGB_RUN_ID="${RUN_ID:-unknown}" PKGB_DIR="${EVIDENCE_DIR:-unknown}" PKGB_REASON="$reason" PKGB_EXIT="$exit_code" PKGB_OUT="$out" node - <<'NODE_EOF'
const fs = require("fs");
const payload = {
  schema_version: process.env.SCHEMA_VERSION_UNUSED,
  package: "B",
  run_id: process.env.PKGB_RUN_ID,
  evidence_dir: process.env.PKGB_DIR,
  harness_status: "ERROR",
  final_status: "ERROR",
  reason_code: process.env.PKGB_REASON || "EVIDENCE_SERIALIZATION_FAILED",
  process_exit_code: Number(process.env.PKGB_EXIT),
  note: "full evidence could not be serialized; this is a minimal fallback record; check artifacts in evidence_dir",
};
const json = `${JSON.stringify(payload, null, 2)}\n`;
JSON.parse(json);
fs.writeFileSync(process.env.PKGB_OUT, json);
JSON.parse(fs.readFileSync(process.env.PKGB_OUT, "utf8"));
NODE_EOF
}

# publish_evidence_atomic <tmp_json> <final_json>
# The ONLY way canonical evidence.json is ever written: <tmp_json> must
# already exist in the SAME directory as <final_json> and contain validated
# JSON. Publication is a same-directory rename.
publish_evidence_atomic() {
  local tmp="$1" final="$2"
  if [[ ! -s "$tmp" ]]; then
    harness_error "evidence publish: source file missing or empty: $tmp"
    return 1
  fi
  if ! node -e "JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))" "$tmp" >/dev/null 2>&1; then
    harness_error "evidence publish: source file is not valid JSON: $tmp"
    mv -f "$tmp" "${tmp}.invalid-json" 2>/dev/null || rm -f "$tmp"
    return 1
  fi
  if [[ "${LOOP_PACKAGE_B_SELFTEST_FORCE_RENAME_FAIL:-}" == "1" ]]; then
    harness_error "evidence publish: self-test injected atomic-rename failure"
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

# ---------- Claude native structured-output envelope extraction ----------
# The implementer is invoked with `--output-format json --json-schema <...>`.
# A genuine envelope is a single `claude --output-format json` success result
# that ALSO carries Claude's own natively schema-validated `structured_output`
# object (not the free-text `result` field). Only `structured_output` is ever
# extracted - never `result`, never a markdown-fenced or prose-wrapped
# substring, never a "last JSON object" scan. Returns 0 (found), 3 (none
# found - covers a missing/non-object structured_output just as much as a
# missing envelope), 4 (ambiguous: more than one genuine envelope).
extract_claude_structured_output() {
  local raw="$1" out="$2" rc
  rm -f "$out"
  [[ -s "$raw" ]] || return 3
  PKGB_RAW_STDOUT="$raw" PKGB_COMPLETION_OUT="$out" node - <<'NODE_EOF' 2>/dev/null
const fs = require("fs");
const text = fs.readFileSync(process.env.PKGB_RAW_STDOUT, "utf8");
const isGenuine = (e) =>
  e !== null && typeof e === "object" && !Array.isArray(e) &&
  e.type === "result" && e.subtype === "success" && e.is_error === false &&
  typeof e.result === "string" &&
  e.structured_output !== undefined && e.structured_output !== null &&
  typeof e.structured_output === "object" && !Array.isArray(e.structured_output);
const collect = (doc, out) => {
  if (Array.isArray(doc)) { for (const item of doc) if (isGenuine(item)) out.push(item); }
  else if (isGenuine(doc)) out.push(doc);
};
const envelopes = [];
try {
  collect(JSON.parse(text), envelopes);
} catch (e) {
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try { collect(JSON.parse(trimmed), envelopes); } catch (inner) { /* not an envelope line */ }
  }
}
if (envelopes.length === 0) process.exit(3);
if (envelopes.length > 1) process.exit(4);
fs.writeFileSync(process.env.PKGB_COMPLETION_OUT, JSON.stringify(envelopes[0].structured_output));
NODE_EOF
  rc=$?
  [[ $rc -eq 0 && -f "$out" ]] && return 0
  [[ $rc -eq 3 || $rc -eq 4 ]] && return $rc
  return 3
}

# validate_implementer_artifact <raw_candidate_file> <task_file> <out_file>
# Echoes "<true|false> <reason>". <out_file> always receives either the
# normalized valid object or an {artifact_valid:false,...} wrapper carrying
# the raw text - never a bare substring/prose match.
validate_implementer_artifact() {
  local raw_file="$1" task_file="$2" out_file="$3"
  PKGB_RAW="$raw_file" PKGB_TASK_FILE="$task_file" PKGB_OUT="$out_file" \
    PKGB_EXPECTED_SCHEMA="$ARTIFACT_SCHEMA_VERSION" PKGB_EXPECTED_SIGNAL="$IMPLEMENTER_COMPLETION_SIGNAL" \
    node - <<'NODE_EOF'
const fs = require("fs");
const rawPath = process.env.PKGB_RAW;
const outPath = process.env.PKGB_OUT;
let raw = fs.existsSync(rawPath) ? fs.readFileSync(rawPath, "utf8") : "";
raw = raw.replace(/\r\n/g, "\n");
if (raw.endsWith("\n")) raw = raw.slice(0, -1);
const expectedTask = fs.readFileSync(process.env.PKGB_TASK_FILE, "utf8");

function invalid(reason) {
  fs.writeFileSync(outPath, JSON.stringify({ artifact_valid: false, invalid_reason: reason, raw_text: raw }, null, 2) + "\n");
  console.log(`false ${reason}`);
}

let obj;
try { obj = JSON.parse(raw); } catch (e) { invalid("JSON_PARSE_ERROR"); process.exit(0); }
if (obj === null || typeof obj !== "object" || Array.isArray(obj)) { invalid("NOT_OBJECT"); process.exit(0); }
if (obj.schema_version !== process.env.PKGB_EXPECTED_SCHEMA) { invalid("SCHEMA_VERSION_MISMATCH"); process.exit(0); }
if (obj.role !== "implementer") { invalid("ROLE_MISMATCH"); process.exit(0); }
if (typeof obj.task !== "string" || obj.task !== expectedTask) { invalid("TASK_MISMATCH"); process.exit(0); }
if (!Array.isArray(obj.proposal) || obj.proposal.length === 0) { invalid("PROPOSAL_EMPTY_OR_NOT_ARRAY"); process.exit(0); }
if (obj.completion_signal !== process.env.PKGB_EXPECTED_SIGNAL) { invalid("COMPLETION_SIGNAL_MISMATCH"); process.exit(0); }

fs.writeFileSync(outPath, JSON.stringify(obj, null, 2) + "\n");
console.log("true OK");
NODE_EOF
}

# validate_verifier_artifact <raw_final_message_file> <out_file>
# Echoes "<true|false> <reason> <verdict|NONE>".
validate_verifier_artifact() {
  local raw_file="$1" out_file="$2"
  PKGB_RAW="$raw_file" PKGB_OUT="$out_file" \
    PKGB_EXPECTED_SCHEMA="$ARTIFACT_SCHEMA_VERSION" PKGB_EXPECTED_SIGNAL="$VERIFIER_COMPLETION_SIGNAL" \
    node - <<'NODE_EOF'
const fs = require("fs");
const rawPath = process.env.PKGB_RAW;
const outPath = process.env.PKGB_OUT;
let raw = fs.existsSync(rawPath) ? fs.readFileSync(rawPath, "utf8") : "";
raw = raw.replace(/\r\n/g, "\n");
if (raw.endsWith("\n")) raw = raw.slice(0, -1);

function invalid(reason) {
  fs.writeFileSync(outPath, JSON.stringify({ artifact_valid: false, invalid_reason: reason, raw_text: raw }, null, 2) + "\n");
  console.log(`false ${reason} NONE`);
}

let obj;
try { obj = JSON.parse(raw); } catch (e) { invalid("JSON_PARSE_ERROR"); process.exit(0); }
if (obj === null || typeof obj !== "object" || Array.isArray(obj)) { invalid("NOT_OBJECT"); process.exit(0); }
if (obj.schema_version !== process.env.PKGB_EXPECTED_SCHEMA) { invalid("SCHEMA_VERSION_MISMATCH"); process.exit(0); }
if (obj.role !== "verifier") { invalid("ROLE_MISMATCH"); process.exit(0); }
if (!["PASS", "FAIL", "BLOCKED"].includes(obj.verdict)) { invalid("VERDICT_INVALID"); process.exit(0); }
if (!Array.isArray(obj.findings)) { invalid("FINDINGS_NOT_ARRAY"); process.exit(0); }
if (typeof obj.reason !== "string" || obj.reason.length === 0) { invalid("REASON_MISSING"); process.exit(0); }
if (obj.completion_signal !== process.env.PKGB_EXPECTED_SIGNAL) { invalid("COMPLETION_SIGNAL_MISMATCH"); process.exit(0); }

fs.writeFileSync(outPath, JSON.stringify(obj, null, 2) + "\n");
console.log(`true OK ${obj.verdict}`);
NODE_EOF
}

# ---------- target repository read-only snapshot ----------

# capture_target_snapshot <repo> <BEFORE|AFTER>
capture_target_snapshot() {
  local repo="$1" prefix="$2"
  local branch head status_raw diff_raw untracked_raw diff_hash untracked_hash tracked_changes
  branch="$(git -C "$repo" rev-parse --abbrev-ref HEAD 2>/dev/null)"; [[ -n "$branch" ]] || branch="unknown"
  head="$(git -C "$repo" rev-parse HEAD 2>/dev/null)"; [[ -n "$head" ]] || head="unknown"
  status_raw="$(git -C "$repo" status --porcelain=v1 --untracked-files=all 2>/dev/null)"
  tracked_changes="$(git -C "$repo" diff --name-status HEAD -- 2>/dev/null)"
  diff_raw="$(git -C "$repo" diff --binary HEAD -- 2>/dev/null)"
  untracked_raw="$(git -C "$repo" ls-files --others --exclude-standard 2>/dev/null | LC_ALL=C sort)"
  diff_hash="$(printf '%s' "$diff_raw" | sha256sum | cut -d' ' -f1)"
  untracked_hash="$(printf '%s' "$untracked_raw" | sha256sum | cut -d' ' -f1)"

  case "$prefix" in
    BEFORE)
      TARGET_BRANCH_BEFORE="$branch"; TARGET_HEAD_BEFORE="$head"
      TARGET_STATUS_BEFORE="$status_raw"; TARGET_TRACKED_CHANGES_BEFORE="$tracked_changes"
      TARGET_DIFF_HASH_BEFORE="$diff_hash"; TARGET_UNTRACKED_BEFORE="$untracked_raw"
      TARGET_UNTRACKED_HASH_BEFORE="$untracked_hash" ;;
    AFTER)
      TARGET_BRANCH_AFTER="$branch"; TARGET_HEAD_AFTER="$head"
      TARGET_STATUS_AFTER="$status_raw"; TARGET_TRACKED_CHANGES_AFTER="$tracked_changes"
      TARGET_DIFF_HASH_AFTER="$diff_hash"; TARGET_UNTRACKED_AFTER="$untracked_raw"
      TARGET_UNTRACKED_HASH_AFTER="$untracked_hash" ;;
  esac
}

compute_target_mutation() {
  MUTATION_DETECTED=false
  MUTATION_REASONS=()
  [[ "$TARGET_HEAD_BEFORE" == "$TARGET_HEAD_AFTER" ]] || { MUTATION_DETECTED=true; MUTATION_REASONS+=("HEAD_CHANGED"); }
  [[ "$TARGET_BRANCH_BEFORE" == "$TARGET_BRANCH_AFTER" ]] || { MUTATION_DETECTED=true; MUTATION_REASONS+=("BRANCH_CHANGED"); }
  [[ "$TARGET_DIFF_HASH_BEFORE" == "$TARGET_DIFF_HASH_AFTER" ]] || { MUTATION_DETECTED=true; MUTATION_REASONS+=("TRACKED_CONTENT_CHANGED"); }
  [[ "$TARGET_UNTRACKED_HASH_BEFORE" == "$TARGET_UNTRACKED_HASH_AFTER" ]] || { MUTATION_DETECTED=true; MUTATION_REASONS+=("UNTRACKED_FILES_CHANGED"); }
}

emit_snapshot_fields() {
  kv_s "target.repo" "$TARGET_REPO"
  kv_s "target.snapshot.before.branch" "$TARGET_BRANCH_BEFORE"
  kv_s "target.snapshot.before.head_sha" "$TARGET_HEAD_BEFORE"
  kv_s "target.snapshot.before.status" "$TARGET_STATUS_BEFORE"
  kv_s "target.snapshot.before.tracked_changes" "$TARGET_TRACKED_CHANGES_BEFORE"
  kv_s "target.snapshot.before.untracked_files" "$TARGET_UNTRACKED_BEFORE"
  kv_s "target.snapshot.after.branch" "$TARGET_BRANCH_AFTER"
  kv_s "target.snapshot.after.head_sha" "$TARGET_HEAD_AFTER"
  kv_s "target.snapshot.after.status" "$TARGET_STATUS_AFTER"
  kv_s "target.snapshot.after.tracked_changes" "$TARGET_TRACKED_CHANGES_AFTER"
  kv_s "target.snapshot.after.untracked_files" "$TARGET_UNTRACKED_AFTER"
  kv_b "target.mutation.detected" "$MUTATION_DETECTED"
  kv_arr "target.mutation.reasons"
  local i=0 r
  for r in "${MUTATION_REASONS[@]:-}"; do
    [[ -n "$r" ]] || continue
    kv_s "target.mutation.reasons.${i}" "$r"
    i=$(( i + 1 ))
  done
}

# ---------- Package A capability gate ----------

run_package_a_gate() {
  local gate_dir="${EVIDENCE_DIR}/package-a-gate"
  mkdir -p "$gate_dir"
  local out="${PKGB_TMP_ROOT}/raw/pkga.stdout.txt" err="${PKGB_TMP_ROOT}/raw/pkga.stderr.txt"
  local rc fired pid

  GATE_HARNESS_STATUS="ERROR"; GATE_CAPABILITY_STATUS="NOT_RUN"; GATE_RUN_ID=""
  GATE_EVIDENCE_JSON="none"; GATE_EXIT_CODE=""; GATE_DEADLINE_FIRED=false; GATE_REASON="NOT_ATTEMPTED"
  : >"${gate_dir}/gate.stdout.txt"
  : >"${gate_dir}/gate.stderr.txt"

  if [[ ! -f "$PACKAGE_A_SCRIPT" ]]; then
    GATE_REASON="PACKAGE_A_SCRIPT_NOT_FOUND"
    harness_error "Package A gate script not found: ${PACKAGE_A_SCRIPT}"
    return
  fi

  read -r rc fired pid < <( run_bounded "$GATE_TIMEOUT_SECONDS" "$GRACE_SECONDS" "$out" "$err" bash "$PACKAGE_A_SCRIPT" )
  GATE_EXIT_CODE="$rc"; GATE_DEADLINE_FIRED="$fired"

  GATE_RUN_ID="$(grep -m1 -oE '^RUN_ID=.*' "$out" 2>/dev/null | cut -d= -f2-)"
  local hstatus cstatus ejson
  hstatus="$(grep -m1 -oE '^HARNESS_STATUS=.*' "$out" 2>/dev/null | cut -d= -f2-)"
  cstatus="$(grep -m1 -oE '^CAPABILITY_STATUS=.*' "$out" 2>/dev/null | cut -d= -f2-)"
  ejson="$(grep -m1 -oE '^EVIDENCE_JSON=.*' "$out" 2>/dev/null | cut -d= -f2-)"
  [[ -n "$ejson" ]] && GATE_EVIDENCE_JSON="$ejson"

  if [[ "$fired" == true ]]; then
    GATE_HARNESS_STATUS="ERROR"; GATE_CAPABILITY_STATUS="NOT_RUN"; GATE_REASON="GATE_TIMEOUT"
  elif [[ -z "$hstatus" ]]; then
    GATE_HARNESS_STATUS="ERROR"; GATE_CAPABILITY_STATUS="NOT_RUN"; GATE_REASON="GATE_OUTPUT_UNPARSEABLE"
  else
    GATE_HARNESS_STATUS="$hstatus"
    GATE_CAPABILITY_STATUS="${cstatus:-NOT_RUN}"
    GATE_REASON="OK"
  fi

  redact_to_evidence "$out" "${gate_dir}/gate.stdout.txt" >/dev/null
  redact_to_evidence "$err" "${gate_dir}/gate.stderr.txt" >/dev/null
}

emit_gate_fields() {
  kv_s "package_a_gate.script" "$PACKAGE_A_SCRIPT"
  kv_s "package_a_gate.run_id" "${GATE_RUN_ID:-unknown}"
  kv_s "package_a_gate.harness_status" "$GATE_HARNESS_STATUS"
  kv_s "package_a_gate.capability_status" "$GATE_CAPABILITY_STATUS"
  kv_s "package_a_gate.evidence_json" "${GATE_EVIDENCE_JSON:-none}"
  kv_n "package_a_gate.exit_code" "${GATE_EXIT_CODE:-0}"
  kv_b "package_a_gate.deadline_fired" "${GATE_DEADLINE_FIRED:-false}"
  kv_n "package_a_gate.timeout_seconds" "$GATE_TIMEOUT_SECONDS"
  kv_s "package_a_gate.reason" "$GATE_REASON"
  kv_s "package_a_gate.stdout_artifact" "package-a-gate/gate.stdout.txt"
  kv_s "package_a_gate.stderr_artifact" "package-a-gate/gate.stderr.txt"
}

# ---------- prompt construction ----------

build_implementer_prompt() {
  local task="$1" prior_file="$2" findings_file="$3" prior_text="" findings_text=""
  [[ -n "$prior_file" && -s "$prior_file" ]] && prior_text="$(cat "$prior_file")"
  [[ -n "$findings_file" && -s "$findings_file" ]] && findings_text="$(cat "$findings_file")"
  if [[ -n "$prior_text" ]]; then
    cat <<PKGB_IMPL_PROMPT_R2_8f2a
You are the Package B implementer in a bounded, read-only repository-inspection exercise. This is iteration 2 of at most 2. Do NOT modify any files in this repository under any circumstances - you have only been granted Read, Glob, and Grep tools.

Original task:
${task}

Your previous proposal (iteration 1):
${prior_text}

The independent verifier rejected it with these findings:
${findings_text}

Revise your proposal to address the verifier's findings. Respond with ONLY a single, raw JSON object - no markdown code fences, no prose before or after - matching exactly this schema:
{"schema_version":"${ARTIFACT_SCHEMA_VERSION}","role":"implementer","task":"<the exact original task text above, verbatim>","proposal":[{"title":"...","rationale":"..."}],"completion_signal":"${IMPLEMENTER_COMPLETION_SIGNAL}"}
PKGB_IMPL_PROMPT_R2_8f2a
  else
    cat <<PKGB_IMPL_PROMPT_R1_8f2a
You are the Package B implementer in a bounded, read-only repository-inspection exercise. Do NOT modify any files in this repository under any circumstances - you have only been granted Read, Glob, and Grep tools.

Task:
${task}

Inspect the repository as needed using only Read, Glob, and Grep. Then respond with ONLY a single, raw JSON object - no markdown code fences, no prose before or after - matching exactly this schema:
{"schema_version":"${ARTIFACT_SCHEMA_VERSION}","role":"implementer","task":"<the exact task text above, verbatim>","proposal":[{"title":"...","rationale":"..."}],"completion_signal":"${IMPLEMENTER_COMPLETION_SIGNAL}"}
PKGB_IMPL_PROMPT_R1_8f2a
  fi
}

# build_implementer_json_schema -> echoes a JSON Schema string passed
# verbatim to `claude --json-schema`, enforcing the Package B implementer
# artifact shape natively at generation time. `task` is intentionally left
# as an unconstrained string here (its exact-match-against-the-original-task
# check happens afterward in validate_implementer_artifact, since a JSON
# Schema const cannot safely embed arbitrary runtime task text).
build_implementer_json_schema() {
  cat <<PKGB_IMPL_SCHEMA_EOF
{"type":"object","properties":{"schema_version":{"type":"string","const":"${ARTIFACT_SCHEMA_VERSION}"},"role":{"type":"string","const":"implementer"},"task":{"type":"string","minLength":1},"proposal":{"type":"array","minItems":1,"items":{"type":"object","properties":{"title":{"type":"string","minLength":1},"rationale":{"type":"string","minLength":1}},"required":["title","rationale"],"additionalProperties":false}},"completion_signal":{"type":"string","const":"${IMPLEMENTER_COMPLETION_SIGNAL}"}},"required":["schema_version","role","task","proposal","completion_signal"],"additionalProperties":false}
PKGB_IMPL_SCHEMA_EOF
}

build_verifier_prompt() {
  local task="$1" artifact_file="$2" artifact_text=""
  [[ -s "$artifact_file" ]] && artifact_text="$(cat "$artifact_file")"
  cat <<PKGB_VERIFIER_PROMPT_7c2e
You are the Package B independent verifier in a bounded, read-only repository-inspection exercise. You have not seen the implementer's reasoning, only its final artifact below, and you cannot ask it questions. Do not modify any files; you are running in a read-only sandbox.

Original task given to the implementer:
${task}

Repository under test:
  path: ${TARGET_REPO}
  branch: ${TARGET_BRANCH_BEFORE}
  head_sha: ${TARGET_HEAD_BEFORE}

Implementer's proposal artifact:
${artifact_text}

Independently inspect the repository as needed to judge the proposal's quality and factual accuracy. Then respond with ONLY a single, raw JSON object - no markdown code fences, no prose before or after - matching exactly this schema:
{"schema_version":"${ARTIFACT_SCHEMA_VERSION}","role":"verifier","verdict":"PASS or FAIL or BLOCKED","findings":["..."],"reason":"...","completion_signal":"${VERIFIER_COMPLETION_SIGNAL}"}

Use verdict "PASS" only if the proposal is well-formed, on-task, and substantively useful. Use "FAIL" if it is off-task, low-value, or factually wrong. Use "BLOCKED" only if you cannot evaluate it at all (e.g. the repository is inaccessible).
PKGB_VERIFIER_PROMPT_7c2e
}

# ---------- implementer / verifier runners ----------

reset_implementer_globals() {
  IMPLEMENTER_STATUS="NOT_RUN"; IMPLEMENTER_REASON="NOT_ATTEMPTED"
  IMPLEMENTER_STARTED_AT=""; IMPLEMENTER_COMPLETED_AT=""; IMPLEMENTER_DURATION_MS=0
  IMPLEMENTER_EXIT_CODE=""; IMPLEMENTER_DEADLINE_FIRED=false; IMPLEMENTER_ARTIFACT_VALID=false
  IMPLEMENTER_STDOUT_REL=""; IMPLEMENTER_STDERR_REL=""; IMPLEMENTER_ARTIFACT_REL=""
}

# run_implementer <iteration> <task> <prior_proposal_file> <verifier_findings_file> <iter_dir>
run_implementer() {
  local iteration="$1" task="$2" prior_file="$3" findings_file="$4" iter_dir="$5"
  reset_implementer_globals
  local out_stdout="${iter_dir}/implementer.stdout.txt" out_stderr="${iter_dir}/implementer.stderr.txt"
  local out_artifact="${iter_dir}/implementer-proposal.json"
  IMPLEMENTER_STDOUT_REL="iteration-${iteration}/implementer.stdout.txt"
  IMPLEMENTER_STDERR_REL="iteration-${iteration}/implementer.stderr.txt"
  IMPLEMENTER_ARTIFACT_REL="iteration-${iteration}/implementer-proposal.json"
  : >"$out_stdout"; : >"$out_stderr"

  if ! command -v "$IMPLEMENTER_CLI" >/dev/null 2>&1; then
    IMPLEMENTER_STATUS="BLOCKED"; IMPLEMENTER_REASON="CLI_NOT_FOUND"
    printf '{"artifact_valid":false,"invalid_reason":"CLI_NOT_FOUND"}\n' >"$out_artifact"
    return
  fi

  local raw_out="${PKGB_TMP_ROOT}/raw/impl-${iteration}.stdout.txt"
  local raw_err="${PKGB_TMP_ROOT}/raw/impl-${iteration}.stderr.txt"
  local raw_completion="${PKGB_TMP_ROOT}/raw/impl-${iteration}.completion.txt"
  local validated="${PKGB_TMP_ROOT}/raw/impl-${iteration}.validated.json"
  local prompt json_schema rc fired pid

  prompt="$(build_implementer_prompt "$task" "$prior_file" "$findings_file")"
  json_schema="$(build_implementer_json_schema)"

  IMPLEMENTER_STARTED_AT="$(now_iso)"
  local t0 t1
  t0="$(now_ms)"
  read -r rc fired pid < <( cd "$TARGET_REPO" && PKGB_ITERATION="$iteration" run_bounded \
    "$IMPLEMENTER_TIMEOUT_SECONDS" "$GRACE_SECONDS" "$raw_out" "$raw_err" \
    "$IMPLEMENTER_CLI" -p --max-turns 20 --permission-mode default --tools "Read,Glob,Grep" \
      --output-format json --json-schema "$json_schema" "$prompt" )
  t1="$(now_ms)"
  IMPLEMENTER_COMPLETED_AT="$(now_iso)"
  IMPLEMENTER_DURATION_MS=$(( t1 - t0 ))
  IMPLEMENTER_EXIT_CODE="$rc"; IMPLEMENTER_DEADLINE_FIRED="$fired"

  local status reason
  read -r status reason _ < <(classify_process_result "$rc" "$fired")

  extract_claude_structured_output "$raw_out" "$raw_completion"
  local extract_rc=$?
  [[ -f "$raw_completion" ]] || : >"$raw_completion"

  local artifact_valid artifact_reason
  read -r artifact_valid artifact_reason < <(validate_implementer_artifact "$raw_completion" "$TASK_FILE" "$validated")

  if [[ "$status" == "TIMEOUT" ]]; then
    :
  elif [[ "$status" == "FAIL" ]]; then
    :
  elif [[ $extract_rc -ne 0 ]]; then
    status="FAIL"
    [[ $extract_rc -eq 4 ]] && reason="AMBIGUOUS_MULTIPLE_RESULT_ENVELOPES" || reason="STRUCTURED_OUTPUT_UNPARSEABLE"
  elif [[ "$artifact_valid" != "true" ]]; then
    status="FAIL"; reason="ARTIFACT_INVALID:${artifact_reason}"
  else
    status="PASS"; reason="OK"
  fi

  IMPLEMENTER_STATUS="$status"; IMPLEMENTER_REASON="$reason"
  IMPLEMENTER_ARTIFACT_VALID="$([[ "$artifact_valid" == "true" ]] && echo true || echo false)"

  redact_to_evidence "$raw_out" "$out_stdout" >/dev/null
  redact_to_evidence "$raw_err" "$out_stderr" >/dev/null
  redact_to_evidence "$validated" "$out_artifact" >/dev/null
}

reset_verifier_globals() {
  VERIFIER_STATUS="NOT_RUN"; VERIFIER_REASON="NOT_ATTEMPTED"; VERIFIER_VERDICT="NONE"
  VERIFIER_STARTED_AT=""; VERIFIER_COMPLETED_AT=""; VERIFIER_DURATION_MS=0
  VERIFIER_EXIT_CODE=""; VERIFIER_DEADLINE_FIRED=false; VERIFIER_ARTIFACT_VALID=false
  VERIFIER_STDOUT_REL=""; VERIFIER_STDERR_REL=""; VERIFIER_ARTIFACT_REL=""
}

# run_verifier <iteration> <task> <implementer_artifact_file> <iter_dir>
run_verifier() {
  local iteration="$1" task="$2" implementer_artifact_file="$3" iter_dir="$4"
  reset_verifier_globals
  local out_stdout="${iter_dir}/verifier.stdout.txt" out_stderr="${iter_dir}/verifier.stderr.txt"
  local out_artifact="${iter_dir}/verifier-verdict.json"
  VERIFIER_STDOUT_REL="iteration-${iteration}/verifier.stdout.txt"
  VERIFIER_STDERR_REL="iteration-${iteration}/verifier.stderr.txt"
  VERIFIER_ARTIFACT_REL="iteration-${iteration}/verifier-verdict.json"
  : >"$out_stdout"; : >"$out_stderr"

  if ! command -v "$VERIFIER_CLI" >/dev/null 2>&1; then
    VERIFIER_STATUS="BLOCKED"; VERIFIER_REASON="CLI_NOT_FOUND"
    printf '{"artifact_valid":false,"invalid_reason":"CLI_NOT_FOUND"}\n' >"$out_artifact"
    return
  fi

  local raw_out="${PKGB_TMP_ROOT}/raw/verif-${iteration}.stdout.txt"
  local raw_err="${PKGB_TMP_ROOT}/raw/verif-${iteration}.stderr.txt"
  local raw_final="${PKGB_TMP_ROOT}/raw/verif-${iteration}.final-message.txt"
  local validated="${PKGB_TMP_ROOT}/raw/verif-${iteration}.validated.json"
  local prompt rc fired pid

  prompt="$(build_verifier_prompt "$task" "$implementer_artifact_file")"

  VERIFIER_STARTED_AT="$(now_iso)"
  local t0 t1
  t0="$(now_ms)"
  read -r rc fired pid < <( cd "$TARGET_REPO" && PKGB_ITERATION="$iteration" run_bounded \
    "$VERIFIER_TIMEOUT_SECONDS" "$GRACE_SECONDS" "$raw_out" "$raw_err" \
    "$VERIFIER_CLI" exec --ephemeral --skip-git-repo-check --sandbox read-only \
      --output-last-message "$raw_final" "$prompt" )
  t1="$(now_ms)"
  VERIFIER_COMPLETED_AT="$(now_iso)"
  VERIFIER_DURATION_MS=$(( t1 - t0 ))
  VERIFIER_EXIT_CODE="$rc"; VERIFIER_DEADLINE_FIRED="$fired"

  local status reason
  read -r status reason _ < <(classify_process_result "$rc" "$fired")

  [[ -f "$raw_final" ]] || : >"$raw_final"
  local artifact_valid artifact_reason verdict
  read -r artifact_valid artifact_reason verdict < <(validate_verifier_artifact "$raw_final" "$validated")

  if [[ "$status" == "TIMEOUT" ]]; then
    :
  elif [[ "$status" == "FAIL" ]]; then
    :
  elif [[ "$artifact_valid" != "true" ]]; then
    status="FAIL"; reason="ARTIFACT_INVALID:${artifact_reason}"
  else
    status="$verdict"; reason="OK"
  fi

  VERIFIER_STATUS="$status"; VERIFIER_REASON="$reason"
  VERIFIER_VERDICT="${verdict:-NONE}"
  VERIFIER_ARTIFACT_VALID="$([[ "$artifact_valid" == "true" ]] && echo true || echo false)"

  redact_to_evidence "$raw_out" "$out_stdout" >/dev/null
  redact_to_evidence "$raw_err" "$out_stderr" >/dev/null
  redact_to_evidence "$validated" "$out_artifact" >/dev/null
}

# ---------- per-iteration evidence emission ----------

emit_iteration_implementer_fields() {
  local idx="$1" iteration="$2"
  kv_n "iterations.${idx}.number" "$iteration"
  kv_s "iterations.${idx}.implementer.cli" "$IMPLEMENTER_CLI"
  kv_s "iterations.${idx}.implementer.status" "$IMPLEMENTER_STATUS"
  kv_s "iterations.${idx}.implementer.reason" "$IMPLEMENTER_REASON"
  kv_s "iterations.${idx}.implementer.started_at" "$IMPLEMENTER_STARTED_AT"
  kv_s "iterations.${idx}.implementer.completed_at" "$IMPLEMENTER_COMPLETED_AT"
  kv_n "iterations.${idx}.implementer.duration_ms" "$IMPLEMENTER_DURATION_MS"
  if [[ -n "$IMPLEMENTER_EXIT_CODE" ]]; then kv_n "iterations.${idx}.implementer.exit_code" "$IMPLEMENTER_EXIT_CODE"; else kv_z "iterations.${idx}.implementer.exit_code"; fi
  kv_n "iterations.${idx}.implementer.timeout_seconds" "$IMPLEMENTER_TIMEOUT_SECONDS"
  kv_b "iterations.${idx}.implementer.deadline_fired" "$IMPLEMENTER_DEADLINE_FIRED"
  kv_b "iterations.${idx}.implementer.artifact_valid" "$IMPLEMENTER_ARTIFACT_VALID"
  kv_s "iterations.${idx}.implementer.stdout_artifact" "$IMPLEMENTER_STDOUT_REL"
  kv_s "iterations.${idx}.implementer.stderr_artifact" "$IMPLEMENTER_STDERR_REL"
  kv_s "iterations.${idx}.implementer.proposal_artifact" "$IMPLEMENTER_ARTIFACT_REL"
}

emit_iteration_verifier_fields() {
  local idx="$1"
  kv_s "iterations.${idx}.verifier.cli" "$VERIFIER_CLI"
  kv_s "iterations.${idx}.verifier.status" "$VERIFIER_STATUS"
  kv_s "iterations.${idx}.verifier.verdict" "$VERIFIER_VERDICT"
  kv_s "iterations.${idx}.verifier.reason" "$VERIFIER_REASON"
  kv_s "iterations.${idx}.verifier.started_at" "$VERIFIER_STARTED_AT"
  kv_s "iterations.${idx}.verifier.completed_at" "$VERIFIER_COMPLETED_AT"
  kv_n "iterations.${idx}.verifier.duration_ms" "$VERIFIER_DURATION_MS"
  if [[ -n "$VERIFIER_EXIT_CODE" ]]; then kv_n "iterations.${idx}.verifier.exit_code" "$VERIFIER_EXIT_CODE"; else kv_z "iterations.${idx}.verifier.exit_code"; fi
  kv_n "iterations.${idx}.verifier.timeout_seconds" "$VERIFIER_TIMEOUT_SECONDS"
  kv_b "iterations.${idx}.verifier.deadline_fired" "$VERIFIER_DEADLINE_FIRED"
  kv_b "iterations.${idx}.verifier.artifact_valid" "$VERIFIER_ARTIFACT_VALID"
  kv_s "iterations.${idx}.verifier.stdout_artifact" "$VERIFIER_STDOUT_REL"
  kv_s "iterations.${idx}.verifier.stderr_artifact" "$VERIFIER_STDERR_REL"
  kv_s "iterations.${idx}.verifier.verdict_artifact" "$VERIFIER_ARTIFACT_REL"
}

emit_iteration_verifier_not_run() {
  local idx="$1"
  kv_s "iterations.${idx}.verifier.cli" "$VERIFIER_CLI"
  kv_s "iterations.${idx}.verifier.status" "NOT_RUN"
  kv_s "iterations.${idx}.verifier.verdict" "NONE"
  kv_s "iterations.${idx}.verifier.reason" "IMPLEMENTER_ARTIFACT_NOT_VALID"
  kv_z "iterations.${idx}.verifier.started_at"
  kv_z "iterations.${idx}.verifier.completed_at"
  kv_n "iterations.${idx}.verifier.duration_ms" 0
  kv_z "iterations.${idx}.verifier.exit_code"
  kv_z "iterations.${idx}.verifier.stdout_artifact"
  kv_z "iterations.${idx}.verifier.stderr_artifact"
  kv_z "iterations.${idx}.verifier.verdict_artifact"
}

# ---------- finalization ----------

# finalize_and_exit: captures the after-snapshot, decides mutation fail-close,
# renders + atomically publishes canonical evidence.json, prints the summary
# and terminates the process. Called from every terminal path in main().
finalize_and_exit() {
  capture_target_snapshot "$TARGET_REPO" AFTER
  compute_target_mutation

  if [[ "$MUTATION_DETECTED" == true ]]; then
    harness_error "target repository mutation detected: ${MUTATION_REASONS[*]}"
    HARNESS_STATUS="ERROR"
    FINAL_STATUS="ERROR"
  fi

  [[ "$HARNESS_ERRORS" -eq 0 ]] || HARNESS_STATUS="ERROR"

  local run_completed_at total_ms
  run_completed_at="$(now_iso)"
  total_ms=$(( $(now_ms) - RUN_T0 ))

  kv_s "schema_version" "$SCHEMA_VERSION"
  kv_s "package" "$PACKAGE"
  kv_s "run_id" "$RUN_ID"
  kv_s "started_at" "$RUN_STARTED_AT"
  kv_s "completed_at" "$run_completed_at"
  kv_n "total_duration_ms" "$total_ms"
  kv_s "host.repo_root" "$REPO_ROOT"
  kv_s "task" "$TASK"
  kv_s "task_artifact" "task.txt"
  kv_n "max_iterations" "$MAX_ITERATIONS"
  kv_n "iterations_used" "${ITERATIONS_USED:-0}"

  emit_snapshot_fields
  emit_gate_fields

  local scan_findings
  scan_findings="$(scan_secrets "$EVIDENCE_DIR")"
  [[ "$scan_findings" =~ ^[0-9]+$ ]] || scan_findings=0
  [[ "$scan_findings" -eq 0 ]] || HARNESS_STATUS="ERROR"

  kv_s "harness_status" "$HARNESS_STATUS"
  kv_s "capability_status" "$CAPABILITY_STATUS"
  kv_s "implementer_status" "$IMPLEMENTER_STATUS"
  kv_s "verifier_status" "$VERIFIER_STATUS"
  kv_s "final_status" "$FINAL_STATUS"
  kv_n "secret_scan.findings" "$scan_findings"
  kv_n "secret_scan.patterns_checked" "${#SECRET_PATTERNS[@]}"
  kv_s "secret_scan.artifact" "secret-scan.txt"
  kv_n "harness_internal_errors" "$HARNESS_ERRORS"

  local process_exit_code
  process_exit_code="$(compute_process_exit_code "$HARNESS_STATUS" "$FINAL_STATUS")"
  kv_n "process_exit_code" "$process_exit_code"

  local tmp_json="${EVIDENCE_DIR}/.evidence.json.tmp" render_log published=true
  render_log="$(render_evidence "$FIELDS_FILE" "$tmp_json" 2>&1)"
  if [[ $? -ne 0 || ! -s "$tmp_json" ]]; then
    harness_error "evidence serialization failed: ${render_log}"
    HARNESS_STATUS="ERROR"
    process_exit_code="$(compute_process_exit_code "$HARNESS_STATUS" "$FINAL_STATUS")"
    rm -f "$tmp_json" "$FIELDS_FILE"
    published="$(publish_fallback_evidence "EVIDENCE_SERIALIZATION_FAILED" "$process_exit_code" && echo true || echo false)"
  else
    rm -f "$FIELDS_FILE"
    if ! publish_evidence_atomic "$tmp_json" "$EVIDENCE_JSON"; then
      HARNESS_STATUS="ERROR"
      process_exit_code="$(compute_process_exit_code "$HARNESS_STATUS" "$FINAL_STATUS")"
      published="$(publish_fallback_evidence "EVIDENCE_PUBLISH_RENAME_FAILED" "$process_exit_code" && echo true || echo false)"
    fi
  fi

  echo "RUN_ID=${RUN_ID}"
  echo "HARNESS_STATUS=${HARNESS_STATUS}"
  echo "CAPABILITY_STATUS=${CAPABILITY_STATUS}"
  echo "IMPLEMENTER_STATUS=${IMPLEMENTER_STATUS}"
  echo "VERIFIER_STATUS=${VERIFIER_STATUS}"
  echo "FINAL_STATUS=${FINAL_STATUS}"
  echo "ITERATIONS_USED=${ITERATIONS_USED:-0}"
  echo "MAX_ITERATIONS=${MAX_ITERATIONS}"
  echo "TARGET_MUTATION_DETECTED=${MUTATION_DETECTED}"
  echo "PROCESS_EXIT_CODE=${process_exit_code}"
  if [[ "$published" == true ]]; then
    echo "EVIDENCE_JSON=${EVIDENCE_JSON}"
  else
    echo "EVIDENCE_JSON=none"
  fi

  exit "$process_exit_code"
}

# ---------- main ----------

usage() {
  cat <<'USAGE_EOF'
Usage: scripts/package-b.sh --task "text"
       scripts/package-b.sh --self-test
USAGE_EOF
}

main() {
  local task=""
  local self_test=false

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --task) task="${2:-}"; shift 2 ;;
      --self-test) self_test=true; shift ;;
      -h|--help) usage; exit 0 ;;
      *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
  done

  if [[ "$self_test" == true ]]; then
    run_self_test
    exit $?
  fi

  RUN_ID="pkgB-$(date -u +%Y%m%dT%H%M%SZ)-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"

  if [[ -z "${task//[[:space:]]/}" ]]; then
    echo "RUN_ID=${RUN_ID}"
    echo "HARNESS_STATUS=ERROR"
    echo "FINAL_STATUS=NOT_RUN"
    echo "REASON=EMPTY_TASK"
    echo "PROCESS_EXIT_CODE=2"
    echo "EVIDENCE_JSON=none"
    return 2
  fi
  TASK="$task"

  PKGB_TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/package-b-run.XXXXXX")"
  mkdir -p "${PKGB_TMP_ROOT}/raw"
  trap 'rm -rf -- "$PKGB_TMP_ROOT" 2>/dev/null || true' EXIT

  local evidence_root evidence_dir
  evidence_root="$(realpath -m "${REPO_ROOT}/evidence/package-b")"
  evidence_dir="$(realpath -m "${evidence_root}/${RUN_ID}")"
  case "$evidence_dir" in
    "${evidence_root}"/*) : ;;
    *)
      echo "RUN_ID=${RUN_ID}"
      echo "HARNESS_STATUS=ERROR"
      echo "FINAL_STATUS=NOT_RUN"
      echo "REASON=EVIDENCE_CONTAINMENT_REJECTED"
      echo "PROCESS_EXIT_CODE=2"
      echo "EVIDENCE_JSON=none"
      return 2 ;;
  esac
  if ! mkdir -p "$evidence_dir"; then
    echo "RUN_ID=${RUN_ID}"
    echo "HARNESS_STATUS=ERROR"
    echo "FINAL_STATUS=NOT_RUN"
    echo "REASON=EVIDENCE_DIR_CREATE_FAILED"
    echo "PROCESS_EXIT_CODE=2"
    echo "EVIDENCE_JSON=none"
    return 2
  fi
  EVIDENCE_DIR="$evidence_dir"
  EVIDENCE_JSON="${EVIDENCE_DIR}/evidence.json"
  FIELDS_FILE="${EVIDENCE_DIR}/.fields.kv"
  : >"$FIELDS_FILE"
  TASK_FILE="${EVIDENCE_DIR}/task.txt"
  printf '%s' "$TASK" >"$TASK_FILE"

  TARGET_REPO="${LOOP_PACKAGE_B_TARGET_REPO:-$REPO_ROOT}"

  RUN_STARTED_AT="$(now_iso)"
  RUN_T0="$(now_ms)"

  HARNESS_STATUS="PASS"
  CAPABILITY_STATUS="NOT_RUN"
  IMPLEMENTER_STATUS="NOT_RUN"
  VERIFIER_STATUS="NOT_RUN"
  FINAL_STATUS="ERROR"
  ITERATIONS_USED=0
  kv_arr "iterations"

  capture_target_snapshot "$TARGET_REPO" BEFORE

  run_package_a_gate

  if [[ "$GATE_HARNESS_STATUS" != "PASS" ]]; then
    HARNESS_STATUS="ERROR"
    CAPABILITY_STATUS="${GATE_CAPABILITY_STATUS:-NOT_RUN}"
    FINAL_STATUS="ERROR"
    harness_error "Package A gate harness_status=${GATE_HARNESS_STATUS}"
    finalize_and_exit
  fi

  CAPABILITY_STATUS="$GATE_CAPABILITY_STATUS"
  if [[ "$CAPABILITY_STATUS" != "PASS" ]]; then
    FINAL_STATUS="BLOCKED"
    finalize_and_exit
  fi

  local iteration=1 prev_iter_dir=""
  while (( iteration <= MAX_ITERATIONS )); do
    local iter_dir="${EVIDENCE_DIR}/iteration-${iteration}"
    mkdir -p "$iter_dir"
    local idx=$(( iteration - 1 ))
    local prior_file="" findings_file=""
    if (( iteration == 2 )); then
      prior_file="${prev_iter_dir}/implementer-proposal.json"
      findings_file="${prev_iter_dir}/verifier-verdict.json"
    fi

    run_implementer "$iteration" "$TASK" "$prior_file" "$findings_file" "$iter_dir"
    emit_iteration_implementer_fields "$idx" "$iteration"

    if [[ "$IMPLEMENTER_STATUS" != "PASS" ]]; then
      emit_iteration_verifier_not_run "$idx"
      ITERATIONS_USED="$iteration"
      break
    fi

    run_verifier "$iteration" "$TASK" "${iter_dir}/implementer-proposal.json" "$iter_dir"
    emit_iteration_verifier_fields "$idx"
    ITERATIONS_USED="$iteration"

    if [[ "$VERIFIER_STATUS" == "PASS" ]]; then
      break
    fi
    if [[ "$VERIFIER_STATUS" == "FAIL" && "$iteration" -lt "$MAX_ITERATIONS" ]]; then
      prev_iter_dir="$iter_dir"
      iteration=$(( iteration + 1 ))
      continue
    fi
    break
  done

  if [[ "$IMPLEMENTER_STATUS" == "BLOCKED" ]]; then FINAL_STATUS="BLOCKED"
  elif [[ "$IMPLEMENTER_STATUS" == "TIMEOUT" ]]; then FINAL_STATUS="TIMEOUT"
  elif [[ "$IMPLEMENTER_STATUS" == "ERROR" ]]; then FINAL_STATUS="ERROR"
  elif [[ "$IMPLEMENTER_STATUS" == "FAIL" ]]; then FINAL_STATUS="FAIL"
  elif [[ "$VERIFIER_STATUS" == "PASS" ]]; then FINAL_STATUS="PASS"
  elif [[ "$VERIFIER_STATUS" == "FAIL" ]]; then FINAL_STATUS="FAIL"
  elif [[ "$VERIFIER_STATUS" == "BLOCKED" ]]; then FINAL_STATUS="BLOCKED"
  elif [[ "$VERIFIER_STATUS" == "TIMEOUT" ]]; then FINAL_STATUS="TIMEOUT"
  else FINAL_STATUS="ERROR"
  fi

  finalize_and_exit
}

# ==================================================
# Self-test / fault-injection suite (no network, no real credentials)
# ==================================================

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

node_json_valid() {
  node -e "JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))" "$1" >/dev/null 2>&1
}

node_json_field() {
  node -e "
const d = JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));
const v = process.argv[2].split('.').reduce((o,k)=> (o==null?undefined:o[k]), d);
process.stdout.write(typeof v === 'string' ? v : JSON.stringify(v));
" "$1" "$2" 2>/dev/null
}

self_test_write_fakes() {
  local bindir="$1"
  cat >"${bindir}/claude" <<'FAKE_CLAUDE_EOF'
#!/bin/bash
if [[ "${1:-}" == "--version" ]]; then printf 'claude 0.0.0 (fake)\n'; exit 0; fi
mode="${FAKE_CLAUDE_MODE:-pass}"
task="${FAKE_TASK:-}"
# Mirrors a genuine `claude --output-format json --json-schema ...` success
# envelope: both the free-text `result` string AND the natively
# schema-validated `structured_output` object are present.
emit_envelope_from_obj() {
  node -e '
    const obj = JSON.parse(process.argv[1]);
    process.stdout.write(JSON.stringify({type:"result",subtype:"success",is_error:false,result:JSON.stringify(obj),structured_output:obj}) + "\n");
  ' "$1"
}
# Mirrors a genuine envelope that never produced structured output at all
# (e.g. `--json-schema` was not honored) - `result` only, no
# `structured_output` key. Used to prove such envelopes can never PASS.
emit_envelope_result_only() {
  node -e '
    process.stdout.write(JSON.stringify({type:"result",subtype:"success",is_error:false,result:process.argv[1]}) + "\n");
  ' "$1"
}
valid_proposal_json() {
  node -e '
    const [t] = process.argv.slice(1);
    process.stdout.write(JSON.stringify({
      schema_version: "1.0.0",
      role: "implementer",
      task: t,
      proposal: [{title:"Test gap A", rationale:"fake"}, {title:"Test gap B", rationale:"fake"}],
      completion_signal: "IMPLEMENTER_COMPLETE"
    }));
  ' "$1"
}
case "$mode" in
  pass)
    emit_envelope_from_obj "$(valid_proposal_json "$task")"; exit 0 ;;
  malformed_json)
    emit_envelope_result_only "this is not json for the proposal schema"; exit 0 ;;
  result_only_perfect_json)
    # (B) `result` is a perfect, schema-conforming JSON string, but
    # structured_output is absent - must still FAIL, `result` is never read.
    emit_envelope_result_only "$(valid_proposal_json "$task")"; exit 0 ;;
  fenced_prose)
    # (C) `result` contains prose plus a fenced JSON block (exactly what the
    # real Claude CLI produced before this fix); structured_output absent -
    # must still FAIL, no fence-stripping/prose-scanning fallback exists.
    body="$(node -e 'const [t]=process.argv.slice(1); const obj=JSON.parse(t); process.stdout.write("Here is my answer.\n\n```json\n"+JSON.stringify(obj)+"\n```")' "$(valid_proposal_json "$task")")"
    emit_envelope_result_only "$body"; exit 0 ;;
  wrong_signal)
    # (D) structured_output IS present (native schema output), but fails our
    # independent semantic check (completion_signal mismatch) - must FAIL.
    p="$(node -e 'const [t]=process.argv.slice(1); process.stdout.write(JSON.stringify({schema_version:"1.0.0",role:"implementer",task:t,proposal:[{title:"x",rationale:"y"}],completion_signal:"NOPE"}));' "$task")"
    emit_envelope_from_obj "$p"; exit 0 ;;
  multiple_envelopes)
    # (E) two genuine, well-formed envelopes on stdout - ambiguous, must FAIL.
    emit_envelope_from_obj "$(valid_proposal_json "$task")"
    emit_envelope_from_obj "$(valid_proposal_json "$task")"
    exit 0 ;;
  nonzero)
    emit_envelope_from_obj "$(valid_proposal_json "$task")"; exit 1 ;;
  hang)
    sleep 300 ;;
  mutate_tracked)
    if [[ -f ./tracked.txt ]]; then printf 'MUTATED BY FAKE IMPLEMENTER\n' >> ./tracked.txt; fi
    emit_envelope_from_obj "$(valid_proposal_json "$task")"; exit 0 ;;
  add_untracked)
    printf 'unexpected file\n' > ./unexpected-untracked-file.txt
    emit_envelope_from_obj "$(valid_proposal_json "$task")"; exit 0 ;;
  delete_tracked)
    rm -f ./tracked.txt
    emit_envelope_from_obj "$(valid_proposal_json "$task")"; exit 0 ;;
  secret_fixture)
    echo "warning: token=ghp_FAKEFIXTURE1234567890ABCDEF leaked in diagnostic" >&2
    emit_envelope_from_obj "$(valid_proposal_json "$task")"; exit 0 ;;
  *) emit_envelope_from_obj "$(valid_proposal_json "$task")"; exit 0 ;;
esac
FAKE_CLAUDE_EOF
  cat >"${bindir}/codex" <<'FAKE_CODEX_EOF'
#!/bin/bash
if [[ "${1:-}" == "--version" ]]; then printf 'codex-cli 0.0.0 (fake)\n'; exit 0; fi
mode="${FAKE_CODEX_MODE:-pass}"
iter="${PKGB_ITERATION:-1}"
final_file=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    -o|--output-last-message) final_file="${args[$((i + 1))]}" ;;
  esac
done
emit_final() { [[ -n "$final_file" ]] && printf '%s' "$1" > "$final_file"; }
verdict_json() {
  node -e '
    const [v] = process.argv.slice(1);
    process.stdout.write(JSON.stringify({
      schema_version:"1.0.0", role:"verifier", verdict:v,
      findings:["fake finding"], reason:("fake reason for " + v),
      completion_signal:"VERIFIER_COMPLETE"
    }));
  ' "$1"
}
case "$mode" in
  pass) emit_final "$(verdict_json PASS)"; exit 0 ;;
  fail) emit_final "$(verdict_json FAIL)"; exit 0 ;;
  fail_then_pass)
    if [[ "$iter" == "1" ]]; then emit_final "$(verdict_json FAIL)"; else emit_final "$(verdict_json PASS)"; fi
    exit 0 ;;
  blocked) emit_final "$(verdict_json BLOCKED)"; exit 0 ;;
  malformed) emit_final 'not valid json at all'; exit 0 ;;
  malformed_verdict)
    p="$(node -e 'process.stdout.write(JSON.stringify({schema_version:"1.0.0",role:"verifier",verdict:"PASS",findings:[],reason:"x",completion_signal:"WRONG"}))')"
    emit_final "$p"; exit 0 ;;
  hang) sleep 300 ;;
  secret_fixture)
    echo "warning: token=ghp_FAKEFIXTURE1234567890ABCDEF leaked in diagnostic" >&2
    emit_final "$(verdict_json PASS)"; exit 0 ;;
  *) emit_final "$(verdict_json PASS)"; exit 0 ;;
esac
FAKE_CODEX_EOF
  chmod +x "${bindir}/claude" "${bindir}/codex"
}

self_test_write_fake_pkga() {
  local path="$1"
  cat >"$path" <<'FAKE_PKGA_EOF'
#!/bin/bash
mode="${FAKE_PKGA_MODE:-pass}"
run_id="fake-pkga-$$"
case "$mode" in
  pass)
    echo "RUN_ID=${run_id}"
    echo "HARNESS_STATUS=PASS"
    echo "CAPABILITY_STATUS=PASS"
    echo "EVIDENCE_JSON=${FAKE_PKGA_EVIDENCE_JSON:-/nonexistent/evidence.json}"
    exit 0 ;;
  capfail)
    echo "RUN_ID=${run_id}"
    echo "HARNESS_STATUS=PASS"
    echo "CAPABILITY_STATUS=FAIL"
    echo "EVIDENCE_JSON=${FAKE_PKGA_EVIDENCE_JSON:-/nonexistent/evidence.json}"
    exit 1 ;;
  harnesserror)
    echo "RUN_ID=${run_id}"
    echo "HARNESS_STATUS=ERROR"
    echo "CAPABILITY_STATUS=NOT_RUN"
    echo "EVIDENCE_JSON=none"
    exit 2 ;;
  *)
    echo "RUN_ID=${run_id}"
    echo "HARNESS_STATUS=PASS"
    echo "CAPABILITY_STATUS=PASS"
    echo "EVIDENCE_JSON=none"
    exit 0 ;;
esac
FAKE_PKGA_EOF
  chmod +x "$path"
}

make_fixture_repo() {
  local dir="$1"
  rm -rf "$dir"
  mkdir -p "$dir"
  git -C "$dir" init -q
  git -C "$dir" config user.email "package-b-self-test@example.com"
  git -C "$dir" config user.name "Package B Self Test"
  printf 'tracked file for package-b self-test\n' > "${dir}/tracked.txt"
  git -C "$dir" add tracked.txt
  git -C "$dir" commit -q -m "init"
}

PB_STDOUT=""
PB_RC=0

PB_BASE_ENV=()
self_test_base_env() {
  PB_BASE_ENV=(
    "PATH=${FAKE_BIN}:/usr/bin:/bin"
    "LOOP_PACKAGE_B_PACKAGE_A_SCRIPT=${FAKE_PKGA}"
    "LOOP_PACKAGE_B_IMPLEMENTER_TIMEOUT_SECONDS=3"
    "LOOP_PACKAGE_B_VERIFIER_TIMEOUT_SECONDS=3"
    "LOOP_PACKAGE_B_GRACE_SECONDS=1"
    "LOOP_PACKAGE_B_GATE_TIMEOUT_SECONDS=10"
    "FAKE_PKGA_MODE=pass"
    "FAKE_CLAUDE_MODE=pass"
    "FAKE_CODEX_MODE=pass"
    "FAKE_TASK=${ST_TASK}"
  )
}

run_pkgb() {
  local -a envs=("$@")
  PB_STDOUT="$(env "${envs[@]}" bash "$SELF_PATH" --task "$ST_TASK" 2>"${SELFTEST_TMP}/last.stderr.txt")"
  PB_RC=$?
}

pb_field() {
  printf '%s\n' "$PB_STDOUT" | grep -m1 -oE "^${1}=.*" | cut -d= -f2-
}

run_self_test() {
  echo "=== Package B self-test / fault-injection suite ==="

  echo "--- bash syntax ---"
  local syntax_err="/tmp/package-b-selftest-syntax.$$.err"
  if bash -n "$SELF_PATH" 2>"$syntax_err"; then
    st_assert "bash syntax valid" true
  else
    st_assert "bash syntax valid ($(cat "$syntax_err"))" false
  fi
  rm -f "$syntax_err"

  SELFTEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/package-b-selftest.XXXXXX")"
  FAKE_BIN="${SELFTEST_TMP}/bin"
  mkdir -p "$FAKE_BIN"
  self_test_write_fakes "$FAKE_BIN"
  FAKE_PKGA="${SELFTEST_TMP}/fake-package-a.sh"
  self_test_write_fake_pkga "$FAKE_PKGA"
  ST_TASK="Inspect this repository and propose the three highest-value test gaps. Do not modify files."

  echo "--- scenario 1: implementer PASS + verifier PASS -> final PASS / exit 0 ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}"
  st_assert_eq "scenario1 process exit code" "0" "$PB_RC"
  st_assert_eq "scenario1 FINAL_STATUS" "PASS" "$(pb_field FINAL_STATUS)"
  st_assert_eq "scenario1 HARNESS_STATUS" "PASS" "$(pb_field HARNESS_STATUS)"
  st_assert_eq "scenario1 ITERATIONS_USED" "1" "$(pb_field ITERATIONS_USED)"
  local ej1; ej1="$(pb_field EVIDENCE_JSON)"
  st_assert "scenario1 evidence.json parses" "$(node_json_valid "$ej1" && echo true || echo false)"
  st_assert_eq "scenario1 process exit matches persisted field" "$PB_RC" "$(node_json_field "$ej1" process_exit_code)"

  echo "--- scenario 2: implementer valid + verifier FAIL then PASS -> final PASS ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CODEX_MODE=fail_then_pass"
  st_assert_eq "scenario2 process exit code" "0" "$PB_RC"
  st_assert_eq "scenario2 FINAL_STATUS" "PASS" "$(pb_field FINAL_STATUS)"
  st_assert_eq "scenario2 ITERATIONS_USED" "2" "$(pb_field ITERATIONS_USED)"

  echo "--- scenario 3: verifier FAIL twice -> final FAIL / exit 1 ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CODEX_MODE=fail"
  st_assert_eq "scenario3 process exit code" "1" "$PB_RC"
  st_assert_eq "scenario3 FINAL_STATUS" "FAIL" "$(pb_field FINAL_STATUS)"
  st_assert_eq "scenario3 ITERATIONS_USED" "2" "$(pb_field ITERATIONS_USED)"

  echo "--- scenario 4: implementer CLI missing -> BLOCKED, verifier NOT_RUN ---"
  run_pkgb "PATH=/usr/bin:/bin" "LOOP_PACKAGE_B_PACKAGE_A_SCRIPT=${FAKE_PKGA}" \
    "LOOP_PACKAGE_B_IMPLEMENTER_TIMEOUT_SECONDS=3" "LOOP_PACKAGE_B_VERIFIER_TIMEOUT_SECONDS=3" \
    "LOOP_PACKAGE_B_GRACE_SECONDS=1" "LOOP_PACKAGE_B_GATE_TIMEOUT_SECONDS=10" "FAKE_PKGA_MODE=pass"
  st_assert_eq "scenario4 IMPLEMENTER_STATUS" "BLOCKED" "$(pb_field IMPLEMENTER_STATUS)"
  st_assert_eq "scenario4 VERIFIER_STATUS" "NOT_RUN" "$(pb_field VERIFIER_STATUS)"
  st_assert_eq "scenario4 FINAL_STATUS" "BLOCKED" "$(pb_field FINAL_STATUS)"
  st_assert_eq "scenario4 process exit code" "1" "$PB_RC"

  echo "--- scenario 5: verifier CLI missing -> BLOCKED ---"
  local bin5="${SELFTEST_TMP}/bin5"; mkdir -p "$bin5"
  cp "${FAKE_BIN}/claude" "$bin5/"
  run_pkgb "PATH=${bin5}:/usr/bin:/bin" "LOOP_PACKAGE_B_PACKAGE_A_SCRIPT=${FAKE_PKGA}" \
    "LOOP_PACKAGE_B_IMPLEMENTER_TIMEOUT_SECONDS=3" "LOOP_PACKAGE_B_VERIFIER_TIMEOUT_SECONDS=3" \
    "LOOP_PACKAGE_B_GRACE_SECONDS=1" "LOOP_PACKAGE_B_GATE_TIMEOUT_SECONDS=10" "FAKE_PKGA_MODE=pass" \
    "FAKE_CLAUDE_MODE=pass" "FAKE_TASK=${ST_TASK}"
  st_assert_eq "scenario5 IMPLEMENTER_STATUS" "PASS" "$(pb_field IMPLEMENTER_STATUS)"
  st_assert_eq "scenario5 VERIFIER_STATUS" "BLOCKED" "$(pb_field VERIFIER_STATUS)"
  st_assert_eq "scenario5 FINAL_STATUS" "BLOCKED" "$(pb_field FINAL_STATUS)"

  echo "--- scenario 6: implementer timeout -> TIMEOUT with provenance ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CLAUDE_MODE=hang"
  st_assert_eq "scenario6 IMPLEMENTER_STATUS" "TIMEOUT" "$(pb_field IMPLEMENTER_STATUS)"
  st_assert_eq "scenario6 FINAL_STATUS" "TIMEOUT" "$(pb_field FINAL_STATUS)"
  ej="$(pb_field EVIDENCE_JSON)"
  st_assert_eq "scenario6 deadline_fired provenance" "true" "$(node_json_field "$ej" iterations.0.implementer.deadline_fired)"

  echo "--- scenario 7: verifier timeout -> TIMEOUT with provenance ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CODEX_MODE=hang"
  st_assert_eq "scenario7 VERIFIER_STATUS" "TIMEOUT" "$(pb_field VERIFIER_STATUS)"
  st_assert_eq "scenario7 FINAL_STATUS" "TIMEOUT" "$(pb_field FINAL_STATUS)"
  ej="$(pb_field EVIDENCE_JSON)"
  st_assert_eq "scenario7 deadline_fired provenance" "true" "$(node_json_field "$ej" iterations.0.verifier.deadline_fired)"

  echo "--- scenario 8: malformed implementer artifact cannot PASS ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CLAUDE_MODE=malformed_json"
  st_assert "scenario8 IMPLEMENTER_STATUS is not PASS" "$([[ "$(pb_field IMPLEMENTER_STATUS)" != "PASS" ]] && echo true || echo false)"
  st_assert "scenario8 FINAL_STATUS is not PASS" "$([[ "$(pb_field FINAL_STATUS)" != "PASS" ]] && echo true || echo false)"

  echo "--- scenario 9: malformed verifier artifact cannot PASS ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CODEX_MODE=malformed_verdict"
  st_assert "scenario9 VERIFIER_STATUS is not PASS" "$([[ "$(pb_field VERIFIER_STATUS)" != "PASS" ]] && echo true || echo false)"
  st_assert "scenario9 FINAL_STATUS is not PASS" "$([[ "$(pb_field FINAL_STATUS)" != "PASS" ]] && echo true || echo false)"

  echo "--- scenario 10: verifier cannot run before a valid implementer artifact ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CLAUDE_MODE=wrong_signal"
  st_assert_eq "scenario10 VERIFIER_STATUS" "NOT_RUN" "$(pb_field VERIFIER_STATUS)"

  local fixture="${SELFTEST_TMP}/fixture-repo"

  echo "--- scenario 11: tracked target mutation -> final ERROR/fail-closed ---"
  make_fixture_repo "$fixture"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CLAUDE_MODE=mutate_tracked" "LOOP_PACKAGE_B_TARGET_REPO=${fixture}"
  st_assert_eq "scenario11 TARGET_MUTATION_DETECTED" "true" "$(pb_field TARGET_MUTATION_DETECTED)"
  st_assert_eq "scenario11 HARNESS_STATUS" "ERROR" "$(pb_field HARNESS_STATUS)"
  st_assert_eq "scenario11 FINAL_STATUS" "ERROR" "$(pb_field FINAL_STATUS)"
  st_assert_eq "scenario11 process exit code" "2" "$PB_RC"

  echo "--- scenario 12: untracked target mutation outside evidence -> fail-closed ---"
  make_fixture_repo "$fixture"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CLAUDE_MODE=add_untracked" "LOOP_PACKAGE_B_TARGET_REPO=${fixture}"
  st_assert_eq "scenario12 TARGET_MUTATION_DETECTED" "true" "$(pb_field TARGET_MUTATION_DETECTED)"
  st_assert_eq "scenario12 FINAL_STATUS" "ERROR" "$(pb_field FINAL_STATUS)"

  echo "--- scenario 13: deleted tracked file detected ---"
  make_fixture_repo "$fixture"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CLAUDE_MODE=delete_tracked" "LOOP_PACKAGE_B_TARGET_REPO=${fixture}"
  st_assert_eq "scenario13 TARGET_MUTATION_DETECTED" "true" "$(pb_field TARGET_MUTATION_DETECTED)"
  st_assert_eq "scenario13 FINAL_STATUS" "ERROR" "$(pb_field FINAL_STATUS)"

  echo "--- scenario 14: allowed evidence mutations do not false-positive ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}"
  st_assert_eq "scenario14 TARGET_MUTATION_DETECTED (real repo, evidence-only writes)" "false" "$(pb_field TARGET_MUTATION_DETECTED)"
  st_assert_eq "scenario14 FINAL_STATUS" "PASS" "$(pb_field FINAL_STATUS)"

  echo "--- scenario 15/16: max iterations enforced, no third iteration ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CODEX_MODE=fail"
  st_assert_eq "scenario15 ITERATIONS_USED" "2" "$(pb_field ITERATIONS_USED)"
  st_assert_eq "scenario15 MAX_ITERATIONS" "2" "$(pb_field MAX_ITERATIONS)"
  ej="$(pb_field EVIDENCE_JSON)"
  local ev_dir; ev_dir="$(dirname "$ej")"
  st_assert "scenario16 no iteration-3 directory exists" "$([[ ! -d "${ev_dir}/iteration-3" ]] && echo true || echo false)"

  echo "--- scenario 17: final process exit persisted matches actual exit ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}"
  ej="$(pb_field EVIDENCE_JSON)"
  st_assert_eq "scenario17 persisted exit matches actual" "$PB_RC" "$(node_json_field "$ej" process_exit_code)"

  echo "--- scenario 18: canonical JSON publication is atomic ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}"
  ej="$(pb_field EVIDENCE_JSON)"
  ev_dir="$(dirname "$ej")"
  st_assert "scenario18 no stray tmp evidence file left behind" "$([[ ! -e "${ev_dir}/.evidence.json.tmp" ]] && echo true || echo false)"
  st_assert "scenario18 evidence.json parses" "$(node_json_valid "$ej" && echo true || echo false)"

  echo "--- scenario 19: secret-like fixture is redacted, not persisted ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CODEX_MODE=secret_fixture"
  ej="$(pb_field EVIDENCE_JSON)"
  ev_dir="$(dirname "$ej")"
  st_assert "scenario19 raw secret absent from evidence.json" "$(grep -q 'ghp_FAKEFIXTURE1234567890ABCDEF' "$ej" && echo false || echo true)"
  st_assert "scenario19 redacted marker present in verifier stderr" "$(grep -q '\[REDACTED_TOKEN\]' "${ev_dir}/iteration-1/verifier.stderr.txt" 2>/dev/null && echo true || echo false)"

  echo "--- scenario 20: special characters / newlines / UTF-8 task serializes correctly ---"
  local prev_task="$ST_TASK"
  ST_TASK=$'Inspect "this" repo\nline two: back\\slash and emoji caf\xc3\xa9 \xf0\x9f\x9a\x80. Do not modify files.'
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}"
  ej="$(pb_field EVIDENCE_JSON)"
  st_assert "scenario20 evidence.json parses with special-char task" "$(node_json_valid "$ej" && echo true || echo false)"
  st_assert_eq "scenario20 task field round-trips exactly" "$ST_TASK" "$(node_json_field "$ej" task)"
  ST_TASK="$prev_task"

  echo "--- scenario 21: Package A gate CAPABILITY FAIL -> BLOCKED, agents NOT_RUN ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_PKGA_MODE=capfail"
  st_assert_eq "scenario21 CAPABILITY_STATUS" "FAIL" "$(pb_field CAPABILITY_STATUS)"
  st_assert_eq "scenario21 IMPLEMENTER_STATUS" "NOT_RUN" "$(pb_field IMPLEMENTER_STATUS)"
  st_assert_eq "scenario21 FINAL_STATUS" "BLOCKED" "$(pb_field FINAL_STATUS)"
  st_assert_eq "scenario21 process exit code" "1" "$PB_RC"

  echo "--- scenario 22: Package A gate HARNESS ERROR -> Package B ERROR ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_PKGA_MODE=harnesserror"
  st_assert_eq "scenario22 HARNESS_STATUS" "ERROR" "$(pb_field HARNESS_STATUS)"
  st_assert_eq "scenario22 FINAL_STATUS" "ERROR" "$(pb_field FINAL_STATUS)"
  st_assert_eq "scenario22 process exit code" "2" "$PB_RC"

  echo "--- scenario A: native structured_output present + valid -> implementer PASS ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}"
  ej="$(pb_field EVIDENCE_JSON)"
  st_assert_eq "scenarioA IMPLEMENTER_STATUS" "PASS" "$(pb_field IMPLEMENTER_STATUS)"
  st_assert_eq "scenarioA structured_output validity persisted" "true" "$(node_json_field "$ej" iterations.0.implementer.artifact_valid)"
  st_assert_eq "scenarioA FINAL_STATUS" "PASS" "$(pb_field FINAL_STATUS)"

  echo "--- scenario B: result is perfect JSON but structured_output absent -> FAIL ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CLAUDE_MODE=result_only_perfect_json"
  st_assert "scenarioB IMPLEMENTER_STATUS is not PASS" "$([[ "$(pb_field IMPLEMENTER_STATUS)" != "PASS" ]] && echo true || echo false)"
  st_assert_eq "scenarioB VERIFIER_STATUS" "NOT_RUN" "$(pb_field VERIFIER_STATUS)"
  st_assert_eq "scenarioB FINAL_STATUS" "FAIL" "$(pb_field FINAL_STATUS)"

  echo "--- scenario C: result is fenced/prose JSON, structured_output absent -> FAIL ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CLAUDE_MODE=fenced_prose"
  st_assert "scenarioC IMPLEMENTER_STATUS is not PASS" "$([[ "$(pb_field IMPLEMENTER_STATUS)" != "PASS" ]] && echo true || echo false)"
  st_assert_eq "scenarioC VERIFIER_STATUS" "NOT_RUN" "$(pb_field VERIFIER_STATUS)"
  st_assert_eq "scenarioC FINAL_STATUS" "FAIL" "$(pb_field FINAL_STATUS)"

  echo "--- scenario D: structured_output present but semantically malformed -> FAIL ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CLAUDE_MODE=wrong_signal"
  st_assert "scenarioD IMPLEMENTER_STATUS is not PASS" "$([[ "$(pb_field IMPLEMENTER_STATUS)" != "PASS" ]] && echo true || echo false)"
  st_assert_eq "scenarioD VERIFIER_STATUS" "NOT_RUN" "$(pb_field VERIFIER_STATUS)"

  echo "--- scenario E: multiple genuine outer envelopes cannot PASS ---"
  self_test_base_env; run_pkgb "${PB_BASE_ENV[@]}" "FAKE_CLAUDE_MODE=multiple_envelopes"
  st_assert "scenarioE IMPLEMENTER_STATUS is not PASS" "$([[ "$(pb_field IMPLEMENTER_STATUS)" != "PASS" ]] && echo true || echo false)"
  st_assert_eq "scenarioE VERIFIER_STATUS" "NOT_RUN" "$(pb_field VERIFIER_STATUS)"
  st_assert_eq "scenarioE FINAL_STATUS" "FAIL" "$(pb_field FINAL_STATUS)"

  rm -rf -- "$SELFTEST_TMP" 2>/dev/null || true

  echo "=== self-test: ${ST_PASS} passed, ${ST_FAIL} failed ==="
  [[ "$ST_FAIL" -eq 0 ]]
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
  exit $?
fi
