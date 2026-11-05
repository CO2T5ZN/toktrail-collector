#!/bin/sh
# End-to-end check of "today's data": a Codex session written NOW must reach a
# real toktrail-server and land as a record dated today (Asia/Shanghai).
#
# Everything it touches is disposable:
#   * a private PostgreSQL cluster in a temp directory,
#   * a private server on 127.0.0.1:<PORT>,
#   * a private collector state directory (TOKTRAIL_HOME is NOT used),
#   * a synthetic Codex session file.
# It never reads or writes the user's real collector state, never binds a real
# account, and never talks to a production server.
#
# Requirements: local PostgreSQL binaries (initdb/pg_ctl/psql), go, curl.
# Usage: scripts/e2e-today.sh
set -eu

PGBIN=${PGBIN:-$(dirname "$(command -v initdb 2>/dev/null || echo /usr/local/bin/initdb)")}
DB_PORT=${DB_PORT:-55441}
APP_PORT=${APP_PORT:-32112}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/toktrail-e2e.XXXXXX")
PGDATA="$WORK/pg"
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  "$PGBIN/pg_ctl" -D "$PGDATA" stop -m fast >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

echo "==> starting a disposable PostgreSQL on port $DB_PORT"
"$PGBIN/initdb" -D "$PGDATA" -U postgres --auth=trust >"$WORK/initdb.log" 2>&1
"$PGBIN/pg_ctl" -D "$PGDATA" -o "-p $DB_PORT -k $WORK -c listen_addresses=127.0.0.1" -l "$WORK/pg.log" start >/dev/null
"$PGBIN/psql" -h 127.0.0.1 -p "$DB_PORT" -U postgres -c "create database tt_e2e;" >/dev/null

echo "==> building server and collector"
( cd ../toktrail-server && go build -o "$WORK/toktrail-server" ./cmd/toktrail-server )
( cd . && go build -o "$WORK/toktrail" ./cmd/toktrail )

echo "==> starting toktrail-server on 127.0.0.1:$APP_PORT"
DATABASE_URL="postgres://postgres@127.0.0.1:$DB_PORT/tt_e2e?sslmode=disable" \
TOKTRAIL_BIND_TICKET=dev-ticket \
  "$WORK/toktrail-server" -addr "127.0.0.1:$APP_PORT" -role all >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
tries=0
until curl -fsS -o /dev/null "http://127.0.0.1:$APP_PORT/v1/devices/self" 2>/dev/null || [ "$tries" -ge 30 ]; do
  tries=$((tries + 1)); sleep 0.5
done

echo "==> writing a Codex session that happened just now"
mkdir -p "$WORK/sessions"
python3 - "$WORK/sessions/session.jsonl" <<'PY'
import datetime, json, sys
now = datetime.datetime.now(datetime.timezone.utc)
base = now - datetime.timedelta(minutes=10)
def line(obj):
    return json.dumps(obj)
out = [line({"timestamp": base.isoformat().replace("+00:00", "Z"), "type": "turn_context",
             "payload": {"model": "gpt-5-codex-e2e"}})]
for i, (input_tokens, output_tokens) in enumerate([(1000, 500), (1040, 520)]):
    ts = (base + datetime.timedelta(minutes=i)).isoformat().replace("+00:00", "Z")
    out.append(line({"timestamp": ts, "type": "event_msg", "payload": {"type": "token_count", "info": {
        "total_token_usage": {"input_tokens": input_tokens, "cached_input_tokens": 100,
                              "cache_write_input_tokens": 10, "output_tokens": output_tokens}}}}))
with open(sys.argv[1], "w") as handle:
    handle.write("\n".join(out) + "\n")
PY

echo "==> binding a throwaway device and collecting"
"$WORK/toktrail" bind --server "http://127.0.0.1:$APP_PORT" --ticket dev-ticket \
  --application leaderboard-local --subject e2e-subject --device-name e2e-device \
  --state-dir "$WORK/state" >"$WORK/bind.log" 2>&1
"$WORK/toktrail" sources enable --source codex-jsonl --input "$WORK/sessions" \
  --state-dir "$WORK/state" >"$WORK/enable.log" 2>&1
"$WORK/toktrail" periodic --state-dir "$WORK/state" --server "http://127.0.0.1:$APP_PORT" \
  --sync-timeout 120s --max-total-batches 50 >"$WORK/periodic.log" 2>&1

echo "==> checking the record the server stored"
TODAY=$("$PGBIN/psql" -h 127.0.0.1 -p "$DB_PORT" -U postgres -d tt_e2e -tAc \
  "select to_char(now() at time zone 'Asia/Shanghai', 'YYYY-MM-DD')")
ROWS=$("$PGBIN/psql" -h 127.0.0.1 -p "$DB_PORT" -U postgres -d tt_e2e -tAc \
  "select count(*) from usage_records where to_char(occurred_at at time zone 'Asia/Shanghai', 'YYYY-MM-DD') = '$TODAY'")
TOKENS=$("$PGBIN/psql" -h 127.0.0.1 -p "$DB_PORT" -U postgres -d tt_e2e -tAc \
  "select coalesce(sum(input_tokens),0) || '/' || coalesce(sum(output_tokens),0) from usage_records where to_char(occurred_at at time zone 'Asia/Shanghai','YYYY-MM-DD') = '$TODAY'")
echo "    today ($TODAY): records=$ROWS input/output=$TOKENS"
if [ "$ROWS" != "1" ] || [ "$TOKENS" != "40/20" ]; then
  echo "FAIL: expected exactly one record dated today with 40 input / 20 output tokens" >&2
  tail -20 "$WORK/periodic.log" >&2
  exit 1
fi
echo "PASS: a session written now reached the server as today's usage record"
