#!/bin/sh
# One-shot bootstrap for OpenSearch + Dashboards, run by the opensearch-init
# compose service. Idempotent: safe to re-run on every `docker compose up`.
set -u

OS_URL="${OPENSEARCH_URL:-https://opensearch:9200}"
DASH_URL="${DASHBOARDS_URL:-http://opensearch-dashboards:5601}"
AUTH="admin:${OPENSEARCH_ADMIN_PASSWORD:-Guardian!Lti2026}"

# req <extra-ok-code|-> <method> <url> [curl args...]
# Curl with the HTTP status actually checked: 2xx (or the extra code, e.g. 409
# for already-exists) passes, anything else prints the body and aborts init so
# a rejected template can never silently pass again.
req() {
  extra_ok="$1"; method="$2"; url="$3"; shift 3
  out=$(curl -sk -u "$AUTH" -X "$method" "$url" -w '\n%{http_code}' "$@")
  code=$(printf '%s' "$out" | tail -n 1)
  body=$(printf '%s' "$out" | sed '$d')
  case "$code" in
    2??|"$extra_ok") echo "[init] $method $url -> $code" ;;
    *)
      echo "[init] FATAL: $method $url -> $code" >&2
      echo "$body" >&2
      exit 1
      ;;
  esac
}

echo "[init] waiting for OpenSearch at $OS_URL ..."
until curl -sk -u "$AUTH" "$OS_URL/_cluster/health" | grep -qE '"status":"(green|yellow)"'; do
  sleep 3
done

echo "[init] applying index templates"
req - PUT "$OS_URL/_index_template/guardian-traffic-template" \
  -H 'Content-Type: application/json' -d @/init/opensearch/index-template.json
req - PUT "$OS_URL/_index_template/guardian-scores-template" \
  -H 'Content-Type: application/json' -d @/init/opensearch/scores-template.json
req - PUT "$OS_URL/_index_template/guardian-alerts-template" \
  -H 'Content-Type: application/json' -d @/init/opensearch/alerts-template.json

echo "[init] applying ISM policy guardian-traffic-ilm (409 = already exists, fine)"
req 409 PUT "$OS_URL/_plugins/_ism/policies/guardian-traffic-ilm" \
  -H 'Content-Type: application/json' -d @/init/opensearch/ism-policy.json

# Notification channel: create only if the fixed config_id isn't there yet.
if curl -sk -u "$AUTH" -o /dev/null -w '%{http_code}' \
     "$OS_URL/_plugins/_notifications/configs/guardian-alerting-webhook" | grep -q '^2'; then
  echo "[init] notification channel guardian-alerting-webhook already exists"
else
  echo "[init] creating notification channel guardian-alerting-webhook"
  req - POST "$OS_URL/_plugins/_notifications/configs" \
    -H 'Content-Type: application/json' -d @/init/opensearch/notification-channel.json
fi

# Monitor: the Alerting plugin assigns random ids, so idempotency is by name.
# Look for the name in the hits — on a virgin cluster the search 404s
# (.opendistro-alerting-config doesn't exist yet), which also means "create it".
if curl -sk -u "$AUTH" -X POST "$OS_URL/_plugins/_alerting/monitors/_search" \
     -H 'Content-Type: application/json' \
     -d '{"query":{"term":{"monitor.name.keyword":"guardian-error-rate-spike"}}}' \
     | grep -q '"name":"guardian-error-rate-spike"'; then
  echo "[init] monitor guardian-error-rate-spike already exists"
else
  echo "[init] creating monitor guardian-error-rate-spike"
  req - POST "$OS_URL/_plugins/_alerting/monitors" \
    -H 'Content-Type: application/json' -d @/init/opensearch/monitor-error-rate.json
fi

# Saved-objects bundles are exported from live Dashboards sessions and
# committed under infra/dashboards/; import every one of them.
found_ndjson=0
for f in /init/dashboards/*.ndjson; do
  [ -s "$f" ] || continue
  if [ "$found_ndjson" = 0 ]; then
    found_ndjson=1
    echo "[init] waiting for Dashboards at $DASH_URL ..."
    until curl -s -u "$AUTH" "$DASH_URL/api/status" | grep -q '"state":"green"'; do
      sleep 3
    done
  fi
  echo "[init] importing saved objects from $(basename "$f")"
  # _import answers 200 even on failure; the verdict is the body's success flag.
  resp=$(curl -s -u "$AUTH" -X POST "$DASH_URL/api/saved_objects/_import?overwrite=true" \
    -H 'osd-xsrf: true' --form file=@"$f")
  if printf '%s' "$resp" | grep -q '"success":true'; then
    echo "[init] imported $(basename "$f")"
  else
    echo "[init] FATAL: import of $(basename "$f") failed:" >&2
    echo "$resp" >&2
    exit 1
  fi
done
[ "$found_ndjson" = 0 ] && echo "[init] no saved-objects ndjson found — skipping dashboards import"

echo "[init] done"
