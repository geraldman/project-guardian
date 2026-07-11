#!/bin/sh
# One-shot bootstrap for OpenSearch + Dashboards, run by the opensearch-init
# compose service. Idempotent: safe to re-run on every `docker compose up`.
set -u

OS_URL="${OPENSEARCH_URL:-https://opensearch:9200}"
DASH_URL="${DASHBOARDS_URL:-http://opensearch-dashboards:5601}"
AUTH="admin:${OPENSEARCH_ADMIN_PASSWORD:-Guardian!Lti2026}"

echo "[init] waiting for OpenSearch at $OS_URL ..."
until curl -sk -u "$AUTH" "$OS_URL/_cluster/health" | grep -qE '"status":"(green|yellow)"'; do
  sleep 3
done

echo "[init] applying index template guardian-traffic-template"
curl -sk -u "$AUTH" -X PUT "$OS_URL/_index_template/guardian-traffic-template" \
  -H 'Content-Type: application/json' \
  -d @/init/opensearch/index-template.json
echo ""

echo "[init] applying ISM policy guardian-traffic-ilm (409 = already exists, fine)"
curl -sk -u "$AUTH" -X PUT "$OS_URL/_plugins/_ism/policies/guardian-traffic-ilm" \
  -H 'Content-Type: application/json' \
  -d @/init/opensearch/ism-policy.json
echo ""

# Saved-objects bundle is exported from a live Dashboards session later
# (feat/dashboards); skip quietly until it exists.
if [ -s /init/dashboards/saved_objects.ndjson ]; then
  echo "[init] waiting for Dashboards at $DASH_URL ..."
  until curl -s -u "$AUTH" "$DASH_URL/api/status" | grep -q '"state":"green"'; do
    sleep 3
  done
  echo "[init] importing saved objects"
  curl -s -u "$AUTH" -X POST "$DASH_URL/api/saved_objects/_import?overwrite=true" \
    -H 'osd-xsrf: true' \
    --form file=@/init/dashboards/saved_objects.ndjson
  echo ""
else
  echo "[init] no saved_objects.ndjson yet — skipping dashboards import"
fi

echo "[init] done"
