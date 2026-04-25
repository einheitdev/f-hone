#!/usr/bin/env bash
# Initialize the Solr core's schema for hone.
#
# Solr's solr-precreate already created the `hone` core with the
# default _default config set. This script adds the structured
# fields we need: type, protocol, builtins, severity, etc.
# Embeddings (knn_vector) deferred — added when sentence-transformers
# integration lands.
#
# Idempotent: safe to re-run; field-add calls return 200 if the
# field already exists with the same definition.

set -euo pipefail

SOLR_URL="${SOLR_URL:-http://localhost:8983/solr/hone}"

echo "Pinging $SOLR_URL ..."
until curl -sf "$SOLR_URL/admin/ping" >/dev/null; do
  echo "  Solr not ready yet, retrying..."
  sleep 2
done

add_field() {
  local name=$1
  local type=$2
  local multivalued=${3:-false}
  curl -sf "$SOLR_URL/schema" -H 'Content-Type: application/json' \
    -d "{\"add-field\":{\"name\":\"$name\",\"type\":\"$type\",\"indexed\":true,\"stored\":true,\"multiValued\":$multivalued}}" \
    >/dev/null && echo "  added $name ($type)" \
    || echo "  $name already present"
}

echo "Adding hone schema fields..."
add_field type           string  false
add_field protocol       strings true
add_field builtins       strings true
add_field severity       string  false
add_field layer          string  false
add_field pattern_tags   strings true
add_field status         string  false
add_field summary        text_general false
add_field body           text_general false
add_field source_file    string  false
add_field pkt_path       string  false
add_field created        pdate   false

echo "Done. Schema:"
curl -sf "$SOLR_URL/schema/fields" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for f in d["fields"]:
  print(f"  {f[\"name\"]:<15} {f[\"type\"]}")
'
