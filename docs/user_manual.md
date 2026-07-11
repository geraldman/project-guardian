# User Manual (stub — expanded in Week 5)

## Start the system

```sh
docker compose up -d
```

Wait ~1–2 minutes for OpenSearch to come up, then open **http://localhost:5601**
(login `admin` / `Guardian!Lti2026` unless overridden) and go to the
*Guardian Traffic Overview* dashboard.

## Stop / reset

```sh
docker compose down        # stop, keep data
docker compose down -v     # stop and wipe all indexed data + queue
```

*(To be expanded: dashboard walkthrough, attack-injection demo steps, alert handling.)*
