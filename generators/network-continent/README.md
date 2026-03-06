# Network Continent (GeoIP-Enriched Traffic)

Generates realistic network traffic events enriched with geographic/continent-level information following the Elastic Common Schema (ECS). Simulates the output of a GeoIP enrichment pipeline applied to network flow data — the kind of events consumed by Elastic Security's network map visualization.

## Data Source

This generator produces network traffic events that have been enriched with GeoIP data, populating `source.geo.*` and `destination.geo.*` fields including continent codes, country names, city names, and lat/lon coordinates. This is the standard enrichment applied by Elastic's GeoIP ingest processor to network flow records.

## Event Types

| Event Type | Chance | Description |
|---|---|---|
| Cross-continent outbound | 450 | Internal → external, different continent (CDN, SaaS, cloud) |
| Same-continent outbound | 200 | Internal → external, same continent (regional services) |
| Cross-continent inbound | 120 | External → DMZ/servers from another continent |
| Same-continent inbound | 80 | External → DMZ/servers from same continent |
| Cross-continent denied | 40 | Blocked inbound from foreign continents (threat intel) |
| Same-continent denied | 10 | Blocked inbound from same continent |

## ECS Fields Covered

- `@timestamp`, `event.*`, `data_stream.*`
- `source.ip`, `source.port`, `source.bytes`, `source.packets`
- `source.geo.continent_code`, `source.geo.continent_name`, `source.geo.country_iso_code`, `source.geo.country_name`, `source.geo.city_name`, `source.geo.region_name`, `source.geo.location`, `source.geo.timezone`
- `source.as.number`, `source.as.organization.name`
- `destination.ip`, `destination.port`, `destination.bytes`, `destination.packets`
- `destination.geo.*` (same as source.geo)
- `destination.as.number`, `destination.as.organization.name`
- `network.transport`, `network.type`, `network.direction`, `network.bytes`, `network.packets`, `network.application`, `network.community_id`, `network.iana_number`
- `observer.*`, `agent.*`, `flow.*`, `related.ip`, `tags`

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `observer_hostname` | `gw-edge-01` | Edge gateway hostname |
| `observer_domain` | `example.com` | Domain for FQDN |
| `observer_ip` | `198.51.100.1` | Gateway public IP |
| `internal_continent_code` | `NA` | Your site's continent code |
| `internal_country_iso_code` | `US` | Your site's country |
| `internal_city_name` | `Ashburn` | Your site's city |
| `agent_id` | (uuid) | Elastic agent ID |
| `agent_version` | `8.17.0` | Agent version |

## Usage

```bash
eventum generate --path generators/network-continent/generator.yml --id geocontinent --live-mode
```

## Sample Output

```json
{
    "@timestamp": "2026-03-06T14:22:33.456789",
    "destination": {
        "as": { "number": 15169, "organization": { "name": "Google LLC" } },
        "bytes": 42350,
        "geo": {
            "city_name": "Frankfurt am Main",
            "continent_code": "EU",
            "continent_name": "Europe",
            "country_iso_code": "DE",
            "country_name": "Germany",
            "location": { "lat": 50.1109, "lon": 8.6821 },
            "region_name": "Hesse",
            "timezone": "Europe/Berlin"
        },
        "ip": "203.0.113.42",
        "packets": 28,
        "port": 443
    },
    "event": {
        "action": "allow",
        "category": ["network"],
        "kind": "event",
        "outcome": "success",
        "type": ["connection", "allowed"]
    },
    "network": {
        "application": "ssl",
        "bytes": 45200,
        "direction": "outbound",
        "transport": "tcp",
        "type": "ipv4"
    },
    "source": {
        "bytes": 2850,
        "geo": {
            "city_name": "Ashburn",
            "continent_code": "NA",
            "continent_name": "North America",
            "country_iso_code": "US",
            "country_name": "United States",
            "location": { "lat": 39.0438, "lon": -77.4874 },
            "region_name": "Virginia",
            "timezone": "America/New_York"
        },
        "ip": "10.1.1.30",
        "packets": 5,
        "port": 52341
    },
    "tags": ["geo-enriched", "forwarded", "cross-continent"]
}
```

## References

- [ECS Geo Fields](https://github.com/elastic/ecs/blob/main/schemas/geo.yml)
- [ECS Network Fields](https://www.elastic.co/guide/en/ecs/current/ecs-network.html)
- [Elastic GeoIP Processor](https://www.elastic.co/guide/en/elasticsearch/reference/current/geoip-processor.html)
- [Elastic Security Network Map](https://www.elastic.co/guide/en/security/current/conf-map-ui.html)
