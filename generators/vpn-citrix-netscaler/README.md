# Citrix NetScaler Gateway VPN Event Generator

Produces realistic Citrix ADC / NetScaler Gateway VPN syslog events (ECS-compatible JSON) matching the output of the Elastic Agent `citrix_adc` integration. Events cover the full SSL VPN session lifecycle: authentication, login/logout, ICA application launches, TCP/UDP connections, HTTP resource access, client security checks, session timeouts, and license alerts.

## Event Types Covered

| Event Name | Event Type | Description | Frequency | ECS Action |
|------------|------------|-------------|-----------|------------|
| SSLVPN LOGIN | Auth Success | SSL VPN session login with client/group info | ~11.1% | `logged-in` |
| AAA LOGIN_FAILED | Auth Failure | Failed authentication with failure reason | ~0.9% | `logon-failed` |
| SSLVPN LOGOUT | Session Logout | Session end with duration, bytes, connection stats | ~6.1% | `logged-out` |
| SSLVPN ICASTART | ICA Launch | Citrix ICA application launch (Workspace apps) | ~20.0% | `application-launched` |
| SSLVPN ICAEND_CONNSTAT | ICA End | ICA application terminated with transfer stats | ~13.3% | `application-terminated` |
| SSLVPN TCPCONNSTAT | TCP Stats | TCP connection statistics for VPN tunnel | ~22.2% | `connection-statistics` |
| SSLVPN UDPFLOWSTAT | UDP Stats | UDP flow statistics (DNS, NTP, SNMP, etc.) | ~4.4% | `flow-statistics` |
| SSLVPN HTTPREQUEST | HTTP Access | HTTP resource access through VPN | ~16.7% | `http-request` |
| SSLVPN TCPCONN_TIMEDOUT | Timeout | VPN connection timed out | ~2.8% | `connection-timeout` |
| SSLVPN CLISEC_CHECK | Security Check | Client endpoint security check (pass/fail) | ~1.7% | `client-security-check` |
| SSLVPN LICLMT_REACHED | License Alert | VPN license limit reached | ~0.8% | `license-limit-reached` |

## Realism Features

- **Weighted event distribution** matching production NetScaler Gateway VPN traffic
- **Correlated VPN sessions** — login events produce session context consumed by matching logout events with same user/IP/session ID
- **Correlated ICA sessions** — ICA start events produce context consumed by ICA end events with matching app/UUID/user
- **Realistic logout statistics** — bytes sent/received, TCP/UDP connection counts, policy counts, duration
- **Logout method distribution** — UserLogout (55%), TimedOut (25%), AdminLogout (10%), InternalError (5%), ForceLogout (5%)
- **Session duration distribution** — short (<5 min, 10%), medium (5 min-1 hr, 20%), long (1-4 hrs, 25%), workday (4-9 hrs, 35%), extended (>9 hrs, 10%)
- **ICA application diversity** — 9 realistic Citrix published apps (Outlook, Excel, SAP GUI, VDI desktop, etc.)
- **Authentication failure scenarios** — 70% real users with typos, 30% attacker-style usernames (admin, root, test)
- **Failure reason distribution** — Invalid credentials (40%), Certificate validation (10%), Account locked (15%), LDAP/RADIUS failures
- **Client security checks** — Endpoint compliance expressions (AV versions, firewall, OS version, domain membership)
- **HTTP resource access** — Realistic internal URLs (intranet, SharePoint, OWA, Confluence, JIRA)
- **Internal destination ports** — Weighted distribution: HTTPS (30%), RDP (15%), HTTP (10%), SMB (8%), etc.
- **NetScaler native syslog format** — `event.original` with authentic `MM/DD/YYYY:HH:MM:SS GMT` timestamp format
- **PPE (Packet Processing Engine) distribution** — Realistic multi-core PPE-0/PPE-1/PPE-2 assignment
- **Full ECS compliance** — `citrix.*`, `citrix_adc.log.*` namespaces, `observer.*`, `source.*`, `destination.*`, `related.*`, `user.*`, `url.*`

## Parameters

### Event Parameters

Edit the `params` section under `event.template` in `generator.yml`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `hostname` | `NSGW-01` | NetScaler Gateway hostname |
| `domain` | `corp.example.com` | Domain for FQDN and user domain |
| `vserver_ip` | `10.200.1.10` | VPN virtual server IP |
| `vserver_port` | `443` | VPN virtual server port |
| `nat_ip` | `203.0.113.50` | NAT/mapped IP address |
| `internal_network` | `10.100` | Internal network prefix (first 2 octets) |
| `agent_id` | `c3d4e5f6-...` | Filebeat agent ID |
| `agent_version` | `8.17.0` | Filebeat version string |

## Usage

```bash
# Install Eventum
uv tool install eventum-generator

# Run the generator
eventum generate \
  --path generators/vpn-citrix-netscaler/generator.yml \
  --id netscaler \
  --live-mode
```

### Adjusting Event Rate

Change the `count` in the input section:

```yaml
input:
  - cron:
      expression: "* * * * * *"
      count: 5    # 5 events/second (300/min, 18K/hour)
```

## Sample Output

### SSLVPN LOGIN

```json
{
    "@timestamp": "2026-03-06T10:15:22.000000+00:00",
    "citrix": {
        "cef_format": false,
        "device_product": "NetScaler",
        "device_vendor": "Citrix",
        "device_version": "NS14.1",
        "facility": "local0",
        "hostname": "NSGW-01",
        "name": "SSLVPN LOGIN",
        "ppe_id": "0-PPE-0",
        "priority": "info",
        "session_id": "3847291"
    },
    "citrix_adc": {
        "log": {
            "browser_type": "Citrix Workspace 24.3.0.36",
            "client_ip": "198.51.100.42",
            "group": "VPN_Users",
            "session_id": "3847291",
            "sslvpn_client_type": "ICA",
            "user": "jsmith",
            "vserver": {"ip": "10.200.1.10", "port": 443}
        }
    },
    "event": {
        "action": "logged-in",
        "category": ["authentication", "session"],
        "dataset": "citrix_adc.log",
        "kind": "event",
        "module": "citrix_adc",
        "outcome": "success",
        "type": ["start", "allowed"]
    },
    "observer": {
        "product": "Netscaler",
        "type": "firewall",
        "vendor": "Citrix"
    },
    "user": {"name": "jsmith", "domain": "corp.example.com"}
}
```

## File Structure

```
vpn-citrix-netscaler/
  generator.yml                          # Pipeline config (input -> event -> output)
  README.md                              # This file
  samples/
    usernames.csv                        # 25 VPN usernames with department
    client_types.json                    # 10 Citrix client types (ICA/SSLVPN/CVPN) with OS/version weights
    ica_apps.json                        # 9 Citrix published applications with XenApp server assignments
  templates/
    sslvpn-login.json.jinja              # SSLVPN LOGIN — successful VPN authentication (producer)
    aaa-login-failed.json.jinja          # AAA LOGIN_FAILED — authentication failure
    sslvpn-logout.json.jinja             # SSLVPN LOGOUT — session end with stats (consumer)
    ica-start.json.jinja                 # SSLVPN ICASTART — ICA application launch (producer)
    ica-end.json.jinja                   # SSLVPN ICAEND_CONNSTAT — ICA session terminated (consumer)
    tcp-connstat.json.jinja              # SSLVPN TCPCONNSTAT — TCP connection statistics
    udp-flowstat.json.jinja              # SSLVPN UDPFLOWSTAT — UDP flow statistics
    http-request.json.jinja              # SSLVPN HTTPREQUEST — HTTP resource access
    tcp-conn-timedout.json.jinja         # SSLVPN TCPCONN_TIMEDOUT — connection timeout
    clisec-check.json.jinja              # SSLVPN CLISEC_CHECK — client security check
    license-limit.json.jinja             # SSLVPN LICLMT_REACHED — license limit reached
```

## References

- [NetScaler ADC 14.1 Syslog Message Reference](https://developer-docs.netscaler.com/en-us/netscaler-syslog-message-reference/current-release.html)
- [How to Recognize NetScaler Gateway User Login and Logout Entries in ns.log](https://support.citrix.com/s/article/CTX464125)
- [NetScaler Observability / Logs Documentation](https://docs.netscaler.com/en-us/citrix-adc/current-release/observability/logs.html)
- [Elastic Citrix ADC Integration](https://www.elastic.co/docs/reference/integrations/citrix_adc)
- [Elastic Common Schema (ECS) Reference](https://www.elastic.co/guide/en/ecs/current/index.html)
