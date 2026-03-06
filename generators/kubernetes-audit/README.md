# Kubernetes API Audit Log Generator

Generates realistic Kubernetes API server audit log events in ECS-compatible JSON format, matching the [Elastic Kubernetes audit_logs integration](https://docs.elastic.co/integrations/kubernetes/audit-logs) field structure.

## Data Source

Kubernetes audit logs record all requests to the Kubernetes API server, including user operations (via kubectl), controller reconciliation loops, health probes, and internal system operations. The audit log captures the full lifecycle of each API request with authentication, authorization, and response details.

## Event Types

| Template | Description | Approx. Distribution |
|----------|-------------|---------------------|
| `health-probe` | Health/readiness/liveness probe checks (`/readyz`, `/healthz`, `/livez`) | ~25% |
| `get-resource` | GET single resource (pods, services, configmaps, secrets, etc.) | ~17% |
| `list-resource` | LIST resources across namespaces | ~13% |
| `watch-resource` | Long-running WATCH streams from controllers/operators | ~15% |
| `api-discovery` | API discovery endpoints (`/api`, `/apis`, `/openapi`) | ~10% |
| `create-resource` | CREATE new resources (pods, deployments, services, etc.) | ~5% |
| `update-resource` | UPDATE/PATCH existing resources and status subresources | ~5% |
| `delete-resource` | DELETE resources | ~2% |
| `rbac-access` | RBAC operations (clusterroles, roles, bindings) | ~5% |
| `exec-attach` | Pod exec, attach, port-forward, and log access | ~3% |

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `agent_id` | `6e730a0c-...` | Filebeat agent ID |
| `agent_version` | `8.17.0` | Agent version |
| `agent_name` | `kind-control-plane` | Agent hostname |
| `cluster_name` | `production-cluster` | Kubernetes cluster name |
| `error_rate` | `3` | Percentage of events that are errors (403, 404, 409, 422) |

## Usage

```bash
# Live mode (continuous generation)
eventum generate --path generators/kubernetes-audit/generator.yml --id k8s-audit --live-mode

# Generate a batch
eventum generate --path generators/kubernetes-audit/generator.yml --id k8s-audit --live-mode false
```

## Sample Output

```json
{
  "@timestamp": "2026-03-06T14:30:45.123456+00:00",
  "agent": {
    "ephemeral_id": "d27511c8-9cd1-402c-8b1b-234abbd9dcae",
    "id": "6e730a0c-7da5-48ff-b4c9-f6c63844975d",
    "name": "kind-control-plane",
    "type": "filebeat",
    "version": "8.17.0"
  },
  "ecs": {"version": "8.17.0"},
  "data_stream": {
    "dataset": "kubernetes.audit_logs",
    "namespace": "default",
    "type": "logs"
  },
  "event": {
    "action": "get",
    "category": ["web"],
    "dataset": "kubernetes.audit_logs",
    "kind": "event",
    "module": "kubernetes",
    "outcome": "success",
    "type": ["access"]
  },
  "kubernetes": {
    "audit": {
      "auditID": "bcacfeaa-5ab5-48de-8bac-3a87d1474b6a",
      "apiVersion": "audit.k8s.io/v1",
      "kind": "Event",
      "level": "RequestResponse",
      "stage": "ResponseComplete",
      "verb": "get",
      "requestURI": "/readyz",
      "user": {
        "username": "system:anonymous",
        "groups": ["system:unauthenticated"]
      },
      "sourceIPs": ["172.18.0.2"],
      "userAgent": "kube-probe/1.29",
      "responseStatus": {"metadata": {}, "code": 200},
      "annotations": {
        "authorization_k8s_io/decision": "allow",
        "authorization_k8s_io/reason": "RBAC: allowed by ClusterRoleBinding..."
      },
      "requestReceivedTimestamp": "2026-03-06T14:30:45.123456Z",
      "stageTimestamp": "2026-03-06T14:30:45.124567Z"
    }
  },
  "orchestrator": {
    "cluster": {"name": "production-cluster"},
    "type": "kubernetes"
  },
  "related": {"ip": ["172.18.0.2"], "user": ["system:anonymous"]},
  "source": {"ip": "172.18.0.2"},
  "tags": ["forwarded", "kubernetes-audit"],
  "user": {"name": "system:anonymous"},
  "user_agent": {"original": "kube-probe/1.29"}
}
```

## References

- [Kubernetes Auditing Documentation](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Elastic Kubernetes Audit Logs Integration](https://docs.elastic.co/integrations/kubernetes/audit-logs)
- [Kubernetes Audit Event API](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/)
