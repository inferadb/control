# InferaDB Control Helm Chart

Helm chart for deploying InferaDB Control Plane - the multi-tenant administration API with WebAuthn authentication.

## Prerequisites

- Kubernetes 1.28+
- Helm 3.0+
- (Optional) Ledger for production storage
- (Optional) Prometheus Operator for ServiceMonitor

## Installation

### Quick Start (Development)

```bash
helm install inferadb-control ./helm \
  --namespace inferadb \
  --create-namespace
```

### Production Deployment

```bash
helm install inferadb-control ./helm \
  --namespace inferadb \
  --create-namespace \
  --set config.storage=ledger \
  --set config.webauthn.party=inferadb.example.com \
  --set config.webauthn.origin=https://app.inferadb.example.com \
  --set secrets.masterKey=$(openssl rand -base64 32)
```

## Configuration

### Key Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of Control replicas | `2` |
| `config.storage` | Storage backend (`memory` or `ledger`) | `memory` |
| `config.webauthn.party` | WebAuthn Relying Party ID (your domain) | `""` |
| `config.webauthn.origin` | WebAuthn origin URL | `""` |
| `discovery.mode` | Service discovery mode (`none`, `kubernetes`, `tailscale`) | `kubernetes` |

### Storage Configuration

#### In-Memory (Development)

```yaml
config:
  storage: "memory"
```

#### Ledger (Production)

```yaml
config:
  storage: "ledger"
  ledger:
    endpoint: "https://ledger.example.com"
    clientId: "your-client-id"
    namespaceId: 1
```

### WebAuthn (Passkey) Configuration

Required for passkey authentication:

```yaml
config:
  webauthn:
    party: "inferadb.com"           # Your domain (without protocol)
    origin: "https://app.inferadb.com"  # Full URL users access
```

### Email Configuration

For email verification and password reset:

```yaml
config:
  email:
    enabled: true
    host: "smtp.example.com"
    port: 587
    username: "apikey"
    address: "noreply@inferadb.com"
    name: "InferaDB"
    tls: "starttls"

secrets:
  email:
    password: "your-smtp-password"
```

### Service Discovery

#### Kubernetes Discovery (Default)

Automatically discovers Engine pods for cache invalidation:

```yaml
discovery:
  mode: "kubernetes"
  engine:
    serviceName: "inferadb-engine"
    namespace: "inferadb"
    port: 8080
    labelSelector: "app.kubernetes.io/name=inferadb-engine"
```

#### Tailscale Multi-Region

For cross-cluster service discovery:

```yaml
discovery:
  mode: "tailscale"
  tailscale:
    enabled: true
    localCluster: "us-west-1"
    remoteClusters:
      - name: "eu-west-1"
        tailscaleDomain: "eu-west-1.ts.net"
        serviceName: "inferadb-engine"
        port: 8080
    authKey:
      existingSecret: "tailscale-auth"
      key: "authkey"
```

### Secrets Management

#### Direct Values (Development Only)

```yaml
secrets:
  masterKey: "base64-encoded-32-byte-key"
  email:
    password: "smtp-password"
```

#### External Secrets Operator (Production)

```yaml
externalSecrets:
  enabled: true
  secretStoreRef:
    name: "vault-backend"
    kind: ClusterSecretStore
  data:
    - secretKey: INFERADB_CTRL__AUTH__KEY_ENCRYPTION_SECRET
      remoteRef:
        key: inferadb/prod/control
        property: masterKey
```

### High Availability

```yaml
replicaCount: 3

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10

podDisruptionBudget:
  enabled: true
  minAvailable: 2

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: inferadb-control
          topologyKey: kubernetes.io/hostname
```

### Monitoring

Enable Prometheus ServiceMonitor:

```yaml
serviceMonitor:
  enabled: true
  interval: 30s
  labels:
    release: prometheus
```

## Ports

| Port | Name | Description |
|------|------|-------------|
| 9090 | http | REST API |
| 9091 | grpc | gRPC API |
| 9092 | mesh | Internal mesh API for Engine communication |

## Upgrading

```bash
helm upgrade inferadb-control ./helm \
  --namespace inferadb \
  --reuse-values \
  --set image.tag=v0.2.0
```

## Uninstalling

```bash
helm uninstall inferadb-control --namespace inferadb
```

## Troubleshooting

### Check Pod Status

```bash
kubectl get pods -n inferadb -l app.kubernetes.io/name=inferadb-control
kubectl logs -n inferadb -l app.kubernetes.io/name=inferadb-control
```

### Verify Configuration

```bash
kubectl get configmap -n inferadb inferadb-control-config -o yaml
```

### Test Health Endpoint

```bash
kubectl port-forward svc/inferadb-control 9090:9090 -n inferadb
curl http://localhost:9090/healthz
```

## Related Resources

- [InferaDB Documentation](https://inferadb.com/docs)
- [Engine Helm Chart](../../engine/helm/README.md)
- [Deployment Guides](../../docs/deployment/)
