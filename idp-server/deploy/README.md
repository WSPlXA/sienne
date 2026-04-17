# Deployment Manifests

## Layout

- `deploy/k8s/idp-stack.yaml`: Kubernetes multi-document manifest.
- `deploy/podman/idp-stack.yaml`: `podman kube play` manifest for a single local pod.

## Why The Layout Looks Like This

- `idp-server` is pinned to `replicas: 1` in Kubernetes and a single Pod in Podman. Current JWK rotation stores private keys as filesystem references plus database metadata. That is not multi-writer safe and it is not multi-replica safe unless you move private-key storage to a shared backend such as KMS, Vault, or a RWX filesystem with external leader election.
- Kubernetes uses `Deployment` with `Recreate` for `idp-server` so a rollout does not momentarily run two pods against the same signing-key PVC.
- MySQL and Redis are `StatefulSet` workloads in Kubernetes because their hot path is persistent local state, not stateless CPU. The manifests keep their write path on PVCs and keep them off the public network.
- Podman uses a single Pod and points the application at `127.0.0.1` for MySQL and Redis. That removes extra service discovery, bridge hops, and container-to-container DNS lookup overhead on the local machine.

## Images

Build and tag the local images first:

```powershell
podman build -f dockerfile.db -t localhost/idp-db:2026.04.02 .
podman build -f dockerfile.reids -t localhost/idp-redis:2026.04.02 .
podman build -f dockerfile.server -t localhost/idp-server:2026.04.02 .
```

For Kubernetes, push equivalent immutable tags to your registry and replace the `ghcr.io/your-org/...` image references in [deploy/k8s/idp-stack.yaml](F:/source%20code/palyground/workspace/idp-server/deploy/k8s/idp-stack.yaml).

## Usage

Apply Kubernetes manifests:

```powershell
kubectl apply -f deploy/k8s/idp-stack.yaml
```

Run the Podman stack:

```powershell
podman kube play deploy/podman/idp-stack.yaml
```

## MySQL Replica Hardening

For primary/replica deployments, enforce hard read-only constraints on replica and use a read-only account:

```sql
SOURCE deploy/mysql/replica_readonly_hardening.sql;
```

Then configure application DSNs:

- `MYSQL_DSN`: primary (read/write account)
- `MYSQL_READ_DSN`: replica (read-only account)
- `MYSQL_STRONG_READ_SESSION_BY_ID=true`: force session critical checks to primary
- `MYSQL_STRONG_READ_TOKEN_BY_SHA256=true`: force token SHA256 critical checks to primary

## Windows Host Notes

- Kubernetes 清单不需要改。你在 Windows 上执行 `kubectl apply -f deploy/k8s/idp-stack.yaml` 只是发请求给集群，真正跑 workload 的仍然是 Linux 节点。
- Podman 在 Windows 上实际依赖 Linux VM。Podman Desktop 文档明确说明，在 macOS 和 Windows 上运行 Podman engine 需要先运行一个 Podman machine。
- 这意味着 `deploy/podman/idp-stack.yaml` 里的容器、卷和镜像都存在于 Podman machine 里，不存在于 Windows 文件系统本体里。
- 我这里的 Podman YAML 没有使用 `hostPath`，只用了 `PersistentVolumeClaim` 命名卷，就是为了绕开 Windows 路径映射、盘符和远端挂载语义。
- `podman kube play` 在 Windows 远端客户端模式下，`--build`、`--context-dir`、`--configmap` 这些选项不可用；官方文档也明确写了这一点。所以镜像不要指望 `kube play --build` 现场构建，而要先单独 `podman build`，或者直接从 registry 拉取。

Windows 上推荐执行顺序：

```powershell
podman machine init
podman machine start
podman build -f dockerfile.db -t localhost/idp-db:2026.04.02 .
podman build -f dockerfile.reids -t localhost/idp-redis:2026.04.02 .
podman build -f dockerfile.server -t localhost/idp-server:2026.04.02 .
podman kube play deploy/podman/idp-stack.yaml
```

如果你跑的是 WSL2 内的 Podman，而不是 Windows 远端客户端，上面这些限制会少一些，但这套 YAML 本身不需要改。

## Required Edits Before Production

- Replace `ISSUER` with the real external HTTPS origin.
- Replace the sample passwords in both manifests.
- Add an Ingress or gateway object in front of [deploy/k8s/idp-stack.yaml](F:/source%20code/palyground/workspace/idp-server/deploy/k8s/idp-stack.yaml) once the hostname and TLS termination point are fixed.
- Treat `scripts/migrate.sql` as bootstrap SQL only. It drops and recreates tables, so it must not be used as an online migration path for an already populated database.
