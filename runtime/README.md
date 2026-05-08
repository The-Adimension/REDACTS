# REDACTS Runtime Configurations

Container runtime templates for running REDACTS dynamic analysis.

## Canonical, supported runtimes

These two are exercised in CI and documented in the main README:

| Path | Engine | Use case |
| --- | --- | --- |
| `docker/` | Docker + Docker Compose | Default; matches `dynamic/docker-compose.dast.yml`. |
| `podman/` | Podman + podman-compose | Rootless / daemonless drop-in replacement. |

Each file is a self-contained configuration template.  Copy the one
matching your environment and adjust values as needed.

## Under development (`under_dev/`)

The `contrib/` subtree holds runtime templates that are not part of the supported test matrix.  They are kept for reference and accepted as PRs but they are **not** validated against every release:

- `under_dev/nix/` --- Nix flake
- `under_dev/containerd/` --- containerd + nerdctl
- `under_dev/crio/` --- CRI-O
- `under_dev/k8s/` --- Kubernetes `Job` manifest
- `under_dev/lxc/` --- LXC / LXD
- `under_dev/buildah/` --- Buildah (OCI image build only)
- `under_dev/lima/` --- Lima (macOS Linux VMs)
- `under_dev/rancher/` --- Rancher Desktop
- `under_dev/gcloud/` --- Google Cloud Run
- `under_dev/aws/` --- AWS ECS / EKS
