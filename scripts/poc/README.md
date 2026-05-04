# INTENT-BPF Safe PoC

These scripts trigger syscall events for detection validation. They do not
perform a real container escape.

## 1. Start patrold

Run this on the Kubernetes node or lab VM:

```bash
sudo ./bin/patrold --scope containers
```

For host-only testing without Kubernetes/container scope filtering:

```bash
sudo ./bin/patrold --scope all
```

## 2. Kubernetes pod test

Create a disposable pod:

```bash
kubectl apply -f scripts/poc/poc-pod.yaml
kubectl wait --for=condition=Ready pod/patrol-poc --timeout=60s
kubectl cp scripts/poc/patrol_poc.sh patrol-poc:/tmp/patrol_poc.sh
kubectl cp scripts/poc/nginx_shell_exec.py patrol-poc:/tmp/nginx_shell_exec.py
kubectl exec patrol-poc -- sh -c 'chmod +x /tmp/patrol_poc.sh /tmp/nginx_shell_exec.py && /tmp/patrol_poc.sh'
kubectl exec patrol-poc -- python3 /tmp/nginx_shell_exec.py
```

Clean up:

```bash
kubectl delete pod patrol-poc
```

## 3. Expected detections

`patrol_poc.sh` should trigger some of these, depending on available tools and
container permissions:

- `detect-shell-exec`: shell execution
- `detect-python-exec`: Python execution
- `deny-shadow-access`: `/etc/shadow` open attempt
- `deny-kcore-access`: `/proc/kcore` open attempt
- `deny-docker-sock-access`: docker socket open attempt, only if mounted
- `detect-unshare-namespace`: `unshare` syscall, only if `unshare` exists
- `detect-mount-syscall`: `mount` syscall attempt
- `detect-ptrace-abuse`: `strace`/ptrace attempt, only if `strace` exists

`nginx_shell_exec.py` should simulate:

```text
comm=nginx -> execve(/bin/bash or /bin/sh)
```

With the sample `web-server-intent`, this should produce an intent violation
and an anomalous context verdict. In the current userspace enforcement model,
that may result in a `KILL` verdict for the test process.

## Notes

- Missing tools are reported as `skipping`; that is normal on slim images.
- A failed syscall can still be detected because eBPF observes syscall entry.
- If `--scope containers` hides a local host test, rerun with `--scope all`.
