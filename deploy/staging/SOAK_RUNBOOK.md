# Soak Runbook — `dogfood_v02.fw` ≥ 48h

One-page operator checklist for the Phase 2 soak. The implementing
agent has staged everything in this directory; the operator claims
a VM, copies the tree, installs units, and watches the first hour.

## Pre-flight

```sh
takt target list
takt target claim dev-01 f-phase2          # or dev-02 / dev-03
ssh worker@10.101.0.10                     # IP for dev-01
```

Verify kernel + libbpf:

```sh
uname -r                                   # ≥ 6.6
ldconfig -p | grep libbpf                  # libbpf.so.1 present
mount | grep -q '^bpf on /sys/fs/bpf '     # bpffs mounted
```

## 1. Stage the artefacts on the VM

From the operator's host:

```sh
rsync -av f-hone/deploy/staging/ worker@<vm>:/tmp/soak-staging/
```

On the VM:

```sh
sudo install -d -m 0755 /etc/f /usr/share/f/compiled /var/log/f /var/log/f-hone/soak

sudo install -m 0644 /tmp/soak-staging/fd.yaml /etc/f/fd.yaml
sudo install -m 0644 /tmp/soak-staging/dogfood_v02.fw /etc/f/rules.fw

sudo install -m 0644 /tmp/soak-staging/fd.service /etc/systemd/system/
sudo install -m 0644 /tmp/soak-staging/hone-soak.service /etc/systemd/system/
sudo install -m 0644 /tmp/soak-staging/hone-soak.timer /etc/systemd/system/

sudo install -m 0755 /tmp/soak-staging/hone-soak.sh /opt/f-hone/scripts/
sudo install -m 0755 /tmp/soak-staging/hone-soak-summary.sh /opt/f-hone/scripts/
```

## 2. Compile the initial bundle

```sh
cd /opt/f
sudo -u fd /opt/f-hone/.venv/bin/fwl compile --bundle \
    /usr/share/f/compiled/v-init /etc/f/rules.fw
sudo ln -sfT /usr/share/f/compiled/v-init /usr/share/f/compiled/current
```

Verify the symlink resolves and the BPF object is readable:

```sh
sudo -u fd test -r /usr/share/f/compiled/current/main.bpf.o && echo OK
```

## 3. Bring up the daemon

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now fd.service
sudo systemctl status fd.service
```

The first journal line should read:

```
[INFO] Loaded BPF object from /usr/share/f/compiled/current/main.bpf.o
```

If it instead reads `/usr/lib/f/fw.bpf.o` or any of the v0.1
fall-back paths, the symlink is broken — `chown -R fd:fd
/usr/share/f/compiled` and restart `fd`.

## 4. Arm the soak loop

```sh
sudo systemctl enable --now hone-soak.timer
systemctl list-timers hone-soak.timer
```

The first tick fires 5 minutes after the timer is enabled, then
every 30 minutes thereafter. Tail the first run:

```sh
sudo journalctl -u hone-soak.service -f
```

## 5. The first-hour watch

For the first 60 minutes after enabling `fd`:

- `journalctl -u fd.service -f` — no `WARN`/`ERROR` lines, no
  verifier rejections.
- `dmesg -wH` — no BPF prog warnings.
- `bpftool prog show` — `fwl_prog` attached on eth0.
- `bpftool map dump pinned /sys/fs/bpf/f/__rate_limit_overflow`
  — counter stays at 0 (or matches expected key-space exhaustion
  if the soak intentionally drives traffic past the bucket cap).
- `f-api` (or curl): `GET /api/v1/counters` returns the rule
  counters and the reserved `__rate_limit_overflow` slot.

If any of those checks fail, capture the journal + dmesg:

```sh
sudo journalctl -u fd.service --since '-1h' > /tmp/soak-fd-$(date -u +%Y%m%dT%H%M%SZ).log
sudo dmesg -T --since '-1h' > /tmp/soak-dmesg-$(date -u +%Y%m%dT%H%M%SZ).log
```

…and revert with `sudo systemctl stop fd.service` before
investigating. A failed soak is not "let it run anyway".

## 6. Walking away

Once the first hour is clean, the soak is autonomous. Check daily:

```sh
ls -lt /var/log/f-hone/soak/$(date -u +%Y-%m-%d)/  # tick logs
cat /var/log/f-hone/soak/$(date -u +%Y-%m-%d)/spend.txt   # spend so far
```

Or set `OPERATOR_EMAIL` in `/etc/default/hone-soak` so the
summary mailer pings you each morning at 00:05 UTC.

## 7. Closing the soak

After ≥ 48 hours of clean operation:

```sh
sudo systemctl stop hone-soak.timer
sudo journalctl -u fd.service --since '-48h' > /tmp/soak-final-fd.log
sudo journalctl -u hone-soak.service --since '-48h' > /tmp/soak-final-hone.log
ls -R /var/log/f-hone/soak/                 # full log tree
```

Append the result to `f/docs/RELEASE_v0.2.md`'s Verification
section, run `hone abstract` once more (post-soak findings get
clustered), and release the VM:

```sh
takt target release dev-01
```
