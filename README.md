# edge-connector-releases

Signed release tree for [edge-connector](https://github.com/MaiWittawat/edge-connector): `cloudcentric-agent` and the plugins it installs. Files only — no source code.

```
install-agent.sh                                   one-liner installer (base URL + trusted key baked in)
<name>/<version>/<os>_<arch>/manifest.json         PluginManifest: url, sha256, size, Ed25519 signature
<name>/<version>/<os>_<arch>/<name>_<version>_<os>_<arch>.tar.gz
<name>/channels/<channel>.json                     {"version": "x"}
```

Install the agent on a Linux host with systemd (the token comes from the CRM: Settings → Edge → Add host):

```bash
curl -fsSL https://raw.githubusercontent.com/MaiWittawat/edge-connector-releases/main/install-agent.sh \
  | sudo CC_ENROLL_TOKEN=cce1.host_… sh -s -- --server connect.maiwitt.cloud:443
```

Every artifact is signed with key `release-2026`:

```
release-2026: z+2JAsL/vL5CKT1VlAWn0tpuc6hCWKiMi4C1Wxt9Xdc=
```

The agent and `install-agent.sh` refuse anything whose sha256 or signature does not match. Published with `cc-release package` / `promote` / `verify`; releases are immutable — a new build gets a new version.
