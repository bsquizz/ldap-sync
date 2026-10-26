# ldap-sync

Push-based, one-way sync of user entries from a **source LDAP** into a **target LDAP** — any
directory (OpenLDAP, 389-ds /
[Red Hat Directory Server](https://docs.redhat.com/en/documentation/red_hat_directory_server/13),
Active Directory, ...) — via plain LDAP add/modify/delete.

It's the LDAP→LDAP sibling of
[`ldap-keycloak-sync`](https://github.com/bsquizz/ldap-keycloak-sync): same source side, but the
destination is another directory instead of a Keycloak realm. Run it as a job wherever the
source LDAP is reachable; it reads the source and **pushes** changes into the target directory.
Designed to run as an OpenShift `CronJob`.

The tool is generic LDAP→LDAP. The `disable` leaver action defaults to 389-ds/RHDS's
`nsAccountLock: TRUE`, but the lock attribute and values are configurable (`sync.lock_attr` /
`lock_value` / `unlock_value`) so it works against any directory.

## What it does

On each run it reconciles **one target container** (`target.base_dn`) against a source search:

- **Create** — a source user matching `source.user_filter` with no entry in the target container
  is created there (with the configured `object_classes` and mapped attributes; no password).
- **Update** — an existing entry gets only the **changed** mapped attributes written back. No
  change means no LDAP write (idempotent).
- **Delete** (default) or **disable** — an entry in the target container whose user has fallen
  out of source scope is deleted. With `leaver_action: disable` it is locked via the configured
  `lock_attr`/`lock_value` (default `nsAccountLock: TRUE`) instead, and re-enabled (set to
  `unlock_value`) if the user returns to scope.

### Ownership model — the subtree *is* the boundary

The tool owns `target.base_dn` **exclusively**. Every entry under it matching
`target.entry_filter` is considered managed, and anything there but missing from the source is a
leaver. There is no ownership marker and no adopt step.

> **Point `target.base_dn` at a container this tool controls alone.** If it also holds
> manually-created entries, they have no source match and will be deleted (or disabled) as
> leavers.

### Safety guarantees

- **Refuses to run on an empty source.** If the source returns 0 in-scope users (bad filter,
  LDAP hiccup), every target entry would look like a leaver — which under the default
  `leaver_action: delete` would wipe the container. The run aborts with a fatal error before any
  write. **This is the single most important guard; keep it.**
- **Never touches passwords, objectClass, or operational attributes.** Updates send only the
  mapped attributes; `userPassword` and the like are never in the change set.
- **Preserves unmanaged attributes.** Only mapped attribute names are compared and replaced;
  everything else on an entry is left intact.
- **Protected principals.** RDN values listed in `sync.exclude_users` are skipped by every path
  (create/update/disable/delete) on both sides.
- **Secrets never live in config files** — binds are read from the environment (`${VAR}`),
  supplied by a Kubernetes Secret.

## Install

```bash
pip install .
# For auth.method: gssapi, first install the Kerberos build prerequisite, then the extra:
#   Fedora/RHEL:  sudo dnf install krb5-devel
#   Debian/Ubuntu: sudo apt install libkrb5-dev
pip install '.[gssapi]'
```

## Configuration

Copy [`config.example.yaml`](config.example.yaml) and edit. Key points:

- **Two LDAP sections** — `source` (read) and `target` (write), each with its own
  `url`/`auth`/`verify`. Both support `method: simple` (bind DN + password from `${VAR}`) or
  `method: gssapi` (ambient Kerberos ticket/keytab).
- **`source.user_filter`** decides who belongs in the target. Scope it to your authoritative
  group (e.g. `memberOf=...`). `(uid=*)` copies everyone the bind account can see — for a large
  corporate directory that's tens of thousands of entries and a heavy initial import. A
  directory's "person" objectClass often also covers service/shared accounts — add a
  discriminating attribute to the filter to exclude them.
- **`target.base_dn`** — the dedicated, tool-owned container (see *Ownership model*).
- **`target.object_classes`** — stamped on created entries. The default inetOrgPerson chain
  requires `cn` and `sn`, so your `mappings` must produce both; an entry missing a
  schema-required attribute fails its own `add` (logged) without aborting the run.
- **`sync.mappings`** are `source_attr: target_attr` (usually identity; rename where schemas
  differ). `target.rdn_attr` (default `uid`) must appear as a mapping target — it's the join key
  and the RDN of created entries. The example mirrors the five fields the companion
  `ldap-keycloak-sync` syncs (`uid`, `givenName`, `sn`, `mail`, `rhatUUID`) **plus `cn`**, which
  `inetOrgPerson` requires but Keycloak didn't.
- **`sync.leaver_action`**: `delete` (default) or `disable` (reversible lock). For `disable`,
  **`sync.lock_attr`** / **`lock_value`** / **`unlock_value`** control the lock (defaults
  `nsAccountLock` / `TRUE` / `FALSE`, for 389-ds/RHDS). Override for other directories.

#### Storing `rhatUUID` (custom attribute)

`rhatUUID` is a Red Hat custom attribute defined by the `rhatPerson` objectClass; standard
`inetOrgPerson` can't hold it. The config keeps the **native name** (`rhatUUID: rhatUUID`) and
adds `rhatPerson` to `target.object_classes`, mirroring the source. Consequently the **target
RHDS must have the `rhatUUID`/`rhatPerson` schema loaded** — otherwise every create fails with an
attribute/objectClass violation.

On the target, either:

- **Load Red Hat's real `rhatPerson` schema** — faithful 1:1 mirror, no OID/name clashes. If
  `rhatPerson` requires attributes beyond the ones synced here, add them to `sync.mappings`.
- **Load just the `rhatUUID` attribute definition plus a minimal auxiliary objectClass** that
  only *may* contain it (no extra required attrs), and put that class in `target.object_classes`
  instead of `rhatPerson`. Use Red Hat's real `rhatUUID` OID/definition so a later full-schema
  load doesn't collide.

Downstream, map `rhatUUID → rhatUUID` in the Keycloak LDAP federation like any other attribute.

> **Not `employeeNumber`.** On a real entry that is a separate, populated attribute (the actual
> employee number) — never overload it with a UUID.

### Target bind (least privilege)

The target bind account needs add/modify/delete rights **only under `target.base_dn`**. In RHDS,
grant a scoped ACI on that subtree rather than using `cn=Directory Manager` in production.

## Run locally

```bash
pip install -e '.[dev]'
export SRC_BIND_DN=... SRC_BIND_PASSWORD=... TGT_BIND_DN=... TGT_BIND_PASSWORD=...
ldap-sync --config config.yaml --dry-run -v
```

`--dry-run` logs the planned create/update/delete actions and makes no changes. Drop it to
apply. Verify the empty-source guard once by pointing `source.user_filter` at a no-match filter
and confirming the run aborts **before** any delete.

## Deploy on OpenShift

```bash
# 1. Build and push the image (distroless Red Hat Hardened Image runtime).
podman build -t <registry>/ldap-sync:latest -f Containerfile .
podman push <registry>/ldap-sync:latest

# 2. Create the Secret (do NOT commit real values).
oc create secret generic ldap-sync \
  --from-literal=SRC_BIND_DN='uid=svc-sync,ou=serviceaccounts,dc=src,dc=com' \
  --from-literal=SRC_BIND_PASSWORD=... \
  --from-literal=TGT_BIND_DN='...' \
  --from-literal=TGT_BIND_PASSWORD=...

# 3. Edit deploy/configmap.yaml (urls/bases/filters) and cronjob.yaml (image), then apply.
oc apply -f deploy/configmap.yaml
oc apply -f deploy/cronjob.yaml
```

The CronJob mounts the ConfigMap at `/etc/sync`, pulls secrets via `envFrom`, and runs under a
restricted-v2-compatible `securityContext` (non-root, read-only root FS, all capabilities
dropped). `concurrencyPolicy: Forbid` prevents overlap.

**GSSAPI in-pod:** the distroless runtime has no krb5 libraries. To use `method: gssapi` in a
pod, bundle krb5 libs into the image (or switch to a UBI base) and mount a keytab + `krb5.conf`.
Simple bind is the default pod path.

### Initial import

The first run creates every in-scope user; at whole-company scale that can exceed the CronJob
`activeDeadlineSeconds`. Run it once manually, then let the CronJob take over steady state — the
sync is idempotent, so an interrupted import completes over successive runs.

## Development

```bash
pip install -e '.[dev]'
pytest                # or: python tests/test_sync.py
```

The reconcile logic (`desired_entry`, `diff_entry`, `partition`, `is_protected` in
`ldap_sync/sync.py`) is pure and unit-tested without a network.

## Not supported

- Copying `userPassword` / credentials (created entries have no password).
- Moving/renaming entries whose RDN value changed in the source (treated as delete + create).

## License

MIT — see [LICENSE](LICENSE).
