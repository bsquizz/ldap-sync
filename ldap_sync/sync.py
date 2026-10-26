"""Reconcile a target LDAP container against a source LDAP search result.

Pure functions (desired_entry / diff_entry / partition / is_protected) hold all the decision
logic and take plain dicts, so they are unit-tested without a network. The *_run / fetch_* /
apply entry points wrap them with ldap3 connections.

Ownership model: the tool owns one target container (`target.base_dn`). Every entry under it
matching `target.entry_filter` is managed; a user present there but absent from the source is a
leaver. No marker attribute is needed -- the subtree *is* the ownership boundary.
"""

from __future__ import annotations

import logging
import ssl
import sys
from collections import Counter

log = logging.getLogger("ldap_sync")

# Defaults for the leaver_action=disable lock. Suit 389-ds/RHDS (nsAccountLock: TRUE); override
# sync.lock_attr / lock_value / unlock_value for other directories.
DEFAULT_LOCK_ATTR = "nsAccountLock"
DEFAULT_LOCK_VALUE = "TRUE"
DEFAULT_UNLOCK_VALUE = "FALSE"


# --------------------------------------------------------------------------- helpers

def _norm(vals) -> list:
    """Normalize an ldap3 attribute value (scalar or list) to a list of str."""
    if vals is None:
        return []
    if not isinstance(vals, list):
        vals = [vals]
    return [v if isinstance(v, str) else str(v) for v in vals]


def _ci_get(attrs: dict, name: str) -> list:
    """Case-insensitive attribute lookup (LDAP attribute names are case-insensitive)."""
    name_l = name.lower()
    for k, v in attrs.items():
        if k.lower() == name_l:
            return _norm(v)
    return []


def _is_locked(attrs: dict, lock_attr: str, lock_value: str) -> bool:
    lv = lock_value.lower()
    return any(v.lower() == lv for v in _ci_get(attrs, lock_attr))


# --------------------------------------------------------------------------- pure logic

def is_protected(rdn_value: str, exclude_users) -> bool:
    """Users the tool must never create, update, disable, or delete (by RDN value)."""
    return rdn_value in set(exclude_users)


def desired_entry(source_attrs: dict, cfg_sync: dict, rdn_attr: str):
    """Build the desired target entry for one in-scope source row.

    Returns (rdn_value, attrs) where attrs maps target_attr -> [str, ...] (objectClass is not
    included; it is supplied at add time). Returns None if the entry has no RDN value.
    """
    attrs = {}
    for src_attr, tgt_attr in cfg_sync["mappings"].items():
        vals = _norm(source_attrs.get(src_attr))
        if vals:
            attrs[tgt_attr] = vals
    rdn_vals = attrs.get(rdn_attr)
    if not rdn_vals:
        return None
    return rdn_vals[0], attrs


def diff_entry(existing_attrs: dict, desired_attrs: dict) -> dict | None:
    """Return ldap3 modify changes for managed attrs that differ, or None if unchanged.

    Only mapped (managed) attributes are compared. Unmanaged attributes (userPassword,
    objectClass, operational attrs, ...) are never in `desired_attrs`, so they are never touched.
    """
    from ldap3 import MODIFY_REPLACE

    changes = {}
    for attr, desired_vals in desired_attrs.items():
        if sorted(_ci_get(existing_attrs, attr)) != sorted(desired_vals):
            changes[attr] = [(MODIFY_REPLACE, desired_vals)]
    return changes or None


def partition(desired: dict, current: dict, cfg_sync: dict) -> dict:
    """Split work into create / update / leaver lists from in-memory state.

    `desired`: {rdn_key: (rdn_value, attrs)}.  `current`: {rdn_key: {"dn", "attrs"}}.
    Protected users are dropped from both sides first.
    """
    from ldap3 import MODIFY_REPLACE

    exclude = cfg_sync.get("exclude_users", [])
    disable = cfg_sync.get("leaver_action", "delete") == "disable"
    lock_attr = cfg_sync.get("lock_attr", DEFAULT_LOCK_ATTR)
    lock_value = cfg_sync.get("lock_value", DEFAULT_LOCK_VALUE)
    unlock_value = cfg_sync.get("unlock_value", DEFAULT_UNLOCK_VALUE)

    desired = {k: v for k, v in desired.items() if not is_protected(v[0], exclude)}
    current = {
        k: c for k, c in current.items()
        if not is_protected(_rdn_of(c, k), exclude)
    }

    creates = [
        {"rdn_value": rdn_value, "attrs": attrs}
        for key, (rdn_value, attrs) in desired.items() if key not in current
    ]

    updates = []
    for key, (rdn_value, attrs) in desired.items():
        existing = current.get(key)
        if existing is None:
            continue
        changes = diff_entry(existing["attrs"], attrs) or {}
        # Re-enable a returning user: only when currently locked, so it stays idempotent.
        if disable and _is_locked(existing["attrs"], lock_attr, lock_value):
            changes[lock_attr] = [(MODIFY_REPLACE, [unlock_value])]
        if changes:
            updates.append({"dn": existing["dn"], "changes": changes})

    leavers = [
        {"dn": c["dn"], "rdn_value": _rdn_of(c, key)}
        for key, c in current.items() if key not in desired
    ]
    return {"creates": creates, "updates": updates, "leavers": leavers}


def _rdn_of(current_entry: dict, key: str) -> str:
    """Best-effort human-readable RDN value for logging/exclude (falls back to the join key)."""
    return current_entry.get("rdn_value", key)


# --------------------------------------------------------------------------- I/O

def connect_ldap(section: dict):
    """Open an ldap3 connection for a source/target config section (identical shape)."""
    from ldap3 import NONE, Connection, Server, Tls

    tls = Tls(validate=ssl.CERT_REQUIRED if section.get("verify", True) else ssl.CERT_NONE)
    # get_info=NONE: skip the heavy server schema fetch on connect. We only do searches and
    # writes; the schema fetch can be terminated by the server (esp. with concurrent binds).
    server = Server(
        section["url"], use_ssl=section["url"].lower().startswith("ldaps"), tls=tls, get_info=NONE
    )
    auth = section["auth"]
    if auth["method"] == "gssapi":
        from ldap3 import GSSAPI, SASL
        return Connection(server, authentication=SASL, sasl_mechanism=GSSAPI, auto_bind=True)
    return Connection(
        server, user=auth["bind_dn"], password=auth["bind_password"], auto_bind=True
    )


def _paged(conn, base, flt, attributes, page=500):
    for entry in conn.extend.standard.paged_search(
        search_base=base, search_filter=flt, attributes=attributes,
        paged_size=page, generator=True,
    ):
        if entry.get("type") == "searchResEntry":
            yield entry


def fetch_source(conn, cfg: dict) -> dict:
    sc, sync = cfg["source"], cfg["sync"]
    rdn_attr = cfg["target"]["rdn_attr"]
    desired = {}
    for entry in _paged(conn, sc["search_base"], sc["user_filter"], list(sync["mappings"].keys())):
        built = desired_entry(entry["attributes"], sync, rdn_attr)
        if built is None:
            continue
        rdn_value, attrs = built
        desired[rdn_value.lower()] = (rdn_value, attrs)
    return desired


def fetch_target(conn, cfg: dict) -> dict:
    tc = cfg["target"]
    rdn_attr = tc["rdn_attr"]
    lock_attr = cfg["sync"].get("lock_attr", DEFAULT_LOCK_ATTR)
    wanted = sorted(set(cfg["sync"]["mappings"].values()) | {lock_attr})
    base_l = tc["base_dn"].lower()
    current = {}
    for entry in _paged(conn, tc["base_dn"], tc["entry_filter"], wanted):
        if entry["dn"].lower() == base_l:  # the container itself is not a managed user
            continue
        attrs = entry["attributes"]
        rdn_vals = _ci_get(attrs, rdn_attr)
        if not rdn_vals:
            continue
        rdn_value = rdn_vals[0]
        current[rdn_value.lower()] = {"dn": entry["dn"], "attrs": attrs, "rdn_value": rdn_value}
    return current


def apply(conn, plan: dict, cfg: dict, dry_run: bool) -> Counter:
    from ldap3.utils.dn import escape_rdn

    tc, sync = cfg["target"], cfg["sync"]
    counts = Counter()
    prefix = "[dry-run] " if dry_run else ""
    action = sync.get("leaver_action", "delete")
    lock_attr = sync.get("lock_attr", DEFAULT_LOCK_ATTR)
    lock_value = sync.get("lock_value", DEFAULT_LOCK_VALUE)

    def _do(count_key: str, verb: str, name: str, fn):
        # One bad record (e.g. a missing required attr) must not abort a bulk run.
        log.info("%s%s %s", prefix, verb, name)
        if not dry_run:
            try:
                if not fn():
                    raise RuntimeError(conn.result.get("description") or conn.result)
            except Exception as e:  # noqa: BLE001 - deliberately resilient
                counts["failed"] += 1
                log.error("FAILED %s %s: %s", verb, name, e)
                return
        counts[count_key] += 1

    for c in plan["creates"]:
        dn = f"{tc['rdn_attr']}={escape_rdn(c['rdn_value'])},{tc['base_dn']}"
        _do("created", "CREATE", dn,
            lambda dn=dn, c=c: conn.add(dn, object_class=tc["object_classes"], attributes=c["attrs"]))
    for u in plan["updates"]:
        _do("updated", "UPDATE", u["dn"], lambda u=u: conn.modify(u["dn"], u["changes"]))
    for leaver in plan["leavers"]:
        if action == "delete":
            _do("removed", "DELETE", leaver["dn"], lambda leaver=leaver: conn.delete(leaver["dn"]))
        else:
            from ldap3 import MODIFY_REPLACE
            _do("removed", "DISABLE", leaver["dn"],
                lambda leaver=leaver: conn.modify(leaver["dn"], {lock_attr: [(MODIFY_REPLACE, [lock_value])]}))
    return counts


def run(cfg: dict, dry_run: bool = False) -> int:
    dry_run = dry_run or cfg["sync"].get("dry_run", False)

    src = connect_ldap(cfg["source"])
    desired = fetch_source(src, cfg)
    if not desired:
        # Guard against a bad filter / LDAP hiccup: with an empty desired set every managed
        # target entry looks like a leaver, which under leaver_action=delete would wipe the
        # whole target container.
        sys.exit("FATAL: source LDAP returned 0 in-scope users; refusing to sync. "
                 "Check source.user_filter and connectivity.")

    tgt = connect_ldap(cfg["target"])
    current = fetch_target(tgt, cfg)
    plan = partition(desired, current, cfg["sync"])
    log.info(
        "target=%s source_in_scope=%d target_entries=%d -> create=%d update=%d leaver=%d (%s)",
        cfg["target"]["base_dn"], len(desired), len(current),
        len(plan["creates"]), len(plan["updates"]), len(plan["leavers"]),
        cfg["sync"].get("leaver_action", "delete"),
    )
    counts = apply(tgt, plan, cfg, dry_run)
    log.info("done: %s", dict(counts))
    return 1 if counts.get("failed") else 0
