"""Load, env-expand and validate the YAML config."""

from __future__ import annotations

import os
import re

import yaml

from .sync import DEFAULT_LOCK_ATTR, DEFAULT_LOCK_VALUE, DEFAULT_UNLOCK_VALUE

_ENV_RE = re.compile(r"\$\{(\w+)\}")


def _expand(value):
    """Recursively replace ${VAR} in strings with os.environ[VAR].

    Raises KeyError with a clear message if a referenced variable is unset, so a
    missing secret fails loudly instead of leaking a literal '${VAR}' into a bind.
    """
    if isinstance(value, str):
        def sub(m):
            name = m.group(1)
            try:
                return os.environ[name]
            except KeyError:
                raise KeyError(f"config references unset environment variable ${{{name}}}")
        return _ENV_RE.sub(sub, value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def _require(cfg: dict, path: str):
    node = cfg
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node or node[part] in (None, ""):
            raise ValueError(f"config: missing required key '{path}'")
        node = node[part]
    return node


def _validate_ldap_auth(cfg: dict, section: str) -> None:
    method = cfg[section].setdefault("auth", {}).get("method", "simple")
    if method not in ("simple", "gssapi"):
        raise ValueError(f"config: {section}.auth.method must be 'simple' or 'gssapi'")
    if method == "simple":
        _require(cfg, f"{section}.auth.bind_dn")
        _require(cfg, f"{section}.auth.bind_password")


def load_config(path: str) -> dict:
    with open(path) as f:
        cfg = _expand(yaml.safe_load(f) or {})

    # source LDAP (read)
    _require(cfg, "source.url")
    _require(cfg, "source.search_base")
    _require(cfg, "source.user_filter")
    _validate_ldap_auth(cfg, "source")

    # target LDAP (write)
    _require(cfg, "target.url")
    _require(cfg, "target.base_dn")
    _validate_ldap_auth(cfg, "target")

    mappings = _require(cfg, "sync.mappings")
    rdn_attr = cfg["target"].setdefault("rdn_attr", "uid")
    if rdn_attr not in mappings.values():
        raise ValueError(
            f"config: target.rdn_attr '{rdn_attr}' must be a mapping target in sync.mappings "
            f"(so every entry has an RDN value to key and name it by)"
        )
    if cfg["sync"].get("leaver_action", "delete") not in ("disable", "delete"):
        raise ValueError("config: sync.leaver_action must be 'disable' or 'delete'")

    # defaults
    cfg["source"].setdefault("verify", True)
    cfg["target"].setdefault("verify", True)
    cfg["target"].setdefault("object_classes", ["top", "person", "organizationalPerson", "inetOrgPerson"])
    cfg["target"].setdefault("entry_filter", f"(objectClass={cfg['target']['object_classes'][-1]})")
    cfg["sync"].setdefault("exclude_users", [])
    cfg["sync"].setdefault("leaver_action", "delete")
    cfg["sync"].setdefault("lock_attr", DEFAULT_LOCK_ATTR)
    cfg["sync"].setdefault("lock_value", DEFAULT_LOCK_VALUE)
    cfg["sync"].setdefault("unlock_value", DEFAULT_UNLOCK_VALUE)
    cfg["sync"].setdefault("dry_run", False)
    return cfg
