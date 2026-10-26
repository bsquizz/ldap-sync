"""Unit tests for the pure reconcile logic (no network)."""

import types

from ldap_sync.sync import (
    DEFAULT_LOCK_ATTR,
    DEFAULT_LOCK_VALUE,
    desired_entry,
    diff_entry,
    fetch_source,
    is_protected,
    partition,
)

CFG_SYNC = {
    "mappings": {
        "uid": "uid",
        "givenName": "givenName",
        "sn": "sn",
        "cn": "cn",
        "mail": "mail",
    },
    "exclude_users": ["admin"],
    "leaver_action": "delete",
}
RDN = "uid"


def _src(uid="jdoe"):
    return {
        "uid": [uid],
        "givenName": ["Jane"],
        "sn": ["Doe"],
        "cn": ["Jane Doe"],
        "mail": [f"{uid}@example.com"],
    }


def _desired(uid="jdoe", cfg=CFG_SYNC):
    rdn_value, attrs = desired_entry(_src(uid), cfg, RDN)
    return {rdn_value.lower(): (rdn_value, attrs)}


def test_desired_entry_maps_and_keys():
    rdn_value, attrs = desired_entry(_src(), CFG_SYNC, RDN)
    assert rdn_value == "jdoe"
    assert attrs["sn"] == ["Doe"]
    assert attrs["mail"] == ["jdoe@example.com"]
    assert "objectClass" not in attrs  # supplied at add time, never a managed attr


def test_desired_entry_none_without_rdn_value():
    src = _src()
    del src["uid"]
    assert desired_entry(src, CFG_SYNC, RDN) is None


def test_diff_entry_none_when_unchanged():
    _, desired = desired_entry(_src(), CFG_SYNC, RDN)
    assert diff_entry(desired, desired) is None  # idempotent -> no write


def test_diff_entry_detects_change():
    _, desired = desired_entry(_src(), CFG_SYNC, RDN)
    existing = {**desired, "sn": ["Old"]}
    changes = diff_entry(existing, desired)
    assert changes is not None and changes["sn"][0][1] == ["Doe"]


def test_diff_entry_case_insensitive_attr_names():
    # LDAP attribute names are case-insensitive; a server returning 'Mail' must not re-write.
    _, desired = desired_entry(_src(), CFG_SYNC, RDN)
    existing = {"UID": ["jdoe"], "GivenName": ["Jane"], "SN": ["Doe"],
                "CN": ["Jane Doe"], "Mail": ["jdoe@example.com"]}
    assert diff_entry(existing, desired) is None


def test_diff_entry_ignores_unmanaged():
    _, desired = desired_entry(_src(), CFG_SYNC, RDN)
    existing = {**desired, "userPassword": ["{SSHA}secret"], "telephoneNumber": ["555"]}
    assert diff_entry(existing, desired) is None  # unmanaged attrs never compared or touched


def test_partition_create_update_leaver():
    desired = _desired("jdoe")
    current = {
        "gone": {"dn": "uid=gone,ou=people,dc=t", "attrs": _src("gone"), "rdn_value": "gone"},
        "jdoe": {"dn": "uid=jdoe,ou=people,dc=t",
                 "attrs": {**_src("jdoe"), "sn": ["Old"]}, "rdn_value": "jdoe"},
    }
    plan = partition(desired, current, CFG_SYNC)
    assert [l["rdn_value"] for l in plan["leavers"]] == ["gone"]
    assert plan["updates"] and plan["updates"][0]["dn"] == "uid=jdoe,ou=people,dc=t"
    assert plan["creates"] == []

    desired.update(_desired("new"))
    plan = partition(desired, current, CFG_SYNC)
    assert [c["rdn_value"] for c in plan["creates"]] == ["new"]


def test_partition_reenables_locked_returning_user():
    cfg = {**CFG_SYNC, "leaver_action": "disable"}
    desired = _desired("jdoe")
    current = {"jdoe": {"dn": "uid=jdoe,ou=people,dc=t",
                        "attrs": {**_src("jdoe"), DEFAULT_LOCK_ATTR: [DEFAULT_LOCK_VALUE]},
                        "rdn_value": "jdoe"}}
    plan = partition(desired, current, cfg)
    assert plan["updates"][0]["changes"][DEFAULT_LOCK_ATTR][0][1] == ["FALSE"]
    # not locked -> no perpetual unlock write
    current["jdoe"]["attrs"].pop(DEFAULT_LOCK_ATTR)
    assert partition(desired, current, cfg)["updates"] == []


def test_partition_honors_custom_lock_attr_and_value():
    # A non-RHDS directory: lock via a different attribute/value pair.
    cfg = {**CFG_SYNC, "leaver_action": "disable",
           "lock_attr": "pwdLockout", "lock_value": "locked", "unlock_value": "active"}
    desired = _desired("jdoe")
    current = {"jdoe": {"dn": "uid=jdoe,ou=people,dc=t",
                        "attrs": {**_src("jdoe"), "pwdLockout": ["locked"]}, "rdn_value": "jdoe"}}
    plan = partition(desired, current, cfg)
    assert plan["updates"][0]["changes"]["pwdLockout"][0][1] == ["active"]


def test_protected_users_untouched():
    assert is_protected("admin", ["admin"])
    assert not is_protected("jdoe", ["admin"])
    desired = _desired("admin")
    current = {"admin": {"dn": "uid=admin,ou=people,dc=t", "attrs": _src("admin"),
                         "rdn_value": "admin"}}
    plan = partition(desired, current, CFG_SYNC)
    assert plan == {"creates": [], "updates": [], "leavers": []}


def _fake_conn(entries, result_code=0):
    std = types.SimpleNamespace(paged_search=lambda **kw: iter(entries))
    return types.SimpleNamespace(
        extend=types.SimpleNamespace(standard=std),
        result={"result": result_code, "description": "test"},
    )


def test_fetch_source_keys_by_lowercase_rdn():
    cfg = {"source": {"search_base": "ou=x", "user_filter": "(uid=*)"},
           "target": {"rdn_attr": RDN}, "sync": CFG_SYNC}
    entries = [
        {"type": "searchResEntry", "attributes": _src("MixedCase1")},
        {"type": "searchResRef"},  # non-entry rows are ignored
    ]
    desired = fetch_source(_fake_conn(entries), cfg)
    assert set(desired) == {"mixedcase1"}
    assert desired["mixedcase1"][0] == "MixedCase1"  # original case preserved for the DN
    assert desired["mixedcase1"][1]["mail"] == ["MixedCase1@example.com"]


def test_paged_aborts_on_truncated_result():
    # A non-zero final search result (e.g. adminLimitExceeded=11) means the paged read was
    # truncated by a server limit; refuse rather than act on a partial view.
    cfg = {"source": {"search_base": "ou=x", "user_filter": "(uid=*)"},
           "target": {"rdn_attr": RDN}, "sync": CFG_SYNC}
    entries = [{"type": "searchResEntry", "attributes": _src("jdoe")}]
    try:
        fetch_source(_fake_conn(entries, result_code=11), cfg)
    except RuntimeError as e:
        assert "incomplete" in str(e).lower()
    else:
        raise AssertionError("expected RuntimeError on truncated (adminLimitExceeded) read")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("all passed")
