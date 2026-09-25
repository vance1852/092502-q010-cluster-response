"""事件分级、关联与分类的纯领域规则。

规则只依赖上报信号的脱敏字段，不接触任何企业敏感生产数据：

- 单厂故障：同一企业场所的重复告警，且没有可关联的共用供应代码；
- 共用供应异常：多个不同企业上报了相同的共用供应代码；
- 区域性风险：覆盖三个及以上不同企业，或两个企业中至少一方为高严重度。
"""

from __future__ import annotations

from typing import Any

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
SEVERITY_VALUES = frozenset(SEVERITY_ORDER)

CLASSIFICATION_SINGLE = "single_fault"
CLASSIFICATION_SHARED = "shared_supply"
CLASSIFICATION_REGIONAL = "regional"


def normalize_severity(value: str) -> str:
    """校验并归一化严重度。"""

    value = str(value).strip().lower()
    if value not in SEVERITY_VALUES:
        raise ValueError("severity 必须是 low、medium 或 high")
    return value


def normalize_supply_code(value: Any) -> str | None:
    """共用供应代码缺省时为空，否则去除首尾空白。"""

    if value is None:
        return None
    text = str(value).strip()
    return text or None


def classify(org_count: int, max_severity: str, shared_supply: bool) -> str:
    """依据覆盖企业数、最高严重度与共用供应标记判定事件类别。"""

    if org_count >= 3 or (org_count >= 2 and SEVERITY_ORDER[max_severity] >= 3):
        return CLASSIFICATION_REGIONAL
    if shared_supply and org_count >= 2:
        return CLASSIFICATION_SHARED
    return CLASSIFICATION_SINGLE


def resolve_level(rule: dict[str, Any], classification: str,
                  max_severity: str, org_count: int) -> int:
    """按版本化预案规则计算升级级别。

    规则按声明顺序求值，第一条全部条件命中的规则生效；没有命中时使用
    ``default_level``。规则引用的分类必须与实际分类一致，且不能要求比
    实际更多的覆盖企业数。
    """

    default_level = int(rule.get("default_level", 1))
    for entry in rule.get("rules", []):
        if entry.get("classification") not in (None, classification):
            continue
        if "min_orgs" in entry and org_count < int(entry["min_orgs"]):
            continue
        if "min_severity" in entry:
            if SEVERITY_ORDER[max_severity] < SEVERITY_ORDER[entry["min_severity"]]:
                continue
        return int(entry["level"])
    return default_level


def aggregate_signals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """把已持久化的信号行汇总为分级所需的事实。"""

    orgs: set[str] = set()
    sites: set[str] = set()
    code_orgs: dict[str, set[str]] = {}
    severity = "low"
    for row in rows:
        orgs.add(row["organization_id"])
        sites.add(row["site_id"])
        if row.get("supply_code"):
            code_orgs.setdefault(row["supply_code"], set()).add(row["organization_id"])
        if SEVERITY_ORDER[row["severity"]] > SEVERITY_ORDER[severity]:
            severity = row["severity"]
    shared_codes = sorted(code for code, owners in code_orgs.items() if len(owners) >= 2)
    return {
        "org_count": len(orgs),
        "site_count": len(sites),
        "max_severity": severity,
        "supply_codes": sorted(code_orgs),
        "shared_supply_codes": shared_codes,
    }
