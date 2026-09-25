"""定义集群联防协同服务使用的版本化预案对象。

事件、信号与预占的对外视图按角色裁剪字段，统一以字典返回；预案是判定
升级级别、牵头人与响应时限的固定规则载体，使用不可变对象表达。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ResponseLevel:
    """描述预案中一个响应级别的牵头人角色与响应时限。"""

    level: str
    rank: int
    deadline_minutes: int
    commander_role: str
    display_name: str


@dataclass(frozen=True)
class ResponsePlan:
    """表示一个具体版本的联防响应预案。"""

    plan_id: str
    version: int
    name: str
    levels: tuple[ResponseLevel, ...]
    rules: tuple[dict[str, Any], ...]
    default_level: str
    append_window_minutes: int
    active: bool
    created_by: str
    created_at: str

    def level_by_name(self, name: str) -> ResponseLevel | None:
        for candidate in self.levels:
            if candidate.level == name:
                return candidate
        return None
