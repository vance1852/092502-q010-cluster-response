"""家具产业集群协作资料服务的服务端基础包。"""

from .service import DomainService
from .incidents import (
    CLASSIFICATION_REGIONAL,
    CLASSIFICATION_SHARED,
    CLASSIFICATION_SINGLE,
    classify,
    resolve_level,
)

__all__ = [
    "DomainService",
    "CLASSIFICATION_REGIONAL",
    "CLASSIFICATION_SHARED",
    "CLASSIFICATION_SINGLE",
    "classify",
    "resolve_level",
]
