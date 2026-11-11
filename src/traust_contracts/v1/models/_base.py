"""Shared Pydantic base for contract models."""

from __future__ import annotations

from typing import Any, ClassVar, Self

from pydantic import BaseModel, ConfigDict, SerializationInfo, SerializerFunctionWrapHandler
from pydantic.functional_serializers import model_serializer


class ContractModel(BaseModel):
    """Base for schema-derived models with JSON round-trip helpers."""

    # validate_assignment keeps field constraints (IsoTimestamp, enums) binding
    # after construction; without it `event.recorded_at = "banana"` is accepted.
    model_config = ConfigDict(extra="ignore", validate_assignment=True)
    explicit_null_fields: ClassVar[frozenset[str]] = frozenset()
    omit_unset_empty_fields: ClassVar[frozenset[str]] = frozenset()

    @model_serializer(mode="wrap")
    def _serialize(
        self, handler: SerializerFunctionWrapHandler, info: SerializationInfo
    ) -> dict[str, Any]:
        """Preserve explicitly supplied optional values during nested serialization."""
        data = handler(self)
        for name in self.omit_unset_empty_fields:
            if name not in self.model_fields_set and not getattr(self, name):
                data.pop(name, None)
        if info.exclude_none:
            for name in self.explicit_null_fields:
                if name not in self.model_fields_set or getattr(self, name) is not None:
                    continue
                if info.include is not None and name not in info.include:
                    continue
                if isinstance(info.exclude, set) and name in info.exclude:
                    continue
                if isinstance(info.exclude, dict) and info.exclude.get(name) in (True, ...):
                    continue
                data[name] = None
        return data

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls.model_validate(data)
