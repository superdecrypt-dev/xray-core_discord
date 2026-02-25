from typing import Any

from pydantic import BaseModel, Field


class ActionRequest(BaseModel):
    action: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)


class ActionResponse(BaseModel):
    ok: bool
    code: str
    title: str
    message: str
    data: dict[str, Any] = Field(default_factory=dict)
