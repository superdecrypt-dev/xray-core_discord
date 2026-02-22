from pydantic import BaseModel
from typing import Any, Dict


class ActionRequest(BaseModel):
    action: str
    payload: Dict[str, Any] = {}
