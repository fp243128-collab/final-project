"""Base tool definitions for DevSecOps crew tools."""
import importlib
from pydantic import BaseModel

_crewai_base_tool = None
try:
    _crewai_tools_mod = importlib.import_module("crewai.tools")
    _crewai_base_tool = getattr(_crewai_tools_mod, "BaseTool", None)
except Exception:
    pass

if _crewai_base_tool is not None:
    BaseTool = _crewai_base_tool
else:
    class BaseTool(BaseModel):  # type: ignore
        pass

__all__ = ["BaseTool"]
