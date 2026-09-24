"""Pydantic schemas for the audit API."""

from __future__ import annotations

from typing import Annotated, List, Optional

from pydantic import BaseModel, Field

from .bidi import RiskLevel


class AuditRequest(BaseModel):
    text: str = Field(..., description="Text to audit. Sent verbatim; never rewritten.")
    filename: Optional[str] = Field(
        default=None,
        max_length=4096,
        description="Optional source file name for later lookup.",
    )


class AuditCreated(BaseModel):
    id: int
    risk_level: RiskLevel
    stored: bool = True
    result: dict


class CompareRequest(BaseModel):
    before_id: int = Field(
        ..., ge=1, description="ID of the earlier audit record (baseline)."
    )
    after_id: int = Field(
        ..., ge=1, description="ID of the later audit record (regression)."
    )


class DiffAuditRequest(BaseModel):
    diff: str = Field(
        ...,
        description=(
            "Unified diff text (multi-file, multi-hunk). Only added lines "
            "(those starting with '+') are audited; headers, removed and "
            "context lines are ignored."
        ),
    )


class JsonAuditRequest(BaseModel):
    document: str = Field(
        ...,
        description=(
            "Raw JSON document text. Parsed strictly (RFC 8259): duplicate "
            "object keys and malformed input are rejected with 422. Every "
            "string value (object values and array elements, never object "
            "keys) is audited for bidi controls."
        ),
    )
    filename: Optional[str] = Field(
        default=None,
        max_length=4096,
        description=(
            "Optional document name. Stored records are named "
            "'<filename>#<json-pointer>' ('#<json-pointer>' when omitted)."
        ),
    )


class GateRule(BaseModel):
    template: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description=(
            "File path template split on '/'. '*' matches any characters "
            "within a single segment (never a '/'); '**' matches zero or "
            "more whole segments; other characters are literal."
        ),
    )
    max_risk: RiskLevel = Field(
        ...,
        description="Highest risk allowed for matching paths "
        "(info|low|medium|high|critical).",
    )


class GateRequest(BaseModel):
    ids: List[Annotated[int, Field(ge=1)]] = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Stored audit record IDs to gate, in response order.",
    )
    default_max_risk: RiskLevel = Field(
        ...,
        description=(
            "Default highest allowed risk for records without a file name or "
            "with a path no rule matches."
        ),
    )
    rules: List[GateRule] = Field(
        default_factory=list,
        max_length=500,
        description=(
            "Ordered path rules. For a path the rule with the most fixed "
            "segments wins; ties prefer the longer template, then the rule "
            "earlier in this list."
        ),
    )

