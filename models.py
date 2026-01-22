# models.py

"""
DOCSTRING

Defines core data models for the file inspection engine.
Classes represent structured data.
"""

from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path

@dataclass(frozen=True)
class MagicSignature:

    # Represents a single magic-number-based file signature.

    type_name: str
    category: str
    magic_bytes: bytes
    offset: int
    match_length: int
    confidence_weight: float
    allowed_extensions: List[str]
    description: str
    revision: Optional[int] = None

@dataclass
class MatchResult:
    
    # Represents the result of matching a file against a signature.

    signature: MagicSignature
    full_match: bool
    partial_match: bool
    confidence_score: float
    reason: str

@dataclass
class InspectionResult:

    # Represents the final inspection result for a file.

    file_path: Path
    observed_extension: str
    matches: List[MatchResult]
    risk_level: str
    summary: str
