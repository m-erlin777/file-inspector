# engine.py

"""
DOCSTRING

Analysis engine responsible for aggregating match results and producing a final inspection verdict for a file.
"""

from pathlib import Path
from typing import List, Optional
from inspector.models import(
    MatchResult,
    InspectionResult,
    MagicSignature
)

def select_best_signature(matches: List[MatchResult]) -> Optional[MatchResult]:

    """
    Select the best matching signature based on confidence score.
    Full matches preferred over partial.
    """

    if not matches:
        return None
    
    # Prefer full
    full_matches = [m for m in matches if m.full_match]

    candidates = full_matches if full_matches else matches

    return max(candidates, key=lambda m: m.confidence_score)


def evaluate_extension_mismatch(
        file_path: Path,
        signature: MagicSignature
) -> bool:
    # Determine whether file extension is contradictory

    if not signature.allowed_extensions:
        return False
    
    return file_path.suffix.lower() not in signature.allowed_extensions

def determine_risk_level(
        match: MatchResult,
        extension_mismatch: bool
) -> str:
    # Determine risk level based on match strength

    if match.full_match and extension_mismatch:
        return "HIGH"
    
    elif match.full_match:
        return "MEDIUM"
    
    elif match.partial_match:
        return "LOW"

    else:
        return "UNKNOWN"

def inspect_file(
        file_path: Path,
        matches: List[MatchResult]
) -> InspectionResult:
    # Produce final inspection verdict

    best_match = select_best_signature(matches)

    if not best_match:
        return InspectionResult(
            file_path = file_path,
            detected_type = None,
            confidence = 0.0,
            risk_level = "UNKNOWN",
            notes = "No file signature match"
        )

    extension_mismatch = evaluate_extension_mismatch(
        file_path,
        best_match.signature
    )

    risk_level = determine_risk_level(
        best_match,
        extension_mismatch
    )

    notes = []

    if best_match.partial_match:
        notes.append("Partial signature match detected")
    
    if extension_mismatch:
        notes.append("File extension does not match detected file type")

    return InspectionResult(
        file_path = file_path,
        detected_type = best_match.signature.type_name,
        confidence = best_match.confidence_score,
        risk_level = risk_level,
        notes = "; ".join(notes) if notes else "File signature verified"
    )
