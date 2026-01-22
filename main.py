# main.py

"""
DOCSTRING

Coordinates signature loading, file inspection, and result reporting.
"""

import json
import sys
from pathlib import Path
from inspector.loader import load_signatures, SignatureLoadError
from inspector.matcher import match_file_against_signatures, MatchError
from inspector.models import InspectionResult


def inspection_result_to_dict(result: InspectionResult) -> dict:
    return {
        "file_path": str(result.file_path),
        "observed_extension": result.observed_extension,
        "risk_level": result.risk_level,
        "summary": result.summary,
        "matches": [
            {
                "type_name": m.signature.type_name,
                "category": m.signature.category,
                "full_match": m.full_match,
                "partial_match": m.partial_match,
                "confidence_score": m.confidence_score,
                "reason": m.reason,
                "description": m.signature.description,
            }
            for m in result.matches
        ],
    }


def inspect_file(file_path: Path, signature_path: Path) -> InspectionResult:
    signatures = load_signatures(signature_path)
    match_results = match_file_against_signatures(file_path, signatures)

    observed_extension = file_path.suffix.lower()

    best_match = max(
        match_results,
        key=lambda m: m.confidence_score,
        default=None,
    )

    risk_level = "Unknown"
    summary = "No matching signatures detected"

    if best_match:
        sig = best_match.signature
        confidence = best_match.confidence_score

        extension_mismatch = (
            sig.allowed_extensions
            and observed_extension not in sig.allowed_extensions
        )

    if confidence >= 0.9:
        if extension_mismatch:
            risk_level = "High"
            summary = (
                f"File masquerading detected: "
                f"appears as {observed_extension}, "
                f"but identified as {sig.type_name}"
            )
        else:
            risk_level = "Low"
            summary = f"File identified as {sig.type_name}"

    elif confidence > 0:
        risk_level = "Medium"
        summary = f"Possible file type: {sig.type_name}"

    else:
        risk_level = "High"
        summary = "File type could not be confidently identified"

    return InspectionResult(
        file_path=file_path,
        observed_extension=observed_extension,
        matches=match_results,
        risk_level=risk_level,
        summary=summary,
    )


def main() -> None:
    # Flag handling
    json_output = False

    if "--json" in sys.argv:
        json_output = True
        sys.argv.remove("--json")

    # Arg validation
    if len(sys.argv) != 3:
        print("Usage: python main.py <file_to_inspect> <signature_json> [--json]")
        sys.exit(1)

    file_path = Path(sys.argv[1])
    signature_path = Path(sys.argv[2])

    try:
        result = inspect_file(file_path, signature_path)

        # Output selection
        if json_output:
            output = inspection_result_to_dict(result)
            print(json.dumps(output, indent=2))
        else:
            print("\n=== File Inspection Report ===")
            print(f"File: {result.file_path}")
            print(f"Observed Extension: {result.observed_extension}")
            print(f"Risk Level: {result.risk_level}")
            print(f"Summary: {result.summary}\n")

            for match in result.matches:
                if match.confidence_score > 0:
                    print(f"- {match.signature.type_name}")
                    print(f"  Confidence: {match.confidence_score}")
                    print(f"  Reason: {match.reason}")

    except SignatureLoadError as e:
        print(f"[ERROR] Signature loading failed: {e}")
        sys.exit(2)

    except MatchError as e:
        print(f"[ERROR] File inspection failed: {e}")
        sys.exit(3)


if __name__ == "__main__":
    main()
