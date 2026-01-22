# matcher.py

"""
DOCSTRING

Compares file header bytes against known magic signatures and
produces structured match assessments.
"""

from pathlib import Path
from typing import List
from inspector.models import MagicSignature, MatchResult
from inspector.reader import read_bytes, FileReadError


class MatchError(Exception):
    # Raised when a file can't be matched safely.

    pass


def _calculate_partial_match(
    observed: bytes,
    expected: bytes
) -> int:
    
    # Calculate how many leading bytes match between observed and expected.
    
    match_count = 0
    for o, e in zip(observed, expected):
        if o == e:
            match_count += 1
        else:
            break
    return match_count


def match_file_against_signatures(
    file_path: Path,
    signatures: List[MagicSignature]
) -> List[MatchResult]:
    """
    Attempt to match a file against all provided magic signatures.

    :param file_path: Path to the file being inspected
    :param signatures: Loaded magic signatures
    :return: List of MatchResult objects
    """

    results: List[MatchResult] = []

    for sig in signatures:
        try:
            observed_bytes = read_bytes(
                file_path=file_path,
                offset=sig.offset,
                length=sig.match_length
            )

            if observed_bytes is None:
                results.append(
                    MatchResult(
                        signature=sig,
                        full_match=False,
                        partial_match=False,
                        confidence_score=0.0,
                        reason="Unable to read required bytes"
                    )
                )
                continue

            expected_bytes = sig.magic_bytes

            full_match = observed_bytes == expected_bytes

            partial_count = _calculate_partial_match(
                observed_bytes,
                expected_bytes
            )

            partial_match = (
                not full_match and partial_count > 0
            )

            confidence_score = 0.0
            reason = "No matching bytes detected"

            if full_match:
                confidence_score = sig.confidence_weight
                reason = "Exact magic number match"

            elif partial_match:
                ratio = partial_count / sig.match_length
                confidence_score = round(
                    ratio * sig.confidence_weight,
                    3
                )
                reason = (
                    f"Partial magic match "
                    f"({partial_count}/{sig.match_length} bytes)"
                )

            results.append(
                MatchResult(
                    signature=sig,
                    full_match=full_match,
                    partial_match=partial_match,
                    confidence_score=confidence_score,
                    reason=reason
                )
            )

        except FileReadError as e:
            raise MatchError(f"Failed to inspect {file_path}: {e}")

    return results
