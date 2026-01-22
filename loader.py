# loader.py

"""
DOCSTRING

Responsible for loading and validating magic number signatures from a JSON file and converting them into MagicSignature objects.
"""

import json
import binascii
from pathlib import Path
from typing import List
from inspector.models import MagicSignature


class SignatureLoadError(Exception):
    # Raised when signature file can't be loaded or validated.
    pass


def load_signatures(signature_path: Path) -> List[MagicSignature]:
    # Load magic number signatures from JSON files.
    # :param signature_path: Path to JSON signature file.
    # :return: List of MagicSignature objects.

    if not signature_path.exists():
        raise SignatureLoadError(f"Signature file not found: {signature_path}")

    try:
        with signature_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

    except json.JSONDecodeError as e:
        raise SignatureLoadError(f"Invalid JSON format: {e}")

    if "signatures" not in data or not isinstance(data["signatures"], list):
        raise SignatureLoadError("Signature file must contain a 'signatures' list")

    signatures: List[MagicSignature] = []

    for entry in data["signatures"]:
        try:
            magic_hex = entry["magic_value"]
            magic_bytes = binascii.unhexlify(magic_hex)

            match_length = int(entry["match_length"])

            # Loader invariant: declared match_length must equal magic byte length
            
            if len(magic_bytes) != match_length:
                raise SignatureLoadError(
                    f"Invalid signature for '{entry.get('type_name', 'unknown')}': "
                    f"match_length ({match_length}) does not match "
                    f"magic_bytes length ({len(magic_bytes)})"
                )

            signature = MagicSignature(
                type_name = entry["type_name"],
                category = entry["category"],
                magic_bytes = magic_bytes,
                offset = int(entry["offset"]),
                match_length = match_length,
                confidence_weight = float(entry["confidence_weight"]),
                allowed_extensions = entry.get("allowed_extensions", []),
                description = entry.get("description", ""),
                revision = entry.get("revision"),
            )

            signatures.append(signature)

        except KeyError as e:
            raise SignatureLoadError(f"Missing required signature field: {e}")
        except (ValueError, binascii.Error) as e:
            raise SignatureLoadError(f"Invalid signature value: {e}")

    return signatures
