#!/usr/bin/env python3

"""
Cryptography & Network Security Exam Toolkit

Functions:
1. Encrypt a file using Fernet authenticated encryption.
2. Decrypt the encrypted file.
3. Verify that decrypted data matches the original.
4. Calculate SHA-256 and detect later file changes.
5. Handle missing files and invalid inputs without crashing.

The encryption key must be stored outside the Git repository.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hexadecimal digest of a file."""
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def generate_key(key_path: Path) -> None:
    """Generate a Fernet encryption key."""
    if key_path.exists():
        raise FileExistsError(
            f"Key already exists: {key_path}"
        )

    key_path.parent.mkdir(parents=True, exist_ok=True)

    key_path.write_bytes(Fernet.generate_key())

    # Restrict permissions on systems supporting chmod.
    try:
        key_path.chmod(0o600)
    except OSError:
        pass

    print(
        f"Encryption key created outside the repository: "
        f"{key_path}"
    )


def load_key(key_path: Path) -> bytes:
    """Load and validate the encryption key."""

    if not key_path.is_file():
        raise FileNotFoundError(
            f"Key file not found: {key_path}"
        )

    key = key_path.read_bytes().strip()

    try:
        Fernet(key)
    except Exception as exc:
        raise ValueError(
            "Invalid Fernet encryption key."
        ) from exc

    return key


def encrypt_file(
    input_path: Path,
    output_path: Path,
    key_path: Path
) -> None:

    if not input_path.is_file():
        raise FileNotFoundError(
            f"Input file not found: {input_path}"
        )

    key = load_key(key_path)

    encrypted = Fernet(key).encrypt(
        input_path.read_bytes()
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    output_path.write_bytes(encrypted)

    print(
        f"Encrypted: {input_path} -> {output_path}"
    )


def decrypt_file(
    encrypted_path: Path,
    output_path: Path,
    key_path: Path,
    original_path: Path | None = None
) -> None:

    if not encrypted_path.is_file():
        raise FileNotFoundError(
            f"Encrypted file not found: {encrypted_path}"
        )

    key = load_key(key_path)

    try:
        decrypted = Fernet(key).decrypt(
            encrypted_path.read_bytes()
        )

    except InvalidToken as exc:
        raise ValueError(
            "Decryption failed: wrong key or "
            "encrypted file was modified."
        ) from exc

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    output_path.write_bytes(decrypted)

    print(
        f"Decrypted: {encrypted_path} -> {output_path}"
    )

    if original_path is not None:

        if not original_path.is_file():
            raise FileNotFoundError(
                f"Original file not found: {original_path}"
            )

        if original_path.read_bytes() == decrypted:

            print(
                "MATCH: decrypted contents are "
                "identical to the original file."
            )

        else:

            print(
                "MISMATCH: decrypted contents differ "
                "from the original file."
            )


def write_hash(
    file_path: Path,
    hash_path: Path
) -> None:

    if not file_path.is_file():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    digest = sha256_file(file_path)

    hash_path.write_text(
        digest + "\n",
        encoding="utf-8"
    )

    print(f"SHA-256: {digest}")

    print(
        f"Hash saved to: {hash_path}"
    )


def verify_hash(
    file_path: Path,
    hash_path: Path
) -> None:

    if not file_path.is_file():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    if not hash_path.is_file():
        raise FileNotFoundError(
            f"Hash file not found: {hash_path}"
        )

    expected = (
        hash_path
        .read_text(encoding="utf-8")
        .strip()
        .split()[0]
    )

    actual = sha256_file(file_path)

    print(
        f"Expected SHA-256: {expected}"
    )

    print(
        f"Actual SHA-256:   {actual}"
    )

    if actual == expected:

        print(
            "INTEGRITY OK: the file has not changed."
        )

    else:

        print(
            "INTEGRITY FAILED: the file has changed."
        )


def build_parser():

    parser = argparse.ArgumentParser(
        description=(
            "Cryptography and Network Security "
            "exam toolkit"
        )
    )

    sub = parser.add_subparsers(
        dest="command",
        required=True
    )

    # Generate encryption key
    key = sub.add_parser(
        "generate-key",
        help="Generate an encryption key"
    )

    key.add_argument(
        "--key",
        type=Path,
        required=True
    )

    # Encrypt
    enc = sub.add_parser(
        "encrypt",
        help="Encrypt a file"
    )

    enc.add_argument(
        "--input",
        type=Path,
        required=True
    )

    enc.add_argument(
        "--output",
        type=Path,
        required=True
    )

    enc.add_argument(
        "--key",
        type=Path,
        required=True
    )

    # Decrypt
    dec = sub.add_parser(
        "decrypt",
        help="Decrypt a file and compare it with original"
    )

    dec.add_argument(
        "--input",
        type=Path,
        required=True
    )

    dec.add_argument(
        "--output",
        type=Path,
        required=True
    )

    dec.add_argument(
        "--key",
        type=Path,
        required=True
    )

    dec.add_argument(
        "--original",
        type=Path,
        required=True
    )

    # SHA-256
    hsh = sub.add_parser(
        "hash",
        help="Calculate and save SHA-256"
    )

    hsh.add_argument(
        "--file",
        type=Path,
        required=True
    )

    hsh.add_argument(
        "--hash-file",
        type=Path,
        required=True
    )

    # Verify SHA-256
    verify = sub.add_parser(
        "verify",
        help="Verify a file against a saved SHA-256"
    )

    verify.add_argument(
        "--file",
        type=Path,
        required=True
    )

    verify.add_argument(
        "--hash-file",
        type=Path,
        required=True
    )

    return parser


def main() -> int:

    parser = build_parser()

    args = parser.parse_args()

    try:

        if args.command == "generate-key":

            generate_key(args.key)

        elif args.command == "encrypt":

            encrypt_file(
                args.input,
                args.output,
                args.key
            )

        elif args.command == "decrypt":

            decrypt_file(
                args.input,
                args.output,
                args.key,
                args.original
            )

        elif args.command == "hash":

            write_hash(
                args.file,
                args.hash_file
            )

        elif args.command == "verify":

            verify_hash(
                args.file,
                args.hash_file
            )

        return 0

    except (
        FileNotFoundError,
        PermissionError,
        ValueError,
        FileExistsError
    ) as exc:

        print(
            f"ERROR: {exc}",
            file=sys.stderr
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())