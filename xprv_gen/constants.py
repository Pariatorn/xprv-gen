"""
Constants and enumerations for the BSV HD Wallet Key Derivation Tool.

This module contains all the constants, magic numbers, and enumerations
used throughout the application.
"""

from enum import Enum

# Seed and key constants
SEED_LENGTH_64 = 64
SEED_LENGTH_32 = 32
HARDENED_KEY_FLAG = 0x80000000
DERIVATION_PATH_PREFIX = "m"
PBKDF2_ITERATIONS = 2048

# Base58 alphabet for Bitcoin
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Test mode identifier
TEST_MODE_ARG = "test"


class MenuChoice(Enum):
    """Menu choice enumeration for the CLI interface."""

    LOAD_FROM_MNEMONIC = "1"
    LOAD_FROM_XPRV = "2"
    GENERATE_NEW_WALLET = "3"
    SHOW_MASTER_XPUB = "4"
    DERIVE_SINGLE_KEY = "5"
    DERIVE_KEY_RANGE = "6"
    EXIT = "7"
