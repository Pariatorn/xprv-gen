"""
Tests for the constants module.

This module tests all constants and enumerations used throughout the application.
"""

import pytest

from xprv_gen.constants import (
    ALPHABET,
    DERIVATION_PATH_PREFIX,
    HARDENED_KEY_FLAG,
    PBKDF2_ITERATIONS,
    SEED_LENGTH_32,
    SEED_LENGTH_64,
    TEST_MODE_ARG,
    MenuChoice,
)


class TestConstants:
    """Test class for constants validation."""

    def test_seed_lengths(self) -> None:
        """Test that seed length constants are correct."""
        assert SEED_LENGTH_64 == 64
        assert SEED_LENGTH_32 == 32
        assert SEED_LENGTH_64 == 2 * SEED_LENGTH_32

    def test_hardened_key_flag(self) -> None:
        """Test hardened key flag value."""
        assert HARDENED_KEY_FLAG == 0x80000000
        assert HARDENED_KEY_FLAG == 2147483648

    def test_derivation_path_prefix(self) -> None:
        """Test derivation path prefix."""
        assert DERIVATION_PATH_PREFIX == "m"
        assert isinstance(DERIVATION_PATH_PREFIX, str)
        assert len(DERIVATION_PATH_PREFIX) == 1

    def test_pbkdf2_iterations(self) -> None:
        """Test PBKDF2 iterations constant."""
        assert PBKDF2_ITERATIONS == 2048
        assert isinstance(PBKDF2_ITERATIONS, int)
        assert PBKDF2_ITERATIONS > 0

    def test_alphabet(self) -> None:
        """Test Base58 alphabet constant."""
        expected_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        assert ALPHABET == expected_alphabet
        assert len(ALPHABET) == 58
        assert isinstance(ALPHABET, str)

        # Test that there are no duplicate characters
        assert len(set(ALPHABET)) == len(ALPHABET)

        # Test that excluded characters are not present (0, O, I, l)
        excluded_chars = ["0", "O", "I", "l"]
        for char in excluded_chars:
            assert char not in ALPHABET

    def test_test_mode_arg(self) -> None:
        """Test test mode argument constant."""
        assert TEST_MODE_ARG == "test"
        assert isinstance(TEST_MODE_ARG, str)


class TestMenuChoice:
    """Test class for MenuChoice enumeration."""

    def test_menu_choice_values(self) -> None:
        """Test that all menu choice values are correct."""
        assert MenuChoice.LOAD_FROM_MNEMONIC.value == "1"
        assert MenuChoice.LOAD_FROM_XPRV.value == "2"
        assert MenuChoice.GENERATE_NEW_WALLET.value == "3"
        assert MenuChoice.SHOW_MASTER_XPUB.value == "4"
        assert MenuChoice.DERIVE_SINGLE_KEY.value == "5"
        assert MenuChoice.DERIVE_KEY_RANGE.value == "6"
        assert MenuChoice.EXIT.value == "7"

    def test_menu_choice_count(self) -> None:
        """Test that we have the expected number of menu choices."""
        assert len(MenuChoice) == 7

    def test_menu_choice_string_conversion(self) -> None:
        """Test that menu choices can be created from strings."""
        assert MenuChoice("1") == MenuChoice.LOAD_FROM_MNEMONIC
        assert MenuChoice("2") == MenuChoice.LOAD_FROM_XPRV
        assert MenuChoice("3") == MenuChoice.GENERATE_NEW_WALLET
        assert MenuChoice("4") == MenuChoice.SHOW_MASTER_XPUB
        assert MenuChoice("5") == MenuChoice.DERIVE_SINGLE_KEY
        assert MenuChoice("6") == MenuChoice.DERIVE_KEY_RANGE
        assert MenuChoice("7") == MenuChoice.EXIT

    def test_invalid_menu_choice(self) -> None:
        """Test that invalid menu choices raise ValueError."""
        with pytest.raises(ValueError):
            MenuChoice("8")
        with pytest.raises(ValueError):
            MenuChoice("0")
        with pytest.raises(ValueError):
            MenuChoice("invalid")
        with pytest.raises(ValueError):
            MenuChoice("")

    def test_menu_choice_uniqueness(self) -> None:
        """Test that all menu choice values are unique."""
        values = [choice.value for choice in MenuChoice]
        assert len(values) == len(set(values))
