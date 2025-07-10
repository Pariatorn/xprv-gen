"""
Tests for the constants module.

This module tests all constants and enumerations used throughout the application.
"""

import pytest

from xprv_gen.constants import (
    ALPHABET,
    CSV_EXTENSION,
    DEFAULT_SAVE_FILENAME,
    DERIVATION_PATH_PREFIX,
    DETAILED_CSV_HEADER,
    HARDENED_KEY_FLAG,
    INITIAL_MENU_CHOICES,
    KEYS_DERIVED_CHOICES,
    PBKDF2_ITERATIONS,
    SEED_LENGTH_32,
    SEED_LENGTH_64,
    SIMPLE_CSV_HEADER,
    TEST_MODE_ARG,
    WALLET_LOADED_CHOICES,
    EncryptedExportChoice,
    ExportChoice,
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
        assert MenuChoice.EXPORT_KEYS.value == "7"
        assert MenuChoice.EXIT.value == "9"

    def test_menu_choice_count(self) -> None:
        """Test that we have the expected number of menu choices."""
        assert len(MenuChoice) == 9

    def test_menu_choice_string_conversion(self) -> None:
        """Test that menu choices can be created from strings."""
        assert MenuChoice("1") == MenuChoice.LOAD_FROM_MNEMONIC
        assert MenuChoice("2") == MenuChoice.LOAD_FROM_XPRV
        assert MenuChoice("3") == MenuChoice.GENERATE_NEW_WALLET
        assert MenuChoice("4") == MenuChoice.SHOW_MASTER_XPUB
        assert MenuChoice("5") == MenuChoice.DERIVE_SINGLE_KEY
        assert MenuChoice("6") == MenuChoice.DERIVE_KEY_RANGE
        assert MenuChoice("7") == MenuChoice.EXPORT_KEYS
        assert MenuChoice("9") == MenuChoice.EXIT

    def test_invalid_menu_choice(self) -> None:
        """Test that invalid menu choices raise ValueError."""
        with pytest.raises(ValueError):
            MenuChoice("10")  # Use a choice that doesn't exist
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


class TestSaveConstants:
    """Test class for save-related constants."""

    def test_csv_headers(self) -> None:
        """Test CSV header constants."""
        assert SIMPLE_CSV_HEADER == "address,key"
        assert DETAILED_CSV_HEADER == "derivation,address,key"

    def test_save_filename_constants(self) -> None:
        """Test save filename constants."""
        assert DEFAULT_SAVE_FILENAME == "wallet_keys"
        assert CSV_EXTENSION == ".csv"


class TestExportChoice:
    """Test class for ExportChoice enumeration."""

    def test_export_choice_values(self) -> None:
        """Test that all export choice values are correct."""
        assert ExportChoice.EXPORT_SIMPLE_CSV.value == "1"
        assert ExportChoice.EXPORT_DETAILED_CSV.value == "2"
        assert ExportChoice.EXPORT_JSON.value == "3"
        assert ExportChoice.EXPORT_ENCRYPTED.value == "4"
        assert ExportChoice.BACK_TO_MAIN.value == "5"

    def test_export_choice_count(self) -> None:
        """Test that we have the expected number of export choices."""
        assert len(ExportChoice) == 5


class TestEncryptedExportChoice:
    """Test class for EncryptedExportChoice enumeration."""

    def test_encrypted_export_choice_values(self) -> None:
        """Test that all encrypted export choice values are correct."""
        assert EncryptedExportChoice.ENCRYPT_SIMPLE_CSV.value == "1"
        assert EncryptedExportChoice.ENCRYPT_DETAILED_CSV.value == "2"
        assert EncryptedExportChoice.ENCRYPT_JSON.value == "3"
        assert EncryptedExportChoice.BACK_TO_EXPORT.value == "4"

    def test_encrypted_export_choice_count(self) -> None:
        """Test that we have the expected number of encrypted export choices."""
        assert len(EncryptedExportChoice) == 4


class TestMenuConfiguration:
    """Test class for menu configuration lists."""

    def test_initial_menu_choices(self) -> None:
        """Test initial menu choices configuration."""
        assert len(INITIAL_MENU_CHOICES) == 5
        assert MenuChoice.LOAD_FROM_MNEMONIC in INITIAL_MENU_CHOICES
        assert MenuChoice.LOAD_FROM_XPRV in INITIAL_MENU_CHOICES
        assert MenuChoice.GENERATE_NEW_WALLET in INITIAL_MENU_CHOICES
        assert MenuChoice.EXIT in INITIAL_MENU_CHOICES

    def test_wallet_loaded_choices(self) -> None:
        """Test wallet loaded menu choices configuration."""
        assert len(WALLET_LOADED_CHOICES) == 3
        assert MenuChoice.SHOW_MASTER_XPUB in WALLET_LOADED_CHOICES
        assert MenuChoice.DERIVE_SINGLE_KEY in WALLET_LOADED_CHOICES
        assert MenuChoice.DERIVE_KEY_RANGE in WALLET_LOADED_CHOICES

    def test_keys_derived_choices(self) -> None:
        """Test keys derived menu choices configuration."""
        assert len(KEYS_DERIVED_CHOICES) == 1
        assert MenuChoice.EXPORT_KEYS in KEYS_DERIVED_CHOICES
