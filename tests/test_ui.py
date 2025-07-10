"""
Tests for the UI module.

This module tests the user interface components including menu handlers
and input/output functions.
"""

from unittest.mock import MagicMock, patch

from xprv_gen.constants import MenuChoice
from xprv_gen.ui import (
    get_menu_handlers,
    get_valid_choices,
    handle_derive_key_range,
    handle_derive_single_key,
    handle_encrypted_export,
    handle_export_keys,
    handle_generate_new_wallet,
    handle_load_from_mnemonic,
    handle_load_from_xprv,
    handle_save_json_format,
    handle_show_master_xpub,
    print_menu,
)


class TestPrintMenu:
    """Test class for menu printing functionality."""

    def test_print_menu_no_wallet(self, capsys) -> None:
        """Test that menu prints correctly with no wallet loaded."""
        mock_wallet = MagicMock()
        mock_wallet.is_wallet_loaded = False
        mock_wallet.has_derived_keys = False
        
        print_menu(mock_wallet)
        captured = capsys.readouterr()
        output = captured.out

        # Check that title is present
        assert "BSV HD Wallet Key Derivation Tool" in output

        # Check that only basic options are present
        assert "1. Load wallet from mnemonic seed phrase" in output
        assert "2. Load wallet from master private key (xprv)" in output
        assert "3. Generate new wallet" in output
        assert "9. Exit" in output

        # Check that advanced options are NOT present
        assert "4. Show master xpub" not in output
        assert "5. Derive single key" not in output
        assert "6. Derive key range" not in output
        assert "7. Export keys" not in output

    def test_print_menu_wallet_loaded(self, capsys) -> None:
        """Test that menu prints correctly with wallet loaded."""
        mock_wallet = MagicMock()
        mock_wallet.is_wallet_loaded = True
        mock_wallet.has_derived_keys = False
        
        print_menu(mock_wallet)
        captured = capsys.readouterr()
        output = captured.out

        # Check that wallet options are present
        assert "4. Show master xpub" in output
        assert "5. Derive single key from path" in output
        assert "6. Derive key range" in output
        
        # Check that export option is NOT present
        assert "7. Export keys" not in output

    def test_print_menu_keys_derived(self, capsys) -> None:
        """Test that menu prints correctly with keys derived."""
        mock_wallet = MagicMock()
        mock_wallet.is_wallet_loaded = True
        mock_wallet.has_derived_keys = True
        
        print_menu(mock_wallet)
        captured = capsys.readouterr()
        output = captured.out

        # Check that all options are present
        assert "1. Load wallet from mnemonic seed phrase" in output
        assert "4. Show master xpub" in output
        assert "5. Derive single key from path" in output
        assert "6. Derive key range" in output
        assert "7. Export keys" in output
        assert "9. Exit" in output


class TestMenuHandlers:
    """Test class for menu handler functions."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.mock_wallet = MagicMock()

    def test_get_menu_handlers(self) -> None:
        """Test that get_menu_handlers returns correct mapping."""
        handlers = get_menu_handlers()

        assert len(handlers) == 8  # All choices except EXIT
        assert MenuChoice.LOAD_FROM_MNEMONIC in handlers
        assert MenuChoice.LOAD_FROM_XPRV in handlers
        assert MenuChoice.GENERATE_NEW_WALLET in handlers
        assert MenuChoice.SHOW_MASTER_XPUB in handlers
        assert MenuChoice.DERIVE_SINGLE_KEY in handlers
        assert MenuChoice.DERIVE_KEY_RANGE in handlers
        assert MenuChoice.EXPORT_KEYS in handlers
        assert MenuChoice.EXIT not in handlers

    @patch("builtins.input", return_value="test mnemonic")
    def test_handle_load_from_mnemonic_success(self, mock_input) -> None:
        """Test successful mnemonic loading handler."""
        self.mock_wallet.load_from_mnemonic.return_value = True

        handle_load_from_mnemonic(self.mock_wallet)

        mock_input.assert_called_once_with("Enter mnemonic seed phrase: ")
        self.mock_wallet.load_from_mnemonic.assert_called_once_with("test mnemonic")

    @patch("builtins.input", return_value="  ")
    def test_handle_load_from_mnemonic_empty(self, mock_input, capsys) -> None:
        """Test mnemonic loading handler with empty input."""
        handle_load_from_mnemonic(self.mock_wallet)

        captured = capsys.readouterr()
        assert "✗ Empty mnemonic provided" in captured.out
        self.mock_wallet.load_from_mnemonic.assert_not_called()

    @patch("builtins.input", return_value="test xprv")
    def test_handle_load_from_xprv_success(self, mock_input) -> None:
        """Test successful xprv loading handler."""
        self.mock_wallet.load_from_xprv.return_value = True

        handle_load_from_xprv(self.mock_wallet)

        mock_input.assert_called_once_with("Enter master private key (xprv): ")
        self.mock_wallet.load_from_xprv.assert_called_once_with("test xprv")

    @patch("builtins.input", return_value="")
    def test_handle_load_from_xprv_empty(self, mock_input, capsys) -> None:
        """Test xprv loading handler with empty input."""
        handle_load_from_xprv(self.mock_wallet)

        captured = capsys.readouterr()
        assert "✗ Empty xprv provided" in captured.out
        self.mock_wallet.load_from_xprv.assert_not_called()

    @patch("builtins.input", side_effect=["1", "abc123"])
    def test_handle_generate_new_wallet_with_entropy(self, mock_input) -> None:
        """Test new wallet generation with custom entropy choice."""
        self.mock_wallet.generate_new_wallet.return_value = True

        handle_generate_new_wallet(self.mock_wallet)

        assert mock_input.call_count == 2
        self.mock_wallet.generate_new_wallet.assert_called_once_with("abc123")

    @patch("builtins.input", return_value="2")
    def test_handle_generate_new_wallet_secure_random(self, mock_input) -> None:
        """Test new wallet generation with secure random choice."""
        self.mock_wallet.generate_new_wallet_secure.return_value = True

        handle_generate_new_wallet(self.mock_wallet)

        mock_input.assert_called_once()
        self.mock_wallet.generate_new_wallet_secure.assert_called_once()

    def test_handle_show_master_xpub(self) -> None:
        """Test master xpub display handler."""
        self.mock_wallet.get_master_xpub.return_value = "xpub123"

        handle_show_master_xpub(self.mock_wallet)

        self.mock_wallet.get_master_xpub.assert_called_once()

    @patch("builtins.input", return_value="m/0/1")
    def test_handle_derive_single_key_success(self, mock_input) -> None:
        """Test successful single key derivation handler."""
        self.mock_wallet.derive_single_key.return_value = ("wif", "pubkey", "address")

        handle_derive_single_key(self.mock_wallet)

        mock_input.assert_called_once_with("Enter derivation path (e.g., m/0/1234): ")
        self.mock_wallet.derive_single_key.assert_called_once_with("m/0/1")

    @patch("builtins.input", return_value="")
    def test_handle_derive_single_key_empty(self, mock_input, capsys) -> None:
        """Test single key derivation handler with empty input."""
        handle_derive_single_key(self.mock_wallet)

        captured = capsys.readouterr()
        assert "✗ Empty path provided" in captured.out
        self.mock_wallet.derive_single_key.assert_not_called()

    @patch("builtins.input", side_effect=["m/44'/0'/0'", "0", "5"])
    def test_handle_derive_key_range_success(self, mock_input) -> None:
        """Test successful key range derivation handler."""
        self.mock_wallet.derive_keys_range.return_value = [
            ("m/44'/0'/0'/0/0", "wif0", "pub0", "addr0"),
            ("m/44'/0'/0'/0/1", "wif1", "pub1", "addr1"),
        ]

        handle_derive_key_range(self.mock_wallet)

        assert mock_input.call_count == 3
        self.mock_wallet.derive_keys_range.assert_called_once_with("m/44'/0'/0'", 0, 5)

    @patch("builtins.input", side_effect=["m/44'/0'/0'", "5", "0"])
    def test_handle_derive_key_range_invalid_range(self, mock_input, capsys) -> None:
        """Test key range derivation handler with invalid range."""
        handle_derive_key_range(self.mock_wallet)

        captured = capsys.readouterr()
        assert "✗ Invalid input" in captured.out
        self.mock_wallet.derive_keys_range.assert_not_called()

    @patch("builtins.input", side_effect=["", "0", "5"])
    def test_handle_derive_key_range_empty_path(self, mock_input, capsys) -> None:
        """Test key range derivation handler with empty path."""
        handle_derive_key_range(self.mock_wallet)

        captured = capsys.readouterr()
        assert "✗ Invalid input" in captured.out
        self.mock_wallet.derive_keys_range.assert_not_called()

    @patch("builtins.input", side_effect=["m/44'/0'/0'", "invalid", "5"])
    def test_handle_derive_key_range_invalid_indices(self, mock_input, capsys) -> None:
        """Test key range derivation handler with invalid indices."""
        handle_derive_key_range(self.mock_wallet)

        captured = capsys.readouterr()
        assert "✗ Invalid indices provided" in captured.out
        self.mock_wallet.derive_keys_range.assert_not_called()

    @patch("builtins.input", side_effect=["m/44'/0'/0'", "0", "invalid"])
    def test_handle_derive_key_range_invalid_end_index(
        self, mock_input, capsys
    ) -> None:
        """Test key range derivation handler with invalid end index."""
        handle_derive_key_range(self.mock_wallet)

        captured = capsys.readouterr()
        assert "✗ Invalid indices provided" in captured.out
        self.mock_wallet.derive_keys_range.assert_not_called()


class TestChoiceValidation:
    """Test class for choice validation functionality."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.mock_wallet = MagicMock()

    def test_get_valid_choices_no_wallet(self) -> None:
        """Test valid choices with no wallet loaded."""
        self.mock_wallet.is_wallet_loaded = False
        self.mock_wallet.has_derived_keys = False

        valid_choices = get_valid_choices(self.mock_wallet)

        expected_choices = ["1", "2", "3", "8", "9"]  # Basic options + decrypt + exit
        assert valid_choices == expected_choices

    def test_get_valid_choices_wallet_loaded(self) -> None:
        """Test valid choices with wallet loaded."""
        self.mock_wallet.is_wallet_loaded = True
        self.mock_wallet.has_derived_keys = False

        valid_choices = get_valid_choices(self.mock_wallet)

        expected_choices = ["1", "2", "3", "8", "9", "4", "5", "6"]  # Basic + wallet options
        assert valid_choices == expected_choices

    def test_get_valid_choices_keys_derived(self) -> None:
        """Test valid choices with keys derived."""
        self.mock_wallet.is_wallet_loaded = True
        self.mock_wallet.has_derived_keys = True

        valid_choices = get_valid_choices(self.mock_wallet)

        expected_choices = ["1", "2", "3", "8", "9", "4", "5", "6", "7"]  # All options
        assert valid_choices == expected_choices


class TestExportHandlers:
    """Test class for export handler functions."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.mock_wallet = MagicMock()

    def test_handle_export_keys_no_keys(self, capsys) -> None:
        """Test export handler with no keys available."""
        self.mock_wallet.has_derived_keys = False

        handle_export_keys(self.mock_wallet)

        captured = capsys.readouterr()
        assert "✗ No keys available to export" in captured.out

    @patch("builtins.input", side_effect=["5"])  # Back to main
    def test_handle_export_keys_back_to_main(self, mock_input) -> None:
        """Test export handler going back to main menu."""
        self.mock_wallet.has_derived_keys = True

        handle_export_keys(self.mock_wallet)

    @patch("builtins.input", return_value="test_filename")
    def test_handle_save_json_format_success(self, mock_input) -> None:
        """Test JSON format save handler."""
        self.mock_wallet.has_derived_keys = True
        self.mock_wallet.last_derived_keys = [("m/0/0", "wif", "pubkey", "address")]
        self.mock_wallet.save_keys_json_format.return_value = True

        handle_save_json_format(self.mock_wallet)

        self.mock_wallet.save_keys_json_format.assert_called_once_with(
            self.mock_wallet.last_derived_keys, "test_filename"
        )

    def test_handle_save_json_format_no_keys(self, capsys) -> None:
        """Test JSON format save handler with no keys."""
        self.mock_wallet.last_derived_keys = []

        handle_save_json_format(self.mock_wallet)

        captured = capsys.readouterr()
        assert "✗ No keys available to save" in captured.out

    def test_handle_encrypted_export_no_keys(self, capsys) -> None:
        """Test encrypted export handler with no keys available."""
        self.mock_wallet.has_derived_keys = False

        handle_encrypted_export(self.mock_wallet)

        captured = capsys.readouterr()
        assert "✗ No keys available to export" in captured.out
