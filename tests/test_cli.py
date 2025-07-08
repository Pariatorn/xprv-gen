"""
Tests for the CLI module.

This module tests the command-line interface functionality including
the main application loop and test mode.
"""

import sys
from unittest.mock import MagicMock, patch

from xprv_gen.cli import cli_main, main, run_test_mode
from xprv_gen.constants import MenuChoice


class TestRunTestMode:
    """Test class for test mode functionality."""

    @patch("xprv_gen.cli.HDWalletTool")
    def test_run_test_mode(self, mock_wallet_class, capsys) -> None:
        """Test that test mode runs all test scenarios."""
        mock_wallet = MagicMock()
        mock_wallet_class.return_value = mock_wallet

        # Setup mock return values
        mock_wallet.generate_new_wallet.return_value = True
        mock_wallet.get_master_xpub.return_value = "xpub123"
        mock_wallet.derive_single_key.return_value = ("wif", "pubkey", "address")
        mock_wallet.derive_keys_range.return_value = [
            ("m/44'/0'/0'/0/0", "wif0", "pub0", "addr0"),
            ("m/44'/0'/0'/0/1", "wif1", "pub1", "addr1"),
            ("m/44'/0'/0'/0/2", "wif2", "pub2", "addr2"),
        ]

        run_test_mode()

        # Verify all test scenarios were called
        mock_wallet.generate_new_wallet.assert_called_once_with(
            "cd9b819d9c62f0027116c1849e7d497f"
        )
        mock_wallet.get_master_xpub.assert_called_once()
        mock_wallet.derive_single_key.assert_called_once_with("m/0/1234")
        mock_wallet.derive_keys_range.assert_called_once_with("m/44'/0'/0'", 0, 2)

        # Check output
        captured = capsys.readouterr()
        assert "Running test mode..." in captured.out
        assert "Test 1: Generate New Wallet" in captured.out
        assert "Test 2: Master xpub" in captured.out
        assert "Test 3: Derive Single Key" in captured.out
        assert "Test 4: Derive Key Range" in captured.out


class TestMain:
    """Test class for main application loop."""

    @patch("xprv_gen.cli.HDWalletTool")
    @patch("xprv_gen.cli.get_menu_handlers")
    @patch("xprv_gen.cli.print_menu")
    @patch("builtins.input", side_effect=["7"])  # Choose exit
    def test_main_exit(
        self, mock_input, mock_print_menu, mock_get_handlers, mock_wallet_class, capsys
    ) -> None:
        """Test main loop with immediate exit."""
        mock_wallet = MagicMock()
        mock_wallet_class.return_value = mock_wallet
        mock_get_handlers.return_value = {}

        main()

        # Verify exit message
        captured = capsys.readouterr()
        assert "Goodbye!" in captured.out

        # Verify menu was printed
        mock_print_menu.assert_called()

    @patch("xprv_gen.cli.HDWalletTool")
    @patch("xprv_gen.cli.get_menu_handlers")
    @patch("xprv_gen.cli.print_menu")
    @patch(
        "builtins.input", side_effect=["1", "", "7"]
    )  # Choose option 1, press enter, then exit
    def test_main_valid_choice(
        self, mock_input, mock_print_menu, mock_get_handlers, mock_wallet_class
    ) -> None:
        """Test main loop with valid menu choice."""
        mock_wallet = MagicMock()
        mock_wallet_class.return_value = mock_wallet
        mock_handler = MagicMock()
        mock_get_handlers.return_value = {MenuChoice.LOAD_FROM_MNEMONIC: mock_handler}

        main()

        # Verify handler was called
        mock_handler.assert_called_once_with(mock_wallet)

        # Verify menu was printed at least twice (once for each iteration)
        assert mock_print_menu.call_count >= 2

    @patch("xprv_gen.cli.HDWalletTool")
    @patch("xprv_gen.cli.get_menu_handlers")
    @patch("xprv_gen.cli.print_menu")
    @patch(
        "builtins.input", side_effect=["invalid", "", "7"]
    )  # Invalid choice, press enter, then exit
    def test_main_invalid_choice(
        self, mock_input, mock_print_menu, mock_get_handlers, mock_wallet_class, capsys
    ) -> None:
        """Test main loop with invalid menu choice."""
        mock_wallet = MagicMock()
        mock_wallet_class.return_value = mock_wallet
        mock_get_handlers.return_value = {}

        main()

        # Verify error message
        captured = capsys.readouterr()
        assert "✗ Invalid choice. Please try again." in captured.out

    @patch("xprv_gen.cli.HDWalletTool")
    @patch("xprv_gen.cli.get_menu_handlers")
    @patch("xprv_gen.cli.print_menu")
    @patch(
        "builtins.input", side_effect=["8", "", "7"]
    )  # Invalid number, press enter, then exit
    def test_main_invalid_number(
        self, mock_input, mock_print_menu, mock_get_handlers, mock_wallet_class, capsys
    ) -> None:
        """Test main loop with invalid menu number."""
        mock_wallet = MagicMock()
        mock_wallet_class.return_value = mock_wallet
        mock_get_handlers.return_value = {}

        main()

        # Verify error message
        captured = capsys.readouterr()
        assert "✗ Invalid choice. Please try again." in captured.out


class TestCliMain:
    """Test class for CLI main entry point."""

    @patch("xprv_gen.cli.run_test_mode")
    @patch("xprv_gen.cli.main")
    def test_cli_main_test_mode(self, mock_main, mock_run_test_mode) -> None:
        """Test CLI main with test mode argument."""
        # Mock sys.argv to include test argument
        with patch.object(sys, "argv", ["script.py", "test"]):
            cli_main()

            mock_run_test_mode.assert_called_once()
            mock_main.assert_not_called()

    @patch("xprv_gen.cli.run_test_mode")
    @patch("xprv_gen.cli.main")
    def test_cli_main_normal_mode(self, mock_main, mock_run_test_mode) -> None:
        """Test CLI main with normal mode (no arguments)."""
        # Mock sys.argv to have no test argument
        with patch.object(sys, "argv", ["script.py"]):
            cli_main()

            mock_main.assert_called_once()
            mock_run_test_mode.assert_not_called()

    @patch("xprv_gen.cli.run_test_mode")
    @patch("xprv_gen.cli.main")
    def test_cli_main_other_arguments(self, mock_main, mock_run_test_mode) -> None:
        """Test CLI main with other arguments."""
        # Mock sys.argv to have other arguments
        with patch.object(sys, "argv", ["script.py", "other", "args"]):
            cli_main()

            mock_main.assert_called_once()
            mock_run_test_mode.assert_not_called()

    @patch("xprv_gen.cli.run_test_mode")
    @patch("xprv_gen.cli.main")
    def test_cli_main_test_mode_with_other_args(
        self, mock_main, mock_run_test_mode
    ) -> None:
        """Test CLI main with test mode and other arguments."""
        # Mock sys.argv to have test as first argument
        with patch.object(sys, "argv", ["script.py", "test", "other"]):
            cli_main()

            mock_run_test_mode.assert_called_once()
            mock_main.assert_not_called()
