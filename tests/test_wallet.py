"""
Tests for the wallet module.

This module tests the core HDWalletTool functionality including mnemonic loading,
xprv loading, key derivation, and wallet generation.
"""

from unittest.mock import MagicMock, mock_open, patch

import pytest

from xprv_gen.exceptions import (
    DerivationPathError,
    InvalidMnemonicError,
    InvalidXprvError,
    WalletNotLoadedError,
)
from xprv_gen.wallet import HDWalletTool


class TestHDWalletTool:
    """Test class for HDWalletTool functionality."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.wallet = HDWalletTool()
        self.test_mnemonic = (
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about"
        )
        self.test_xprv = (
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWU"
            "tg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        )
        self.test_entropy = "cd9b819d9c62f0027116c1849e7d497f"

    def test_init(self) -> None:
        """Test wallet initialization."""
        assert self.wallet.master_xprv is None
        assert self.wallet.mnemonic is None

    @patch("xprv_gen.wallet.bsv.hd.validate_mnemonic")
    @patch("xprv_gen.wallet.bsv.hd.seed_from_mnemonic")
    @patch("xprv_gen.wallet.bsv.hd.master_xprv_from_seed")
    def test_load_from_mnemonic_bip39_success(
        self, mock_master_xprv, mock_seed, mock_validate
    ) -> None:
        """Test successful loading from BIP39 mnemonic."""
        # Setup mocks
        mock_validate.return_value = True
        mock_seed.return_value = b"a" * 64
        mock_xprv = MagicMock()
        mock_master_xprv.return_value = mock_xprv

        # Test
        result = self.wallet.load_from_mnemonic(self.test_mnemonic)

        # Assertions
        assert result == "BIP39"
        assert self.wallet.master_xprv == mock_xprv
        assert self.wallet.mnemonic == self.test_mnemonic
        mock_validate.assert_called_once_with(self.test_mnemonic)
        mock_seed.assert_called_once_with(self.test_mnemonic)
        mock_master_xprv.assert_called_once()

    @patch("xprv_gen.wallet.bsv.hd.validate_mnemonic")
    @patch("xprv_gen.wallet.hashlib.pbkdf2_hmac")
    @patch("xprv_gen.wallet.hmac.new")
    @patch("xprv_gen.wallet.bsv.hd.master_xprv_from_seed")
    def test_load_from_mnemonic_electrum_success(
        self, mock_master_xprv, mock_hmac, mock_pbkdf2, mock_validate
    ) -> None:
        """Test successful loading from Electrum mnemonic."""
        # Setup mocks
        mock_validate.side_effect = Exception("Not BIP39")
        mock_digest = MagicMock()
        mock_digest.digest.return_value = (
            b"\x01" + b"a" * 63
        )  # Valid Electrum signature
        mock_hmac.return_value = mock_digest
        mock_pbkdf2.return_value = b"a" * 64
        mock_xprv = MagicMock()
        mock_master_xprv.return_value = mock_xprv

        # Test
        result = self.wallet.load_from_mnemonic(self.test_mnemonic)

        # Assertions
        assert result == "Electrum"
        assert self.wallet.master_xprv == mock_xprv
        assert self.wallet.mnemonic == self.test_mnemonic
        mock_pbkdf2.assert_called_once()
        mock_master_xprv.assert_called_once()

    @patch("xprv_gen.wallet.bsv.hd.validate_mnemonic")
    @patch("xprv_gen.wallet.bsv.hd.master_xprv_from_seed")
    def test_load_from_mnemonic_failure(self, mock_master_xprv, mock_validate) -> None:
        """Test failure loading from mnemonic."""
        mock_validate.side_effect = Exception("Invalid mnemonic")
        mock_master_xprv.side_effect = Exception("Failed to create master xprv")

        with pytest.raises(InvalidMnemonicError):
            self.wallet.load_from_mnemonic("invalid mnemonic")

        assert self.wallet.master_xprv is None
        assert self.wallet.mnemonic is None

    def test_load_from_mnemonic_empty(self) -> None:
        """Test loading from empty mnemonic."""
        with pytest.raises(InvalidMnemonicError, match="Empty mnemonic provided"):
            self.wallet.load_from_mnemonic("")

        with pytest.raises(InvalidMnemonicError, match="Empty mnemonic provided"):
            self.wallet.load_from_mnemonic("   ")

    @patch("xprv_gen.wallet.bsv.hd.Xprv")
    def test_load_from_xprv_success(self, mock_xprv_class) -> None:
        """Test successful loading from xprv string."""
        mock_xprv = MagicMock()
        mock_xprv_class.return_value = mock_xprv

        result = self.wallet.load_from_xprv(self.test_xprv)

        assert result == "Extended Private Key"
        assert self.wallet.master_xprv == mock_xprv
        assert self.wallet.mnemonic is None
        mock_xprv_class.assert_called_once_with(self.test_xprv)

    @patch("xprv_gen.wallet.bsv.hd.master_xprv_from_seed")
    def test_load_from_xprv_hex_success(self, mock_master_xprv) -> None:
        """Test successful loading from hex private key."""
        hex_key = "a" * 64  # 64 character hex string
        mock_xprv = MagicMock()
        mock_master_xprv.return_value = mock_xprv

        result = self.wallet.load_from_xprv(hex_key)

        assert result == "Hex Seed"
        assert self.wallet.master_xprv == mock_xprv
        assert self.wallet.mnemonic is None

    def test_load_from_xprv_failure(self) -> None:
        """Test failure loading from xprv."""
        with pytest.raises(InvalidXprvError):
            self.wallet.load_from_xprv("invalid_xprv")

        assert self.wallet.master_xprv is None
        assert self.wallet.mnemonic is None

    def test_load_from_xprv_empty(self) -> None:
        """Test loading from empty xprv."""
        with pytest.raises(InvalidXprvError, match="Empty xprv string provided"):
            self.wallet.load_from_xprv("")

        with pytest.raises(InvalidXprvError, match="Empty xprv string provided"):
            self.wallet.load_from_xprv("   ")

    def test_get_master_xpub_no_wallet(self) -> None:
        """Test getting master xpub with no wallet loaded."""
        with pytest.raises(WalletNotLoadedError, match="No wallet loaded"):
            self.wallet.get_master_xpub()

    def test_get_master_xpub_success(self) -> None:
        """Test successful getting master xpub."""
        mock_xprv = MagicMock()
        mock_xpub = MagicMock()
        mock_xpub.__str__ = MagicMock(return_value="xpub123")
        mock_xprv.xpub.return_value = mock_xpub
        self.wallet.master_xprv = mock_xprv

        result = self.wallet.get_master_xpub()

        assert result == "xpub123"
        mock_xprv.xpub.assert_called_once()

    def test_derive_single_key_no_wallet(self) -> None:
        """Test deriving single key with no wallet loaded."""
        with pytest.raises(WalletNotLoadedError, match="No wallet loaded"):
            self.wallet.derive_single_key("m/0/1")

    def test_derive_single_key_invalid_path(self) -> None:
        """Test deriving single key with invalid path."""
        mock_xprv = MagicMock()
        self.wallet.master_xprv = mock_xprv

        with pytest.raises(DerivationPathError):
            self.wallet.derive_single_key("invalid/path")

    def test_derive_single_key_success(self) -> None:
        """Test successful single key derivation."""
        # Setup mocks for chained derivation: master -> child1 -> child2
        mock_xprv = MagicMock()
        mock_child1 = MagicMock()
        mock_child2 = MagicMock()
        mock_private_key = MagicMock()
        mock_public_key = MagicMock()

        # Set up the chain: master.ckd(0) -> child1.ckd(1) -> child2
        mock_xprv.ckd.return_value = mock_child1
        mock_child1.ckd.return_value = mock_child2

        # Set up the final child key
        mock_child2.private_key.return_value = mock_private_key
        mock_child2.public_key.return_value = mock_public_key
        mock_child2.address.return_value = "1ABC123"
        mock_private_key.wif.return_value = (
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        )
        mock_public_key.hex.return_value = "abcdef123456"

        self.wallet.master_xprv = mock_xprv

        result = self.wallet.derive_single_key("m/0/1")

        assert result is not None
        derivation_path, wif, pub_hex, address = result
        assert derivation_path == "m/0/1"
        assert wif == "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        assert pub_hex == "abcdef123456"
        assert address == "1ABC123"

    def test_derive_single_key_hardened(self) -> None:
        """Test deriving single key with hardened derivation."""
        # Setup mocks for chained derivation: master -> child1 -> child2 -> child3
        mock_xprv = MagicMock()
        mock_child1 = MagicMock()
        mock_child2 = MagicMock()
        mock_child3 = MagicMock()
        mock_private_key = MagicMock()
        mock_public_key = MagicMock()

        # Set up the chain: master.ckd(44') -> child1.ckd(0') -> child2.ckd(0')
        mock_xprv.ckd.return_value = mock_child1
        mock_child1.ckd.return_value = mock_child2
        mock_child2.ckd.return_value = mock_child3

        # Set up the final child key
        mock_child3.private_key.return_value = mock_private_key
        mock_child3.public_key.return_value = mock_public_key
        mock_child3.address.return_value = "1ABC123"
        mock_private_key.wif.return_value = (
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        )
        mock_public_key.hex.return_value = "abcdef123456"

        self.wallet.master_xprv = mock_xprv

        result = self.wallet.derive_single_key("m/44'/0'/0'")

        assert result is not None
        # Check that derivation was called on each level (3 times total)
        assert mock_xprv.ckd.call_count == 1
        assert mock_child1.ckd.call_count == 1
        assert mock_child2.ckd.call_count == 1

    def test_derive_keys_range_no_wallet(self) -> None:
        """Test deriving key range with no wallet loaded."""
        result = self.wallet.derive_keys_range("m/44'/0'/0'", 0, 2)

        assert result == []

    @patch("xprv_gen.wallet.bsv.hd.derive_xprvs_from_mnemonic")
    def test_derive_keys_range_with_mnemonic(self, mock_derive_xprvs) -> None:
        """Test deriving key range with mnemonic available."""
        # Setup mocks
        mock_key1 = MagicMock()
        mock_key2 = MagicMock()
        mock_keys = [mock_key1, mock_key2]

        mock_derive_xprvs.return_value = mock_keys

        # Setup key1 mocks
        mock_key1.private_key.return_value.wif.return_value = "wif1"
        mock_key1.public_key.return_value.hex.return_value = "pub1"
        mock_key1.address.return_value = "addr1"

        # Setup key2 mocks
        mock_key2.private_key.return_value.wif.return_value = "wif2"
        mock_key2.public_key.return_value.hex.return_value = "pub2"
        mock_key2.address.return_value = "addr2"

        self.wallet.mnemonic = self.test_mnemonic
        mock_xprv = MagicMock()
        self.wallet.master_xprv = mock_xprv

        result = self.wallet.derive_keys_range("m/44'/0'/0'", 0, 1)

        assert len(result) == 2
        assert result[0] == ("m/44'/0'/0'/0/0", "wif1", "pub1", "addr1")
        assert result[1] == ("m/44'/0'/0'/0/1", "wif2", "pub2", "addr2")

    @patch("xprv_gen.wallet.bsv.hd.mnemonic_from_entropy")
    def test_generate_new_wallet_success(self, mock_mnemonic_from_entropy) -> None:
        """Test successful new wallet generation."""
        mock_mnemonic_from_entropy.return_value = self.test_mnemonic

        with patch.object(
            self.wallet, "load_from_mnemonic", return_value=True
        ) as mock_load:
            result = self.wallet.generate_new_wallet(self.test_entropy)

            assert result is True
            mock_mnemonic_from_entropy.assert_called_once_with(self.test_entropy)
            mock_load.assert_called_once_with(self.test_mnemonic)

    @patch("xprv_gen.wallet.bsv.hd.mnemonic_from_entropy")
    def test_generate_new_wallet_failure(self, mock_mnemonic_from_entropy) -> None:
        """Test failure in new wallet generation."""
        mock_mnemonic_from_entropy.side_effect = Exception("Generation failed")

        result = self.wallet.generate_new_wallet(self.test_entropy)

        assert result is False

    def test_base58_decode_basic(self) -> None:
        """Test basic base58 decoding."""
        # Test with simple case
        result = self.wallet._base58_decode("1")
        assert result == b"\x00"

        # Test with another simple case
        result = self.wallet._base58_decode("2")
        assert result == b"\x01"

    def test_base58_decode_invalid_character(self) -> None:
        """Test base58 decoding with invalid character."""
        with pytest.raises(ValueError):
            self.wallet._base58_decode("0")  # 0 is not in Base58 alphabet

        with pytest.raises(ValueError):
            self.wallet._base58_decode("O")  # O is not in Base58 alphabet

    def test_wallet_state_properties(self) -> None:
        """Test wallet state property methods."""
        # Test initial state
        assert self.wallet.is_wallet_loaded is False
        assert self.wallet.has_derived_keys is False

        # Test with wallet loaded
        mock_xprv = MagicMock()
        self.wallet.master_xprv = mock_xprv
        assert self.wallet.is_wallet_loaded is True
        assert self.wallet.has_derived_keys is False

        # Test with keys derived
        self.wallet.last_derived_keys = [("m/0/0", "wif", "pubkey", "address")]
        assert self.wallet.is_wallet_loaded is True
        assert self.wallet.has_derived_keys is True

    @patch("xprv_gen.wallet.secrets.token_bytes")
    @patch("xprv_gen.wallet.bsv.hd.mnemonic_from_entropy")
    def test_generate_new_wallet_secure_success(
        self, mock_mnemonic_from_entropy, mock_token_bytes
    ) -> None:
        """Test successful secure new wallet generation."""
        mock_token_bytes.return_value = b"a" * 32
        mock_mnemonic_from_entropy.return_value = self.test_mnemonic

        with patch.object(
            self.wallet, "load_from_mnemonic", return_value=True
        ) as mock_load:
            result = self.wallet.generate_new_wallet_secure()

            assert result is True
            mock_token_bytes.assert_called_once_with(32)
            # The bytes are converted to hex, so "a" * 32 becomes "61" * 32
            expected_hex = (b"a" * 32).hex()
            mock_mnemonic_from_entropy.assert_called_once_with(expected_hex)
            mock_load.assert_called_once_with(self.test_mnemonic)

    def test_save_keys_json_format_no_data(self) -> None:
        """Test JSON format save with no data."""
        result = self.wallet.save_keys_json_format([])
        assert result is False

    @patch("builtins.open", new_callable=mock_open)
    @patch("xprv_gen.wallet.Path")
    def test_save_keys_json_format_success(self, mock_path, mock_file) -> None:
        """Test successful JSON format save."""
        test_data = [
            ("m/44'/0'/0'/0/0", "wif1", "pubkey1", "address1"),
            ("m/44'/0'/0'/0/1", "wif2", "pubkey2", "address2"),
        ]

        mock_path_instance = MagicMock()
        mock_path_instance.stat.return_value.st_size = 1000
        mock_path.return_value = mock_path_instance

        result = self.wallet.save_keys_json_format(test_data, "test_export")

        assert result is True
        mock_file.assert_called_once()
        mock_path.assert_called_once_with("test_export.json")

    def test_encrypt_decrypt_data_success(self) -> None:
        """Test successful data encryption and decryption."""
        test_data = "This is sensitive wallet data"
        test_password = "secure_password_123"

        encrypted = self.wallet._encrypt_data(test_data, test_password)
        assert encrypted != ""
        assert encrypted != test_data

        decrypted = self.wallet._decrypt_data(encrypted, test_password)
        assert decrypted == test_data

    def test_encrypt_decrypt_data_wrong_password(self) -> None:
        """Test decryption with wrong password."""
        test_data = "This is sensitive wallet data"
        test_password = "secure_password_123"
        wrong_password = "wrong_password"

        encrypted = self.wallet._encrypt_data(test_data, test_password)
        assert encrypted != ""

        decrypted = self.wallet._decrypt_data(encrypted, wrong_password)
        assert decrypted is None

    @patch("xprv_gen.wallet.getpass.getpass")
    @patch("builtins.open", new_callable=mock_open)
    @patch("xprv_gen.wallet.Path")
    def test_save_keys_encrypted_success(
        self, mock_path, mock_file, mock_getpass
    ) -> None:
        """Test successful encrypted keys save."""
        mock_getpass.side_effect = [
            "test_password",
            "test_password",
        ]  # Password and confirmation

        test_data = [
            ("m/44'/0'/0'/0/0", "wif1", "pubkey1", "address1"),
        ]

        result = self.wallet.save_keys_encrypted(test_data, "json", "test_encrypted")

        assert result is True
        mock_getpass.assert_called()
        mock_file.assert_called_once()

    @patch("xprv_gen.wallet.getpass.getpass")
    def test_save_keys_encrypted_password_mismatch(self, mock_getpass) -> None:
        """Test encrypted save with password mismatch."""
        mock_getpass.side_effect = ["password1", "password2"]  # Different passwords

        test_data = [("m/44'/0'/0'/0/0", "wif1", "pubkey1", "address1")]

        result = self.wallet.save_keys_encrypted(test_data, "json")

        assert result is False

    @patch("xprv_gen.wallet.getpass.getpass")
    def test_save_keys_encrypted_empty_password(self, mock_getpass) -> None:
        """Test encrypted save with empty password."""
        mock_getpass.return_value = ""

        test_data = [("m/44'/0'/0'/0/0", "wif1", "pubkey1", "address1")]

        result = self.wallet.save_keys_encrypted(test_data, "json")

        assert result is False

    @patch("xprv_gen.wallet.getpass.getpass")
    @patch("builtins.open", new_callable=mock_open, read_data="encrypted_content")
    @patch("xprv_gen.wallet.Path")
    def test_decrypt_keys_file_success(
        self, mock_path, mock_file, mock_getpass
    ) -> None:
        """Test successful file decryption."""
        mock_getpass.return_value = "test_password"
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        # Mock the decryption to return JSON content
        with patch.object(
            self.wallet, "_decrypt_data", return_value='{"test": "data"}'
        ) as mock_decrypt:
            result = self.wallet.decrypt_keys_file("test.enc", "output.json")

            assert result is True
            mock_decrypt.assert_called_once_with("encrypted_content", "test_password")

    @patch("xprv_gen.wallet.Path")
    def test_decrypt_keys_file_not_found(self, mock_path) -> None:
        """Test file decryption with non-existent file."""
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = False
        mock_path.return_value = mock_path_instance

        result = self.wallet.decrypt_keys_file("nonexistent.enc")

        assert result is False
