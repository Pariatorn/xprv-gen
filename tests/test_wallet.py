"""
Tests for the wallet module.

This module tests the core HDWalletTool functionality including mnemonic loading,
xprv loading, key derivation, and wallet generation.
"""

from unittest.mock import MagicMock, mock_open, patch

import pytest

from xprv_gen.exceptions import (
    DecryptionError,
    DerivationPathError,
    FileOperationError,
    InvalidEntropyError,
    InvalidMnemonicError,
    InvalidXprvError,
    NoKeysAvailableError,
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

        # Set up the final derived key with callable returns
        mock_child2.private_key.return_value = mock_private_key
        mock_child2.public_key.return_value = mock_public_key

        # Mock the key formats
        mock_private_key.wif.return_value = "test_wif"
        mock_public_key.hex.return_value = "test_pubkey_hex"
        mock_child2.address.return_value = "test_address"

        self.wallet.master_xprv = mock_xprv

        result = self.wallet.derive_single_key("m/0/1")

        # Should return (derivation_path, private_key_wif, public_key_hex, address)
        assert result == ("m/0/1", "test_wif", "test_pubkey_hex", "test_address")
        mock_xprv.ckd.assert_called_once_with(0)
        mock_child1.ckd.assert_called_once_with(1)

    def test_derive_single_key_hardened(self) -> None:
        """Test single key derivation with hardened derivation."""
        # Setup mocks
        mock_xprv = MagicMock()
        mock_child1 = MagicMock()
        mock_child2 = MagicMock()
        mock_private_key = MagicMock()
        mock_public_key = MagicMock()

        # Set up the chain with hardened derivation
        mock_xprv.ckd.return_value = mock_child1
        mock_child1.ckd.return_value = mock_child2

        # Set up the final derived key with callable returns
        mock_child2.private_key.return_value = mock_private_key
        mock_child2.public_key.return_value = mock_public_key

        # Mock the key formats
        mock_private_key.wif.return_value = "test_wif"
        mock_public_key.hex.return_value = "test_pubkey_hex"
        mock_child2.address.return_value = "test_address"

        self.wallet.master_xprv = mock_xprv

        result = self.wallet.derive_single_key("m/44'/0'")

        # Should return (derivation_path, private_key_wif, public_key_hex, address)
        assert result == ("m/44'/0'", "test_wif", "test_pubkey_hex", "test_address")

        # Check that hardened derivation was used (44 + 2^31 for hardened)
        expected_hardened_44 = 44 + 2**31
        mock_xprv.ckd.assert_called_once_with(expected_hardened_44)

        # Check that second hardened derivation was used (0 + 2^31 for hardened)
        expected_hardened_0 = 0 + 2**31
        mock_child1.ckd.assert_called_once_with(expected_hardened_0)

    def test_derive_keys_range_no_wallet(self) -> None:
        """Test deriving key range with no wallet loaded."""
        with pytest.raises(WalletNotLoadedError, match="No wallet loaded"):
            self.wallet.derive_keys_range("m/44'/0'/0'", 0, 2)

    @patch("xprv_gen.wallet.bsv.hd.derive_xprvs_from_mnemonic")
    def test_derive_keys_range_with_mnemonic(self, mock_derive_xprvs) -> None:
        """Test deriving key range with mnemonic available."""
        # Setup wallet with mnemonic
        mock_xprv = MagicMock()
        self.wallet.master_xprv = mock_xprv
        self.wallet.mnemonic = self.test_mnemonic

        # Mock the derived keys
        mock_derived_xprvs = []
        for i in range(3):
            mock_derived_xprv = MagicMock()
            mock_private_key = MagicMock()
            mock_public_key = MagicMock()

            mock_derived_xprv.private_key.return_value = mock_private_key
            mock_derived_xprv.public_key.return_value = mock_public_key

            mock_private_key.wif.return_value = f"wif{i}"
            mock_public_key.hex.return_value = f"pubkey{i}"
            mock_derived_xprv.address.return_value = f"address{i}"

            mock_derived_xprvs.append(mock_derived_xprv)

        mock_derive_xprvs.return_value = mock_derived_xprvs

        result = self.wallet.derive_keys_range("m/44'/0'/0'", 0, 2)

        # Should return list of
        # (derivation_path, private_key_wif, public_key_hex, address)
        expected_result = [
            ("m/44'/0'/0'/0/0", "wif0", "pubkey0", "address0"),
            ("m/44'/0'/0'/0/1", "wif1", "pubkey1", "address1"),
            ("m/44'/0'/0'/0/2", "wif2", "pubkey2", "address2"),
        ]
        assert result == expected_result
        mock_derive_xprvs.assert_called_once()

    @patch("xprv_gen.wallet.bsv.hd.mnemonic_from_entropy")
    def test_generate_new_wallet_success(self, mock_mnemonic_from_entropy) -> None:
        """Test successful new wallet generation."""
        mock_mnemonic_from_entropy.return_value = self.test_mnemonic

        with patch.object(
            self.wallet, "load_from_mnemonic", return_value="BIP39"
        ) as mock_load:
            result = self.wallet.generate_new_wallet(self.test_entropy)

            # Should return (mnemonic, entropy_used)
            assert result == (self.test_mnemonic, self.test_entropy)
            mock_mnemonic_from_entropy.assert_called_once_with(self.test_entropy)
            mock_load.assert_called_once_with(self.test_mnemonic)

    @patch("xprv_gen.wallet.bsv.hd.mnemonic_from_entropy")
    def test_generate_new_wallet_failure(self, mock_mnemonic_from_entropy) -> None:
        """Test failure in new wallet generation."""
        mock_mnemonic_from_entropy.side_effect = Exception("Generation failed")

        with pytest.raises(InvalidEntropyError, match="Error generating new wallet"):
            self.wallet.generate_new_wallet(self.test_entropy)

    def test_base58_decode_basic(self) -> None:
        """Test basic base58 decoding."""
        # Test with a simple case
        result = self.wallet._base58_decode("1")
        assert result == b"\x00"

    def test_base58_decode_invalid_character(self) -> None:
        """Test base58 decoding with invalid character."""
        with pytest.raises(ValueError):
            self.wallet._base58_decode("0")  # '0' is not in base58 alphabet

    def test_wallet_state_properties(self) -> None:
        """Test wallet state property methods."""
        # Test initial state
        assert self.wallet.is_wallet_loaded is False

        # Test with wallet loaded
        mock_xprv = MagicMock()
        self.wallet.master_xprv = mock_xprv
        assert self.wallet.is_wallet_loaded is True

    @patch("xprv_gen.wallet.secrets.token_bytes")
    @patch("xprv_gen.wallet.bsv.hd.mnemonic_from_entropy")
    def test_generate_new_wallet_secure_success(
        self, mock_mnemonic_from_entropy, mock_token_bytes
    ) -> None:
        """Test successful secure new wallet generation."""
        mock_token_bytes.return_value = b"a" * 32
        mock_mnemonic_from_entropy.return_value = self.test_mnemonic

        with patch.object(
            self.wallet, "load_from_mnemonic", return_value="BIP39"
        ) as mock_load:
            result = self.wallet.generate_new_wallet_secure()

            # Should return (mnemonic, entropy_hex)
            expected_entropy = ("a" * 32).encode().hex()
            assert result == (self.test_mnemonic, expected_entropy)
            mock_token_bytes.assert_called_once_with(32)
            mock_load.assert_called_once_with(self.test_mnemonic)

    def test_save_keys_no_data(self) -> None:
        """Test saving keys with no data."""
        with pytest.raises(NoKeysAvailableError, match="No keys data provided"):
            self.wallet.save_keys([], "json")

    @patch("builtins.open", new_callable=mock_open)
    @patch("xprv_gen.wallet.Path")
    def test_save_keys_success(self, mock_path, mock_file) -> None:
        """Test successful key saving."""
        test_data = [
            ("m/44'/0'/0'/0/0", "wif1", "pubkey1", "address1"),
            ("m/44'/0'/0'/0/1", "wif2", "pubkey2", "address2"),
        ]

        mock_path_instance = MagicMock()
        mock_path_instance.stat.return_value.st_size = 1000
        mock_path.return_value = mock_path_instance

        result = self.wallet.save_keys(test_data, "json", "test_export")

        assert str(result) == str(mock_path_instance)
        mock_file.assert_called_once()

    def test_encrypt_decrypt_data_success(self) -> None:
        """Test successful data encryption and decryption."""
        test_data = "This is sensitive wallet data"
        test_password = "secure_password_123"

        # Encrypt the data
        encrypted = self.wallet._encrypt_data(test_data, test_password)
        assert encrypted != ""
        assert encrypted != test_data

        # Decrypt the data
        decrypted = self.wallet._decrypt_data(encrypted, test_password)
        assert decrypted == test_data

    def test_encrypt_decrypt_data_wrong_password(self) -> None:
        """Test decryption with wrong password."""
        test_data = "This is sensitive wallet data"
        test_password = "secure_password_123"
        wrong_password = "wrong_password"

        encrypted = self.wallet._encrypt_data(test_data, test_password)
        assert encrypted != ""

        with pytest.raises(DecryptionError, match="Decryption error"):
            self.wallet._decrypt_data(encrypted, wrong_password)

    @patch("builtins.open", new_callable=mock_open)
    @patch("xprv_gen.wallet.Path")
    def test_save_keys_encrypted_success(self, mock_path, mock_file) -> None:
        """Test successful encrypted key saving."""
        test_data = [
            ("m/44'/0'/0'/0/0", "wif1", "pubkey1", "address1"),
            ("m/44'/0'/0'/0/1", "wif2", "pubkey2", "address2"),
        ]

        mock_path_instance = MagicMock()
        mock_path_instance.stat.return_value.st_size = 1000
        mock_path.return_value = mock_path_instance

        result = self.wallet.save_keys_encrypted(
            test_data, "password123", "password123", export_format="json"
        )

        assert str(result) == str(mock_path_instance)
        mock_file.assert_called_once()

    def test_save_keys_encrypted_password_mismatch(self) -> None:
        """Test encrypted save with password mismatch."""
        test_data = [("m/0/0", "wif", "pubkey", "address")]

        with pytest.raises(FileOperationError, match="Error saving encrypted keys"):
            self.wallet.save_keys_encrypted(
                test_data, "password1", "password2", export_format="json"
            )

    def test_save_keys_encrypted_empty_password(self) -> None:
        """Test encrypted save with empty password."""
        test_data = [("m/0/0", "wif", "pubkey", "address")]

        with pytest.raises(FileOperationError, match="Error saving encrypted keys"):
            self.wallet.save_keys_encrypted(test_data, "", "", export_format="json")

    @patch("builtins.open", new_callable=mock_open, read_data="encrypted_content")
    @patch("xprv_gen.wallet.Path")
    def test_decrypt_keys_file_success(self, mock_path, mock_file) -> None:
        """Test successful file decryption."""
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        # Mock the decryption process
        with patch.object(
            self.wallet, "_decrypt_data", return_value="decrypted_content"
        ) as mock_decrypt:
            result = self.wallet.decrypt_keys_file("test.enc", "password123")

            assert result == "test_decrypted.txt"
            mock_decrypt.assert_called_once_with("encrypted_content", "password123")

    @patch("xprv_gen.wallet.Path")
    def test_decrypt_keys_file_not_found(self, mock_path) -> None:
        """Test file decryption with non-existent file."""
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = False
        mock_path.return_value = mock_path_instance

        from xprv_gen.exceptions import FileOperationError

        with pytest.raises(FileOperationError, match="File not found"):
            self.wallet.decrypt_keys_file("nonexistent.enc", "password123")
