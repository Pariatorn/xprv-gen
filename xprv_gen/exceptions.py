"""
Custom exception classes for the BSV HD Wallet Key Derivation Tool.

This module contains all the custom exceptions used throughout the application
to provide specific error handling and improve code maintainability.
"""


class WalletError(Exception):
    """Base exception for all wallet-related errors."""

    pass


class InvalidMnemonicError(WalletError):
    """Raised when an invalid mnemonic is provided."""

    pass


class InvalidXprvError(WalletError):
    """Raised when an invalid xprv string is provided."""

    pass


class DerivationPathError(WalletError):
    """Raised when an invalid derivation path is provided."""

    pass


class WalletNotLoadedError(WalletError):
    """Raised when attempting operations on an unloaded wallet."""

    pass


class NoKeysAvailableError(WalletError):
    """Raised when attempting to save keys but no keys are available."""

    pass


class FileOperationError(WalletError):
    """Raised when file operations fail."""

    pass


class EncryptionError(WalletError):
    """Raised when encryption operations fail."""

    pass


class DecryptionError(WalletError):
    """Raised when decryption operations fail."""

    pass


class InvalidPasswordError(WalletError):
    """Raised when an invalid password is provided for encryption/decryption."""

    pass


class InvalidEntropyError(WalletError):
    """Raised when invalid entropy is provided for wallet generation."""

    pass


class InvalidIndexRangeError(WalletError):
    """Raised when an invalid index range is provided for key derivation."""

    pass
