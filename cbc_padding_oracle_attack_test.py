#!/usr/bin/env python3

"""
Test cases for the CBC padding-oracle attack.
__author__ = Eik List
__date__   = 2018-06
__copyright__ = Creative Commons CC0
"""

import unittest

from cbc_padding_oracle import CBCPaddingOracle
from cbc_padding_oracle_attack import CBCPaddingOracleAttack


# ---------------------------------------------------------

def to_bytes(hex_string: str) -> bytes:
    """
    Converts hexadecimal string, e.g., "0a1b57" to byte array of half the size.
    :param: hex_string
    :return: The corresponding byte array.
    """
    return bytes.fromhex(hex_string)


# ---------------------------------------------------------

def to_string(byte_array: bytes) -> str:
    """
    Converts byte array to hexadecimal string, e.g., b"0a1b57" to "0a1b57".
    :param: byte_array
    :return: The corresponding hexadecimal string.
    """
    return byte_array.hex()


# ---------------------------------------------------------

class CBCPaddingOracleAttackTest(unittest.TestCase):
    """
    Test cases for the CBC padding-oracle attack.
    """

    # ---------------------------------------------------------

    def setUp(self) -> None:
        """
        Called before the tests. Initializes parameters and objects.
        """
        self.initial_value = to_bytes("3031323334353637383940414243446a")
        self.key = to_bytes("000102030405060708090a0b0c0d0e0f")
        self.oracle = CBCPaddingOracle(self.key)
        self.attack = CBCPaddingOracleAttack()

    # ---------------------------------------------------------

    def test_cbc_encryption(self) -> None:
        """
        Tests the encryption with the CBC instance in the oracle.
        """
        message = to_bytes("45cf12964fc824ab76616ae2f4bf08")
        ciphertext = self.oracle.encrypt(self.initial_value, message)
        expected_ciphertext = to_bytes("50d32b72f3c1506f7c433ac480bdd7af")

        self.assertEqual(expected_ciphertext, ciphertext)

    # ---------------------------------------------------------

    def _test_cbc_attack(self, message: str) -> None:
        message = to_bytes(message)
        ciphertext = self.oracle.encrypt(self.initial_value, message)

        recovered_message = self.attack.recover_message(self.oracle,
                                                        self.initial_value,
                                                        ciphertext)
        self.assertEqual(message, recovered_message)

    # ---------------------------------------------------------

    def test_cbc_attack_empty_message(self) -> None:
        self._test_cbc_attack("")

    # ---------------------------------------------------------

    def test_cbc_attack_small_message(self) -> None:
        self._test_cbc_attack("466f6f")

    # ---------------------------------------------------------

    def test_cbc_attack_single_block(self) -> None:
        self._test_cbc_attack("45cf12964fc824ab76616ae2f4bf0822")

    # ---------------------------------------------------------

    def test_cbc_attack_two_blocks(self) -> None:
        self._test_cbc_attack(\
            "068b25c7bfb1f8bdd4cfc908f69dffc5ddc726a197f0e5f720f730393279be91")

    # ---------------------------------------------------------

    def test_cbc_attack_three_blocks(self) -> None:
        self._test_cbc_attack(\
            "9b7cee827a26575afdbb7c7a329f887238052e3601a7917456ba61251c214763"\
            "d5e1847a6ad5d54127a399ab07ee3599")

    # ---------------------------------------------------------

    def test_cbc_attack_non_full_blocks(self) -> None:
        self._test_cbc_attack(\
            "416d65726963616e205374616e6461726420436f646520666f7220496e666f72"\
            "6d6174696f6e20496e7465726368616e6765")

    # ---------------------------------------------------------

    def test_cbc_attack_eight_blocks(self) -> None:
        self._test_cbc_attack(\
            "9ac19954ce1319b354d3220460f71c1e373f1cd336240881160cfde46ebfed2e"\
            "791e8d5a1a136ebd1dc469dec00c4187722b841cdabcb22c1be8a14657da200e")

    # ---------------------------------------------------------

    def test_cbc_attack_many_blocks(self) -> None:
        self._test_cbc_attack(\
            "db397ec22718dbffb9c9d13de0efcd4611bf792be4fce0dc5f25d4f577ed8cdb"\
            "d4eb9208d593dda3d4653954ab64f05676caa3ce9bfa795b08b67ceebc923fdc"\
            "89a8c431188e9e482d8553982cf304d1")


# ---------------------------------------------------------

if __name__ == '__main__':
    unittest.main()
