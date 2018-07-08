#!/usr/bin/env python3

"""
Implements a CBC padding oracle for AES-128-CBC.
__author__ = Eik List
__date__   = 2018-04
__copyright__ = Creative Commons CC0
"""

# ---------------------------------------------------------

from Crypto.Cipher import AES
from Crypto import Random


# ---------------------------------------------------------

class CBCPaddingOracle:
    """
    Implements a CBC padding oracle for AES-128-CBC.
    """

    def __init__(self, key: bytes):
        """
        Sets the key.
        :param key:
        """
        self.key = key

    #----------------------------------------------------------
    # source
    # https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/Padding.py

    def pad(data_to_pad, block_size, style='pkcs7') -> bytes:
        """
        Apply standard padding.
        :Parameters:
          data_to_pad : byte string
            The data that needs to be padded.
          block_size : integer
            The block boundary to use for padding. The output length is guaranteed
            to be a multiple of ``block_size``.
          style : string
            Padding algorithm. It can be *'pkcs7'* (default), *'iso7816'* or *'x923'*.
        :Return:
          The original data with the appropriate padding added at the end.
        """
        padding_len = block_size - len(data_to_pad) % block_size
        if style == 'pkcs7':
            padding = bchr(padding_len) * padding_len
        elif style == 'x923':
            padding = bchr(0) * (padding_len - 1) + bchr(padding_len)
        elif style == 'iso7816':
            padding = bchr(128) + bchr(0) * (padding_len - 1)
        else:
            raise ValueError("Unknown padding style")
        return data_to_pad + padding

    #----------------------------------------------------------
    # source
    # https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/Padding.py

    def unpad(padded_data, block_size, style='pkcs7'):
        """Remove standard padding.
        :Parameters:
          padded_data : byte string
            A piece of data with padding that needs to be stripped.
          block_size : integer
            The block boundary to use for padding. The input length
            must be a multiple of ``block_size``.
          style : string
            Padding algorithm. It can be *'pkcs7'* (default), *'iso7816'* or *'x923'*.
        :Return:
            Data without padding.
        :Raises ValueError:
            if the padding is incorrect.
        """

        pdata_len = len(padded_data)
        if pdata_len % block_size:
            raise ValueError("Input data is not padded")
        if style in ('pkcs7', 'x923'):
            padding_len = bord(padded_data[-1])
            if padding_len < 1 or padding_len > min(block_size, pdata_len):
                raise ValueError("Padding is incorrect.")
            if style == 'pkcs7':
                if padded_data[-padding_len:] != bchr(padding_len) * padding_len:
                    raise ValueError("PKCS#7 padding is incorrect.")
            else:
                if padded_data[-padding_len:-1] != bchr(0) * (padding_len - 1):
                    raise ValueError("ANSI X.923 padding is incorrect.")
        elif style == 'iso7816':
            padding_len = pdata_len - padded_data.rfind(bchr(128))
            if padding_len < 1 or padding_len > min(block_size, pdata_len):
                raise ValueError("Padding is incorrect.")
            if padding_len > 1 and padded_data[1 - padding_len:] != bchr(0) * (padding_len - 1):
                raise ValueError("ISO 7816-4 padding is incorrect.")
        else:
            raise ValueError("Unknown padding style")
        return padded_data[:-padding_len]

    # ---------------------------------------------------------

    def encrypt(self, initial_value: bytes, message: bytes) -> bytes:
        """
        Pads the given message to a multiple of the block length,
        computes, and returns its encryption with AES-128-CBC-XMLPad.

        :param initial_value: 16-byte initial value.
        :param message: Plaintext of arbitrary length
        :return: Ciphertext whose length is a multiple of 16 bytes, but
        always at least the length of the message.
        """
        key = self.key
        iv = initial_value
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(message, 16, 'pkcs7')
        msg = iv + cipher.encrypt(padded)
        return msg

    # ---------------------------------------------------------

    def verify_padding(self, initial_value: bytes, ciphertext: bytes) -> bool:
        """
        Given a ciphertext, evaluates if the padding is correct.
        :param initial_value: 16-byte initial value.
        :param ciphertext: Ciphertext. Length must be multiple of 16 bytes.
        :return: True if padding is correct, and False otherwise.
        """
        key = self.key
        iv = initial_value
        cipher = AES.new(key, AES.MODE_CBC, iv)
        msg = cipher.decrypt(ciphertext)
        try:
            unpad(msg, 16, 'pkcs7')
            return True
        except ValueError as e:
            return False
