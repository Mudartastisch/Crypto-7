#!/usr/bin/env python3

"""
Implements the CBC padding oracle attack and returns (if possible)
the plaintext that corresponded to the given ciphertext.
"""

from cbc_padding_oracle import CBCPaddingOracle


# ---------------------------------------------------------

class CBCPaddingOracleAttack:
    """
    Implements the CBC padding oracle attack.
    """

    BLOCK_SIZE = 16 # bytes

    # ---------------------------------------------------------

    def __init__(self):
        pass

    # ---------------------------------------------------------

    def blockify(text, block_size=BLOCK_SIZE):
        return [text[i:i+block_size] for i in range(0, len(text), block_size)]

    def recover_message(self, 
                        oracle: CBCPaddingOracle,
                        initial_value: bytes,
                        ciphertext: bytes) -> bytes:
        """
        Implements the CBC padding-oracle attack.
        :param initial_value: 16-byte initial value.
        :param ciphertext: Ciphertext. Length must be multiple of 16 bytes.
        :return: Returns the plaintext that corresponded to the given
                 ciphertext.
        """
        blocks = blockify(ciphertext)

        cleartext = []
        for block_num, (c1, c2) in enumerate(zip([initial_value]+blocks, blocks)):
            print ("cracking block {} out of {}".format(block_num+1, len(blocks)))
            i2 = [0] * 16
            p2 = [0] * 16
            for i in xrange(15,-1,-1):
                for b in xrange(0,256):
                    prefix = c1[:i]
                    pad_byte = (BLOCK_SIZE-i)
                    suffix = [pad_byte ^ val for val in i2[i+1:]]
                    evil_c1 = prefix + [b] + suffix
                    try:
                        verify_padding(stringify(c2), my_key, stringify(evil_c1))
                    except ValueError:
                        pass
                    else:
                        i2[i] = evil_c1[i] ^ pad_byte
                        p2[i] = c1[i] ^ i2[i]
                        break
        return (cleartext.append(p2))