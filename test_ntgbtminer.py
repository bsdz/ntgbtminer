import unittest

from bit.transaction import deserialize
from bit.base58 import b58encode_check

from ntgbtminer import (
    int_to_varint_hex,
    bitcoin_address_to_hash_160,
    double_sha256,
    rpc_getblock,
    rpc_getrawtransaction,
    tx_compute_merkle_root,
    tx_make_coinbase,
    block_bits2target,
    block_form_header,
    block_mine,
    block_make_submit,
)

NETWORK = "main"
# NETWORK = "testnet"

TEST_BLOCK_HASHES = {
    "main": [
        "000000000000000a369033d52a4aa264844b50857f0c6104c555d53938e9c8d7",
        "00000000000000000012ceadfe65dccb2d104ae6b33c81125259746abe23c546",
        "0000000000000000000cc115e5fb0726dba6278d56688ef78eaf42b04fdb838c",
    ],
    "testnet": [],
}


class TestConversions(unittest.TestCase):
    def test_int_to_varint_hex(self):
        self.assertEqual(int_to_varint_hex(0x1A), "1a")
        self.assertEqual(int_to_varint_hex(0x1A2B), "fd2b1a")
        self.assertEqual(int_to_varint_hex(0x1A2B3C), "fe3c2b1a00")
        self.assertEqual(int_to_varint_hex(0x1A2B3C4D), "fe4d3c2b1a")
        self.assertEqual(int_to_varint_hex(0x1A2B3C4D5E), "ff5e4d3c2b1a000000")

    def test_binary_to_hex(self):
        self.assertEqual(b"\x00\x01\xab\xcdA".hex(), "0001abcd41")

    def test_hex_to_binary(self):
        self.assertEqual(bytes.fromhex("0001abcd41"), b"\x00\x01\xab\xcdA")

    def test_bitcoin_address_to_hash_160(self):
        self.assertEqual(
            bitcoin_address_to_hash_160("14cZMQk89mRYQkDEj8Rn25AnGoBi5H6uer"),
            "27a1f12771de5cc3b73941664b2537c15316be43",
        )


class TestTransaction(unittest.TestCase):
    def test_hash(self):
        """ check hashing works for sample transactions. use 3rd party lib to
        deserialize so we can easily strip off witness data. """
        for block_hash in TEST_BLOCK_HASHES[NETWORK]:
            block = rpc_getblock(block_hash)
            # coinbase transaction almost always 1st tx in block
            tx_id = block["tx"][0]
            tx_data = rpc_getrawtransaction(tx_id, block_hash)
            tx_data_deserialized = deserialize(tx_data)
            # strip off witness data before serializing
            # see https://bitcoin.stackexchange.com/questions/73979/getting-the-wrong-txid-for-coinbase-transactions
            tx_data_deserialized.TxIn[0].witness = b""
            with self.subTest(block_hash=block_hash, tx_id=tx_id):
                self.assertEqual(
                    double_sha256(bytes.fromhex(tx_data_deserialized.to_hex()))[
                        ::-1
                    ].hex(),
                    tx_id,
                )

    def test_make_coinbase(self):
        """ check hashing works for sample transactions. use 3rd party lib to
        deserialize so we can easily strip off witness data. """
        for block_hash in TEST_BLOCK_HASHES[NETWORK]:
            block = rpc_getblock(block_hash)
            # coinbase transaction almost always 1st tx in block
            tx_id = block["tx"][0]
            tx_data = rpc_getrawtransaction(tx_id, block_hash)
            tx_data_deserialized = deserialize(tx_data)

            # strip off witness data before serializing
            # see https://bitcoin.stackexchange.com/questions/73979/getting-the-wrong-txid-for-coinbase-transactions
            tx_data_deserialized.TxIn[0].witness = b""

            # currently tx_make_coinbase doesn't support OP_RETURN so pop them off
            # while len(tx_data_deserialized.TxOut) > 1:
            #     tx_data_deserialized.TxOut.pop()

            extra_pubkey_scripts = [t.script_pubkey.hex() for t in tx_data_deserialized.TxOut[1:]]

            with self.subTest(block_hash=block_hash, tx_id=tx_id):
                # Test Vector is coinbase transaction data
                test_vector = tx_data_deserialized.to_hex()

                # Parameters to form coinbase transaction

                # strip off height (as will be added later)
                height_byte_length = (block["height"].bit_length() + 7) // 8
                
                coinbase_script = tx_data_deserialized.TxIn[0].script_sig[height_byte_length+1:].hex()
                address = b58encode_check((b'\0' + tx_data_deserialized.TxOut[0].script_pubkey[3:-2]))
                value = int.from_bytes(tx_data_deserialized.TxOut[0].amount, 'little')
                height = block["height"]

                self.assertEqual(
                    tx_make_coinbase(coinbase_script, address, value, height, extra_pubkey_scripts), test_vector
                )

    def test_merkle_root(self):
        """ check we compute same merkle roots as previous transactions """
        for block_hash in TEST_BLOCK_HASHES[NETWORK]:
            block = rpc_getblock(block_hash)
            with self.subTest(block_hash=block_hash):
                self.assertEqual(
                    tx_compute_merkle_root(block["tx"]), block["merkleroot"]
                )


class TestBlock(unittest.TestCase):
    def test_bits2target(self):
        bits = "1a01aa3d"
        vector = "00000000000001aa3d0000000000000000000000000000000000000000000000"
        self.assertEqual(block_bits2target(bits).hex(), vector)

        bits = "1b0404cb"
        vector = "00000000000404cb000000000000000000000000000000000000000000000000"
        self.assertEqual(block_bits2target(bits).hex(), vector)

    def test_block_hash(self):
        for block_hash in TEST_BLOCK_HASHES[NETWORK]:
            block = rpc_getblock(block_hash)

            with self.subTest(block_hash=block_hash):
                # Test Vector is block hash
                test_vector = block["hash"]
                # Copy time key to curtime key to make block look like block template
                block["curtime"] = block["time"]

                # Check block hash
                header = block_form_header(block)
                header_hash = double_sha256(header)[::-1].hex()
                self.assertEqual(header_hash, test_vector)

                # Check block hash meets or fails various targets
                target_hash = block_bits2target(block["bits"])
                header_hash = double_sha256(header)[::-1]
                self.assertEqual(header_hash < target_hash, True)

                # switching 1st byte to 255 will probably always fail
                header_hash = b"\xff" + header_hash[1:]
                self.assertEqual(header_hash < target_hash, False)

                # from original code
                # header_hash = b"\x01" + header_hash[1:]
                # self.assertEqual(header_hash < target_hash, False)
                # header_hash = b"\x00" * 6 + b"\x02" + header_hash[8:]
                # self.assertEqual(header_hash < target_hash, False)
                # header_hash = b"\x00" * 6 + b"\x01" + header_hash[8:]
                # self.assertEqual(header_hash < target_hash, True)
                # header_hash = b"\x00" * 6 + b"\x01\xaa\x3c" + header_hash[10:]
                # self.assertEqual(header_hash < target_hash, True)
                # header_hash = b"\x00" * 6 + b"\x01\xaa\x3d" + header_hash[10:]
                # self.assertEqual(header_hash < target_hash, False)

    def test_block_mine(self):

        for block_hash in TEST_BLOCK_HASHES[NETWORK]:
            block = rpc_getblock(block_hash, 2)
            submission = rpc_getblock(block_hash, 0)
            # coinbase transaction almost always 1st tx in block
            #tx_id = block["tx"][0]
            tx_id = block["tx"][0]["txid"] # since we have verbosity == 2
            tx_data = rpc_getrawtransaction(tx_id, block_hash)
            tx_data_deserialized = deserialize(tx_data)

            # strip off witness data before serializing
            # see https://bitcoin.stackexchange.com/questions/73979/getting-the-wrong-txid-for-coinbase-transactions
            tx_data_deserialized.TxIn[0].witness = b""

            extra_pubkey_scripts = [t.script_pubkey.hex() for t in tx_data_deserialized.TxOut[1:]]

            with self.subTest(block_hash=block_hash, tx_id=tx_id):


                # Parameters to form coinbase transaction

                # strip off height (as will be added later)
                height_byte_length = (block["height"].bit_length() + 7) // 8
                
                # extract original coinbase message and extra nonce
                coinbase_message = tx_data_deserialized.TxIn[0].script_sig[height_byte_length+1:-4].hex()
                extra_nonce_start = int.from_bytes(tx_data_deserialized.TxIn[0].script_sig[-4:], 'little')
                address = b58encode_check((b'\0' + tx_data_deserialized.TxOut[0].script_pubkey[3:-2]))
                value = int.from_bytes(tx_data_deserialized.TxOut[0].amount, 'little')
                # height = block["height"]

                # Manipulate the transactions in real block to look like a block template
                block["transactions"] = []
                for i in range(1, len(block["tx"])):
                    # tx = {"hash": block["tx"][i], "data": "abc"}
                    tx = {"hash": block["tx"][i]["txid"], "data": block["tx"][i]["hex"]}
                    block["transactions"].append(tx)

                # Setup generation transaction parameters with same extra nonce start as the mined black

                # start nonces at mined value minus small offset
                debug_nonce_start = block['nonce'] - 10000
                
                block["coinbasevalue"] = value
                # Copy time key to curtime key to make block look like block template
                block["curtime"] = block["time"]
                # Clear block hash
                block["hash"] = ""

                # Mine
                (mined_block, hps) = block_mine(
                    block,
                    coinbase_message,
                    extra_nonce_start,
                    address,
                    extra_pubkey_scripts,
                    timeout=60,
                    debugnonce_start=debug_nonce_start,
                )

                # Test vector is actual block hash
                test_vector = block_hash

                self.assertEqual(mined_block["hash"], test_vector)

                self.assertEqual(
                    block_make_submit(mined_block),
                    submission
                )


if __name__ == "__main__":
    unittest.main()
