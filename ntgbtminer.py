# ntgbtminer
# No Thrils GetBlockTemplate Bitcoin Miner
#
# This is mostly a demonstration of the GBT protocol.
# It mines at a measly 150 KHashes/sec on my computer
# but with a whole lot of spirit ;)
#
import base64
import hashlib
import http.client
import json
import logging
import random
import struct
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# JSON-HTTP RPC Configuration
# This will be particular to your local ~/.bitcoin/bitcoin.conf
RPC_HOST = "192.168.0.1"
RPC_PORT = 8332
RPC_USER = "bctest"
RPC_PASS = "bctest"

WALLET_ADDRESS = "WALLET_ADDRESS"


# Bitcoin Daemon JSON-HTTP RPC


def rpc(method, params=[]):
    logger.info("Making RPC call: %s", method)

    rpc_id = random.getrandbits(32)
    obj = {"version": "1.1", "method": method, "id": rpc_id, "params": params}
    auth_bytes = base64.encodebytes(("%s:%s" % (RPC_USER, RPC_PASS)).encode()).strip()

    conn = http.client.HTTPConnection(RPC_HOST, RPC_PORT, 30)
    conn.request(
        "POST",
        "/",
        json.dumps(obj),
        {
            "Authorization": "Basic " + auth_bytes[:-2].decode(),
            "Content-type": "application/json",
        },
    )

    resp = conn.getresponse()
    if resp is None:
        print("JSON-RPC: no response")
        return None

    body = resp.read()
    resp_obj = json.loads(body)
    if not resp_obj:
        raise ValueError("JSON-RPC: cannot JSON-decode body")

    if resp_obj["id"] != rpc_id:
        raise ValueError("invalid response id!")

    if "error" in resp_obj and resp_obj["error"]:
        raise ValueError("rpc error: %s" % resp_obj["error"])

    if "result" not in resp_obj:
        raise ValueError("JSON-RPC: no result in object")

    return resp_obj["result"]


# Bitcoin Daemon RPC Call Wrappers
# https://en.bitcoin.it/wiki/Original_Bitcoin_client/API_calls_list


def rpc_getblocktemplate():
    # https://en.bitcoin.it/wiki/Getblocktemplate
    return rpc("getblocktemplate", [{"rules": ["segwit"]}])


def rpc_submitblock(block_submission):
    return rpc("submitblock", [block_submission])


# For unittest purposes:


def rpc_getblock(block_id, verbosity=1):
    # https://bitcoin-rpc.github.io/en/doc/0.17.99/rpc/blockchain/getblock/
    return rpc("getblock", [block_id, verbosity])


def rpc_getrawtransaction(transaction_id, blockhash, verbose=False):
    return rpc("getrawtransaction", [transaction_id, verbose, blockhash])


# Representation Conversion Utility Functions


def int_to_varint_hex(x: int) -> str:
    """Convert an unsigned integer to little endian varint ASCII Hex"""
    if x < 0xFD:
        return "%02x" % x
        # return x.to_bytes(1, byteorder="little").hex()
    elif x <= 0xFFFF:
        return "fd" + x.to_bytes(2, byteorder="little").hex()
    elif x <= 0xFFFFFFFF:
        return "fe" + x.to_bytes(4, byteorder="little").hex()
    else:
        return "ff" + x.to_bytes(8, byteorder="little").hex()


def bitcoin_address_to_hash_160(s):
    """Convert a Base58 Bitcoin address to its Hash-160 ASCII Hex"""
    table = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    x = 0
    s = s[::-1]
    for i in range(len(s)):
        x += (58**i) * table.find(s[i])

    # Convert number to ASCII Hex string
    x = "%050x" % x
    # Discard 1-byte network byte at beginning and 4-byte checksum at the end
    return x[2 : 50 - 8]


# Transaction Coinbase and Hashing Functions


def tx_make_coinbase(
    coinbase_script, address, value, height, extra_pubkey_scripts=[]
) -> str:
    """Create a coinbase transaction

    Arguments:
          coinbase_script:    (hex string) arbitrary script
          address:            (base58 string) bitcoin address
          value:              (unsigned int) value

    Returns: transaction data in ASCII Hex
    """
    # See https://en.bitcoin.it/wiki/Transaction

    # See: https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
    length = (height.bit_length() + 7) // 8
    encoded_coinbase_height = length.to_bytes(1, byteorder="little") + height.to_bytes(
        length=length, byteorder="little"
    )
    coinbase_script = encoded_coinbase_height.hex() + coinbase_script

    # Create a pubkey script
    # OP_DUP OP_HASH160 <len to push> <pubkey> OP_EQUALVERIFY OP_CHECKSIG
    pubkey_script = (
        "76" + "a9" + "14" + bitcoin_address_to_hash_160(address) + "88" + "ac"
    )

    tx = ""
    # version
    tx += "01000000"

    # in-counter
    tx += "01"
    # input[0] prev hash
    tx += "0" * 64
    # input[0] prev seqnum
    tx += "ffffffff"
    # input[0] script len
    tx += int_to_varint_hex(len(coinbase_script) // 2)
    # input[0] script
    tx += coinbase_script
    # input[0] seqnum
    tx += "ffffffff"

    # out-counter
    # tx += "01"
    tx += int_to_varint_hex(len(extra_pubkey_scripts) + 1)
    # output[0] value (little endian)
    tx += value.to_bytes(8, byteorder="little").hex()
    # output[0] script len
    tx += int_to_varint_hex(len(pubkey_script) // 2)
    # output[0] script
    tx += pubkey_script

    # extra scripts
    for epks in extra_pubkey_scripts:
        # output[i] value (little endian)
        tx += int(0).to_bytes(8, byteorder="little").hex()
        # output[i] script len
        tx += int_to_varint_hex(len(epks) // 2)
        # output[i] script
        tx += epks

    # lock-time
    tx += "00000000"

    return tx


def double_sha256(data: bytes) -> bytes:
    """Compute double sha256 hash on data"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def tx_compute_merkle_root(tx_hashes):
    """Compute the Merkle Root of a list of transaction hashes

    Arguments:
          tx_hashes:    (list) ASCII Hex transaction hashes

    Returns: a SHA256 double hash in big endian ASCII Hex
    """
    # Convert each hash into a binary string
    for i in range(len(tx_hashes)):
        # Reverse the hash from big endian to little endian
        tx_hashes[i] = bytes.fromhex(tx_hashes[i])[::-1]

    # Iteratively compute the merkle root hash
    while len(tx_hashes) > 1:
        # Duplicate last hash if the list is odd
        if len(tx_hashes) % 2 != 0:
            tx_hashes.append(tx_hashes[-1][:])

        tx_hashes_new = []
        for i in range(len(tx_hashes) // 2):
            # Concatenate the next two
            concat = tx_hashes.pop(0) + tx_hashes.pop(0)
            # Hash them
            concat_hash = double_sha256(concat)
            # Add them to our working list
            tx_hashes_new.append(concat_hash)
        tx_hashes = tx_hashes_new

    # Format the root in big endian ascii hex
    return tx_hashes[0][::-1].hex()


# Block Preparation Functions


def block_form_header(block: Dict[str, str]) -> bytes:
    """Form the block header

    Arguments:
          block:  block data in dictionary

    Returns: a binary string
    """
    header = b""

    # Version
    header += struct.pack("<L", block["version"])
    # Previous Block Hash
    header += bytes.fromhex(block["previousblockhash"])[::-1]
    # Merkle Root Hash
    header += bytes.fromhex(block["merkleroot"])[::-1]
    # Time
    header += struct.pack("<L", block["curtime"])
    # Target Bits
    header += bytes.fromhex(block["bits"])[::-1]
    # Nonce
    header += struct.pack("<L", block["nonce"])

    return header


def block_bits2target(bits: str) -> bytes:
    """Convert block bits to target

    Arguments:
          bits: compressed target in ASCII Hex

    Returns: a target in big endian binary
    """
    # https://bitcoin.org/en/developer-reference#target-nbits

    # Bits: 1b0404cb
    # 1b -> left shift of (0x1b - 3) bytes
    # 0404cb -> value

    # Shift value to the left by (bits[0]-3) (big endian)
    # Also add leading zeros (big endian)
    _bytes = bytes.fromhex(bits)
    return b"\x00" * (32 - _bytes[0]) + _bytes[1:] + b"\x00" * (_bytes[0] - 3)


def block_make_submit(block: Dict[str, str]) -> str:
    """Format a solved block into the ASCII Hex submit format

    Arguments:
       block: block

    Returns: block in ASCII Hex submit format
    """
    subm = ""

    # Block header
    subm += block_form_header(block).hex()

    block_transactions_key, data_key = (
        ("tx", "hex") if "tx" in block else ("transactions", "data")
    )
    # Number of transactions as a varint
    subm += int_to_varint_hex(len(block[block_transactions_key]))
    # Concatenated transactions data
    for tx in block[block_transactions_key]:
        subm += tx[data_key]

    return subm


# Mining Loop


def calc_average_hps(time_deltas):
    # calculated every 1048576 hashes
    return len(time_deltas) * 1048576 / sum(time_deltas) if time_deltas else 0


# @profile
def block_mine(
    block_template: Dict[str, str],
    coinbase_message: str,
    extranonce_start: int,
    address: str,
    extra_pubkey_scripts: List[str] = [],
    timeout: Optional[int] = None,
    debugnonce_start: Optional[int] = None,
) -> Tuple[Optional[Dict[str, str]], float]:
    """Mine a block

    Arguments:
          block_template: block template
          coinbase_message: binary string for coinbase script
          extranonce_start: extranonce for coinbase script
          address: base58 reward bitcoin address

    Optional Arguments:
          timeout: timeout in seconds to give up mining
          debugnonce_start: nonce start for testing purposes

    Returns tuple of (solved block, hashes per second) on finding a solution,
    or (None, hashes per second) on timeout or nonce exhaustion.
    """
    logger.info(
        "Mining block: prev hash: %s; version: %s; cur time: %s",
        block_template["previousblockhash"],
        block_template["version"],
        block_template["curtime"],
    )

    # Add an empty coinbase transaction to the block template
    coinbase_tx = {}
    block_template["transactions"].insert(0, coinbase_tx)
    # Add a nonce initialized to zero to the block template
    block_template["nonce"] = 0

    # Compute the target hash
    target_hash = block_bits2target(block_template["bits"])

    # Mark our mine start time
    time_start = time.process_time()

    # Initialize our running average of hashes per second
    time_deltas = []

    # Loop through the extranonce
    extranonce = extranonce_start
    while extranonce <= 0xFFFFFFFF:

        # Update the coinbase transaction with the extra nonce
        coinbase_script = (
            coinbase_message + extranonce.to_bytes(4, byteorder="little").hex()
        )
        coinbase_tx["data"] = tx_make_coinbase(
            coinbase_script,
            address,
            block_template["coinbasevalue"],
            block_template["height"],
            extra_pubkey_scripts,
        )
        coinbase_tx["hash"] = double_sha256(bytes.fromhex(coinbase_tx["data"]))[
            ::-1
        ].hex()

        # Recompute the merkle root
        tx_hashes = [tx["hash"] for tx in block_template["transactions"]]
        block_template["merkleroot"] = tx_compute_merkle_root(tx_hashes)

        # Reform the block header
        block_header = block_form_header(block_template)
        block_header_first_76 = block_header[0:76]

        time_prev = time.process_time()

        # Loop through the nonce
        nonce = debugnonce_start if debugnonce_start else 0
        while nonce <= 0xFFFFFFFF:
            # Update the block header with the new 32-bit nonce
            block_header = block_header_first_76 + struct.pack("I", nonce)

            # Recompute the block hash
            block_hash = double_sha256(block_header)[::-1]

            # Check if it the block meets the target target hash
            if block_hash < target_hash:
                block_template["nonce"] = nonce
                block_template["hash"] = block_hash.hex()
                return (block_template, calc_average_hps(time_deltas))

            # Lightweight benchmarking of hashes / sec and timeout check
            # use mask as slightly faster than modulo arithmetic
            # 2**20 = 1048576 = 1<<20
            # mask = (1 << 20) - 1 = 1048575
            if nonce != 0 and nonce & 1048575 == 0:
                time_now = time.process_time()
                time_deltas.append(time_now - time_prev)
                time_prev = time_now

                # If our mine time expired, return none
                if timeout and (time_now - time_start) > timeout:
                    return (None, calc_average_hps(time_deltas))

            nonce += 1
        extranonce += 1

    # If we ran out of extra nonces, return none
    return (None, calc_average_hps(time_deltas))


# Standalone Bitcoin Miner, Single-threaded


def standalone_miner(coinbase_message, address):
    while True:
        mined_block, hps = block_mine(
            rpc_getblocktemplate(), coinbase_message, 0, address, timeout=60
        )
        logger.info("Average Mhash/s: %.4f", (hps / 1000000.0))

        if mined_block:
            logger.info("Solved a block! Block hash: %s", mined_block["hash"])
            submission = block_make_submit(mined_block)
            logger.info("Submitting: %s", submission)
            rpc_submitblock(submission)

            # exit loop as best to vary reward address
            return


if __name__ == "__main__":
    logging.basicConfig(level="INFO")

    standalone_miner(
        b"Test 1 2 3".hex(),
        WALLET_ADDRESS,
    )
