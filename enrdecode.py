#!/usr/bin/env python3
import sys
import rlp
import base64
import socket
from eth_utils import to_hex, big_endian_to_int

def decode_enr(enr_string):
    print(f"\n--- ENR: {enr_string[:20]}... ---")

    # 1. Remove prefix
    if enr_string.startswith("enr:"):
        clean_enr = enr_string[4:]
    else:
        clean_enr = enr_string

    # 2. Base64 URL decode (with padding handling)
    try:
        padding = '=' * ((4 - len(clean_enr) % 4) % 4)
        enr_bytes = base64.urlsafe_b64decode(clean_enr + padding)
    except Exception as e:
        print(f"Base64 decode error: {e}")
        return

    # 3. RLP decoding
    try:
        elements = rlp.decode(enr_bytes)
    except Exception as e:
        print(f"RLP decode error: {e}")
        return

    signature = to_hex(elements[0])
    seq = big_endian_to_int(elements[1])

    print(f"Signature: {signature[:10]}...")
    print(f"Sequence No: {seq}")

    # 4. Parse key-value pairs
    data = {}
    for i in range(2, len(elements), 2):
        key = elements[i].decode('utf-8')
        value = elements[i + 1]
        data[key] = value

    # 5. Print important fields
    if 'id' in data:
        print(f"Scheme: {data['id'].decode('utf-8')}")

    if 'ip' in data:
        try:
            ip_addr = socket.inet_ntoa(data['ip'])
            print(f"IP Address: {ip_addr}")
        except Exception:
            print(f"IP Address: (raw) {to_hex(data['ip'])}")

    if 'tcp' in data:
        print(f"TCP Port: {big_endian_to_int(data['tcp'])}")

    if 'udp' in data:
        print(f"UDP Port: {big_endian_to_int(data['udp'])}")

    # 6. ETH ENTRY (ForkID)
    if 'eth' in data:
        eth_entry = data['eth']

        if isinstance(eth_entry, list) and len(eth_entry) >= 1:
            fork_id = eth_entry[0]

            if isinstance(fork_id, list) and len(fork_id) == 2:
                fork_hash_bytes, next_fork_bytes = fork_id

                fork_hash = to_hex(fork_hash_bytes)
                next_fork = big_endian_to_int(next_fork_bytes) if next_fork_bytes else 0

                print("\n>>> ETH ENTRY (ForkID) <<<")
                print(f"Fork hash:       {fork_hash}")
                print(f"Next fork block: {next_fork}")
            else:
                print(f"Unexpected ForkID format: {fork_id!r}")
        else:
            print(f"Unexpected 'eth' entry format: {eth_entry!r}")
    else:
        print("ENR does not contain the 'eth' key")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage:")
        print("  python3 enrdecode.py enr:-FDSjiog...")
        sys.exit(1)

    enr_arg = sys.argv[1]
    decode_enr(enr_arg)
