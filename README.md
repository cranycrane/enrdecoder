# ENR Decoder

A simple Python script for decoding Ethereum Node Record (ENR) strings.

The script:
- removes the `enr:` prefix (if present),
- performs Base64 URL decoding,
- performs RLP decoding,
- prints key fields (`signature`, `seq`, `id`, `ip`, `tcp`, `udp`),
- tries to parse the `eth` entry (ForkID: `fork_hash`, `next_fork`).

## Requirements

- Python 3.8+
- Packages:
  - `rlp`
  - `eth-utils`

## Install dependencies

```bash
pip install rlp eth-utils
```

## Usage

```bash
python3 enrdecode.py "enr:-FDSjiog..."
```

Or without the prefix:

```bash
python3 enrdecode.py "-FDSjiog..."
```

## Example output

```text
--- ENR: enr:-FDSjiog... ---
Signature: 0x1234abcd...
Sequence No: 1
Scheme: v4
IP Address: 1.2.3.4
TCP Port: 30303
UDP Port: 30303

>>> ETH ENTRY (ForkID) <<<
Fork hash:       0x...
Next fork block: 0
```

## Error cases

- Invalid Base64 input:
  - `Base64 decode error: ...`
- Invalid RLP data:
  - `RLP decode error: ...`
- Wrong number of arguments:
  - the script prints usage instructions.

## Notes

- The script does not verify the ENR cryptographic signature, it only decodes content.
- The `eth` field may have a different format; in that case, the script prints an `Unexpected ... format` message.
