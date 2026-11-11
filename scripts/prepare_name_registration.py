#!/usr/bin/env python3
"""Prepare public TN10 registration JSON; never reads keys, signs or broadcasts."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def frame(text):
    raw = text.encode("ascii")
    if not 1 <= len(raw) <= 63 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in text):
        raise ValueError("Use a canonical lowercase namespace/slug, 1..63 bytes")
    return (bytes([len(raw)]) + raw + bytes(63 - len(raw))).hex()


def witness_context(script, index, entrypoint):
    data = bytes.fromhex(script)
    cursor, arguments = 0, []
    while cursor < len(data):
        opcode = data[cursor]
        cursor += 1
        if opcode in (0, 79) or 81 <= opcode <= 96:
            arguments.append({"opcode": opcode})
            continue
        if 1 <= opcode <= 75:
            length = opcode
        elif opcode in (76, 77):
            width = opcode - 75
            if cursor + width > len(data):
                raise ValueError("Truncated witness length")
            length = int.from_bytes(data[cursor:cursor + width], "little")
            cursor += width
        else:
            raise ValueError("Unsupported witness opcode")
        if cursor + length > len(data):
            raise ValueError("Truncated witness push")
        arguments.append({"data_hex": data[cursor:cursor + length].hex()})
        cursor += length
    redeem = arguments.pop()["data_hex"]
    return {"input_index": index, "entrypoint": entrypoint,
            "redeem_script_hex": redeem, "arguments": arguments}


def prepare(args):
    source, witness = read(args.witness_input), read(args.witness)
    parent_view, gap_view, fee_view = map(read, (args.parent_view, args.gap_view, args.fee_view))
    for view in (parent_view, gap_view, fee_view):
        if view["network"] != "testnet-10" or len(view["observations"]) != 2:
            raise ValueError("Require dual-node TN10 views")
        if not all(o["synced"] and o["utxo_indexed"] for o in view["observations"]):
            raise ValueError("Nodes must be synchronized and UTXO-indexed")
    if source["network"] != "testnet-10" or witness["network"] != "testnet-10":
        raise ValueError("TN10 only")
    if source["namespace_frame"] != frame(args.namespace) or source["slug_frame"] != frame(args.slug):
        raise ValueError("Witness name frames do not match requested name")
    if len(parent_view["utxos"]) != 1 or len(gap_view["utxos"]) != 1:
        raise ValueError("Select scripts with exactly one live parent/Gap")
    parent, gap = parent_view["utxos"][0], gap_view["utxos"][0]
    fee = next(u for u in fee_view["funding_utxos"] if u["outpoint"] == args.fee_outpoint)
    cid = source["parent_covenant_id"]
    if parent["covenant_id"] != cid or gap["covenant_id"] != cid:
        raise ValueError("Parent/Gap covenant identity mismatch")
    for role, utxo in (("parent", parent), ("gap", gap)):
        if witness["state_input_script_public_keys"][role] != utxo["script_public_key"]:
            raise ValueError("Witness does not bind live input script")
    if parent["amount"] != 1_000_000_000 or gap["amount"] != 100_000_000:
        raise ValueError("Unsupported parent/Gap amounts")
    change = fee["amount"] - 200_000_000 - args.fee_reserve_sompi
    if change <= 0:
        raise ValueError("Insufficient fee input for two net-new carriers and reserve")
    outputs = []
    for role, amount, index in (("parent_successor", 1_000_000_000, 0),
                               ("left_gap", 100_000_000, 1),
                               ("name_deed", 100_000_000, 1),
                               ("right_gap", 100_000_000, 1)):
        outputs.append({"role": role, "value": amount,
                        "script_public_key": witness["state_output_script_public_keys"][role],
                        "covenant_id": cid, "authorizing_input": index})
    outputs.append({"role": "fee_change", "value": change,
                    "script_public_key": fee["script_public_key"]})
    fee_script = bytes.fromhex(fee["script_public_key"])
    if len(fee_script) != 36 or fee_script[:3] != bytes.fromhex("000020") or fee_script[-1] != 172:
        raise ValueError("Require a canonical P2PK fee input")
    roles = {"parent": source["authority_xonly"], "claimant": source["claimant_xonly"],
             "target": source["target_authority_xonly"], "parent_for_child": source["authority_xonly"],
             "fee": fee_script[3:35].hex()}
    native = {"inputs": [parent, gap, fee], "outputs": outputs,
              "deed_state_bond_sompi": 1_000_000_000,
              "registration_entrypoint": "register_interior", "registration_kind": "INTERIOR",
              "role_public_keys": roles,
              "covenant_witness_contexts": [witness_context(witness["input_signature_scripts"][0], 0, "authorize_child"),
                                             witness_context(witness["input_signature_scripts"][1], 1, "register_interior")]}
    keys = {"schema": "KTAPEOUT-REGISTERED-KEYS-V1", "network": "testnet-10", "sequence": 1,
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "keys": [{"namespace": args.namespace, "key_hex": source["namespace_hash"],
                      "evidence_ref": args.issuance_txid}]}
    return {"network": "testnet-10", "namespace": args.namespace, "slug": args.slug,
            "owner": fee_view["address"], "namespace_key_sources": [keys],
            "nodes": fee_view["nodes"], "states": [{"role": "deed", "script_public_key": parent["script_public_key"]}],
            "gap_candidates": [{"gap": {"lo": source["gap_lo"], "hi": source["gap_hi"],
                                         "hiIsMax": source["gap_hi_is_max"]},
                                "script_public_key": gap["script_public_key"]}],
            "native_transaction_input": native}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("witness-input", "witness", "parent-view", "gap-view", "fee-view", "fee-outpoint",
                 "namespace", "slug", "issuance-txid", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--fee-reserve-sompi", type=int, required=True)
    args = parser.parse_args()
    if args.fee_reserve_sompi <= 0:
        parser.error("Positive fee reserve required")
    output = Path(args.output)
    if output.exists():
        parser.error("Output already exists; preserve the previous plan")
    result = prepare(args)
    with output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
