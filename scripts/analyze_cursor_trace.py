#!/usr/bin/env python3
"""Analyze or extract protobuf frames from an OpenSub native Cursor trace."""

import argparse
import base64
import collections
import gzip
import json
import os
from pathlib import Path


EXEC_FIELDS = {2, 3, 5, 7, 8, 10, 11, 14, 28, 29, 36}


def read_varint(data, offset):
    value = 0
    shift = 0
    while offset < len(data) and shift < 70:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, offset
        shift += 7
    raise ValueError("invalid varint")


def wire_fields(data):
    fields = []
    offset = 0
    while offset < len(data):
        key, offset = read_varint(data, offset)
        number = key >> 3
        wire = key & 7
        if number == 0:
            raise ValueError("field zero")
        value = None
        if wire == 0:
            value, offset = read_varint(data, offset)
        elif wire == 1:
            offset += 8
        elif wire == 2:
            length, offset = read_varint(data, offset)
            end = offset + length
            if end > len(data):
                raise ValueError("truncated bytes field")
            value = data[offset:end]
            offset = end
        elif wire == 5:
            offset += 4
        else:
            raise ValueError(f"unsupported wire type {wire}")
        if offset > len(data):
            raise ValueError("truncated fixed field")
        fields.append((number, wire, value))
    return fields


def connect_frames(data):
    frames = []
    offset = 0
    while offset + 5 <= len(data):
        flags = data[offset]
        length = int.from_bytes(data[offset + 1 : offset + 5], "big")
        end = offset + 5 + length
        if end > len(data):
            break
        payload = bytes(data[offset + 5 : end])
        decode_error = None
        if flags & 1:
            try:
                payload = gzip.decompress(payload)
            except Exception as error:  # Structural diagnostics only.
                decode_error = type(error).__name__
        frames.append((flags, payload, decode_error))
        offset = end
    return frames, len(data) - offset


def field_numbers(fields):
    return collections.Counter(str(number) for number, _, _ in fields)


def nested_bytes(fields, number):
    return [value for field, wire, value in fields if field == number and wire == 2]


def merge_counter(target, source):
    target.update(source)


def analyze_direction(data, direction):
    frames, trailing = connect_frames(data)
    report = {
        "bytes": len(data),
        "frames": len(frames),
        "compressed_frames": sum(1 for flags, _, _ in frames if flags & 1),
        "end_stream_frames": sum(1 for flags, _, _ in frames if flags & 2),
        "decode_errors": sum(1 for _, _, error in frames if error),
        "protobuf_errors": 0,
        "trailing_bytes": trailing,
        "top_level_fields": collections.Counter(),
        "exec_oneof_fields": collections.Counter(),
        "run_fields": collections.Counter(),
        "interaction_fields": collections.Counter(),
    }
    for flags, payload, decode_error in frames:
        if flags & 2 or decode_error:
            continue
        try:
            fields = wire_fields(payload)
        except ValueError:
            report["protobuf_errors"] += 1
            continue
        merge_counter(report["top_level_fields"], field_numbers(fields))
        if direction == "request":
            for nested in nested_bytes(fields, 1):
                try:
                    merge_counter(report["run_fields"], field_numbers(wire_fields(nested)))
                except ValueError:
                    report["protobuf_errors"] += 1
            exec_payloads = nested_bytes(fields, 2)
        else:
            for nested in nested_bytes(fields, 1):
                try:
                    merge_counter(
                        report["interaction_fields"], field_numbers(wire_fields(nested))
                    )
                except ValueError:
                    report["protobuf_errors"] += 1
            exec_payloads = nested_bytes(fields, 2)
        for nested in exec_payloads:
            try:
                nested_fields = wire_fields(nested)
            except ValueError:
                report["protobuf_errors"] += 1
                continue
            for number, wire, _ in nested_fields:
                if wire == 2 and number in EXEC_FIELDS:
                    report["exec_oneof_fields"][str(number)] += 1
    for key in [
        "top_level_fields",
        "exec_oneof_fields",
        "run_fields",
        "interaction_fields",
    ]:
        report[key] = dict(sorted(report[key].items(), key=lambda item: int(item[0])))
    return report


def matching_frames(data, top_field):
    matches = []
    frames, _ = connect_frames(data)
    for frame_index, (flags, payload, decode_error) in enumerate(frames):
        if flags & 2 or decode_error:
            continue
        try:
            fields = wire_fields(payload)
        except ValueError:
            continue
        if top_field is None or any(number == top_field for number, _, _ in fields):
            matches.append((frame_index, flags, payload))
    return matches


def dump_frames(streams, args):
    request_id = args.request_id
    if request_id not in streams:
        raise SystemExit(f"request id {request_id} is not present in the trace")

    output_dir = args.dump_frames
    output_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(output_dir, 0o700)
    data = streams[request_id][args.direction]
    frames = matching_frames(data, args.top_field)[: args.limit]
    manifest = []
    for frame_index, flags, payload in frames:
        filename = f"{args.direction}-{request_id}-frame-{frame_index}.pb"
        output_path = output_dir / filename
        output_path.write_bytes(payload)
        os.chmod(output_path, 0o600)
        manifest.append(
            {
                "file": filename,
                "frame_index": frame_index,
                "flags": flags,
                "bytes": len(payload),
            }
        )
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    os.chmod(manifest_path, 0o600)
    print(f"dumped {len(manifest)} frame(s) to {output_dir}")


def load_trace(path):
    streams = collections.defaultdict(
        lambda: {"metadata": None, "request": bytearray(), "response": bytearray()}
    )
    records = 0
    first_sequence = None
    last_sequence = None
    truncated = False
    with path.open("r", encoding="utf-8") as trace:
        for line in trace:
            record = json.loads(line)
            records += 1
            sequence = record.get("sequence")
            first_sequence = sequence if first_sequence is None else first_sequence
            last_sequence = sequence
            request_id = record.get("request_id")
            kind = record.get("kind")
            if kind == "trace_truncated":
                truncated = True
            if kind == "native_cursor_route":
                data = record.get("data", {})
                streams[request_id]["metadata"] = {
                    "model": data.get("model"),
                    "reasoning_effort": data.get("reasoning_effort"),
                    "transport": data.get("transport"),
                }
            elif kind == "request_body_chunk":
                streams[request_id]["request"].extend(base64.b64decode(record["data"]))
            elif kind == "response_body_chunk":
                streams[request_id]["response"].extend(base64.b64decode(record["data"]))
    return streams, {
        "records": records,
        "first_sequence": first_sequence,
        "last_sequence": last_sequence,
        "sequence_contiguous": (
            records == 0 or last_sequence - first_sequence + 1 == records
        ),
        "truncated": truncated,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--dump-frames", type=Path)
    parser.add_argument("--request-id", type=int)
    parser.add_argument("--direction", choices=["request", "response"])
    parser.add_argument("--top-field", type=int)
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()

    streams, integrity = load_trace(args.trace)
    if args.dump_frames:
        if args.request_id is None or args.direction is None:
            parser.error("--dump-frames requires --request-id and --direction")
        dump_frames(streams, args)
        return
    report = {
        "trace": str(args.trace),
        "integrity": integrity,
        "stream_count": len(streams),
        "streams": {},
    }
    for request_id in sorted(streams):
        stream = streams[request_id]
        report["streams"][str(request_id)] = {
            "metadata": stream["metadata"],
            "request": analyze_direction(stream["request"], "request"),
            "response": analyze_direction(stream["response"], "response"),
        }

    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
        os.chmod(args.output, 0o600)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
