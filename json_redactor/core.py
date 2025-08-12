from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
from typing import Iterable, Iterator, List, Optional, Sequence, Set, Tuple

import ijson  # type: ignore


REDACTION_TEXT = "***REDACTED***"


def _bool_to_json(b: bool) -> str:
    return "true" if b else "false"


def _dump_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _hash_init():
    return hashlib.sha256()


def _hash_update_utf8(hash, value: str):
    hash.update(value.encode("utf-8"))


def _hash_scalar_repr(event: str, value) -> str:
    """_summary_

    Args:
        event (str): _description_
        value (_type_): _description_

    Raises:
        ValueError: _description_

    Returns:
        str: _description_
    """
    if event == "string":
        return _dump_string(value)
    elif event == "number":
        return str(value)
    elif event == "boolean":
        return _bool_to_json(bool(value))
    elif event == "null":
        return "null"
    else:
        raise ValueError(f"Not a scalar event: {event}")


def _hash_subtree_repr(start_event: str, start_value, events: Iterator[Tuple[str, object]]) -> str:
    """_summary_
    Consume events for a subtree (starting at start_event) and return a SHA-256 hex digest
    of a canonical, whitespace-free JSON representation.

    This function **consumes** exactly the events that belong to this subtree.

    Args:
        start_event (str): _description_
        start_value (_type_): _description_
        events (Iterator[Tuple[str, object]]): _description_

    Raises:
        ValueError: _description_
        ValueError: _description_
        ValueError: _description_
        ValueError: _description_
        ValueError: _description_

    Returns:
        str: _description_
    """
    hash = _hash_init()

    def update(value: str):
        _hash_update_utf8(hash, value)

    def consume_container(container_start: str):
        if container_start == "start_map":
            update("{")
            first = True
            while True:
                event, val = next(events)  # StopIteration for malformed JSON
                if event == "map_key":
                    if not first:
                        update(",")
                    first = False
                    # key
                    update(_dump_string(val))
                    update(":")
                    # value (could be scalar or container)
                    event2, val2 = next(events)
                    if event2 in ("string", "number", "boolean", "null"):
                        update(_hash_scalar_repr(event2, val2))
                    elif event2 in ("start_map", "start_array"):
                        consume_container(event2)
                    else:
                        raise ValueError(f"Unexpected event inside object: {event2}")
                elif event == "end_map":
                    update("}")
                    break
                else:
                    raise ValueError(f"Unexpected event in object: {e}")
        elif container_start == "start_array":
            update("[")
            first = True
            while True:
                event, val = next(events)
                if event == "end_array":
                    update("]")
                    break
                if not first:
                    update(",")
                first = False
                if event in ("string", "number", "boolean", "null"):
                    update(_hash_scalar_repr(event, val))
                elif event in ("start_map", "start_array"):
                    consume_container(event)
                else:
                    raise ValueError(f"Unexpected event in array: {event}")
        else:
            raise ValueError(f"Not a container start: {container_start}")

    # entry: can be scalar or container
    if start_event in ("string", "number", "boolean", "null"):
        update(_hash_scalar_repr(start_event, start_value))
    elif start_event in ("start_map", "start_array"):
        consume_container(start_event)
    else:
        raise ValueError(f"Unexpected start event for subtree: {start_event}")

    return hash.hexdigest()


def _compile_regexes(regex_csv: Optional[str]) -> List[re.Pattern]:
    if not regex_csv:
        return []
    parts = [p.strip() for p in regex_csv.split(",") if p.strip()]
    return [re.compile(p, re.IGNORECASE) for p in parts]


def _load_keys_from_file(path: str) -> List[str]:
    keys: List[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            keys.append(s)
    return keys


def _should_redact_key(key: str, keys_lower: Set[str], regexes: Sequence[re.Pattern]) -> bool:
    if key.lower() in keys_lower:
        return True
    for pat in regexes:
        if pat.search(key):
            return True
    return False


def redact_stream(
    in_fh: io.TextIOBase,
    out_fh: io.TextIOBase,
    sensitive_keys: Sequence[str],
    regex_csv: Optional[str] = None,
    mode: str = "mask",
    pretty: bool = False,
) -> None:
    """_summary_
    Streaming redaction/ hashing. Reads from `in_fh`, writes to `out_fh`.

    - `mode`: "mask" (default) or "hash"
    - `pretty`: add whitespace for readability (minimal pretty to avoid buffering)

    Raises:
        ValueError: _description_
    """
    keys_lower = {key.lower() for key in sensitive_keys}
    regexes = _compile_regexes(regex_csv)

    # We'll parse tokens and emit canonical JSON (compact by default).
    events = ijson.basic_parse(in_fh)

    stack: List[dict] = []  # each entry: {"type": "map"/"array", "first": bool}
    indent = 0

    def w(value: str):
        out_fh.write(value)

    def w_nl():
        # minimal pretty printer to preserve streaming nature
        if pretty:
            out_fh.write("\n" + ("  " * indent))

    def write_array_value_separator():
        if not stack:
            return
        ctx = stack[-1]
        if ctx["type"] == "array":
            if not ctx["first"]:
                w(",")
                if pretty:
                    w(" ")
            ctx["first"] = False

    def write_map_entry_preamble():
        # Called when we see a new "map_key"
        ctx = stack[-1]
        assert ctx["type"] == "map"
        if not ctx["first"]:
            w(",")
        ctx["first"] = False
        if pretty:
            w_nl()

    try:
        for event, value in events:
            # Note: We only peek ahead when we match a sensitive key.
            if event == "start_map":
                write_array_value_separator()
                w("{")
                stack.append({"type": "map", "first": True})
                if pretty:
                    indent += 1
            elif event == "map_key":
                write_map_entry_preamble()
                key = str(value)
                w(_dump_string(key))
                w(":")
                if pretty:
                    w(" ")
                if _should_redact_key(key, keys_lower, regexes):
                    # consume the value's start event
                    e2, v2 = next(events)
                    if mode == "mask":
                        w(_dump_string(REDACTION_TEXT))
                        # if container, skip its entire subtree
                        if e2 in ("start_map", "start_array"):
                            # consume nested container fully
                            depth = 1
                            while depth:
                                e3, _ = next(events)
                                if e3 in ("start_map", "start_array"):
                                    depth += 1
                                elif e3 in ("end_map", "end_array"):
                                    depth -= 1
                        # if scalar -> nothing else to skip
                    elif mode == "hash":
                        digest = _hash_subtree_repr(e2, v2, events)
                        w(_dump_string(digest))
                    else:
                        raise ValueError(f"Unknown mode: {mode}")
                    # after writing masked/hashed value, continue to next token
                    continue
                else:
                    # not sensitive: let the next event handle writing of the value
                    pass
            elif event == "end_map":
                if pretty:
                    indent -= 1
                    w_nl()
                w("}")
                stack.pop()
            elif event == "start_array":
                write_array_value_separator()
                w("[")
                stack.append({"type": "array", "first": True})
                if pretty:
                    indent += 1
            elif event == "end_array":
                if pretty:
                    indent -= 1
                    w_nl()
                w("]")
                stack.pop()
            elif event in ("string", "number", "boolean", "null"):
                # Scalars can be array values or map values (right after a key we already wrote ":")
                if stack and stack[-1]["type"] == "array":
                    # manage commas in arrays
                    if not stack[-1]["first"]:
                        w(",")
                        if pretty:
                            w(" ")
                    stack[-1]["first"] = False
                # write the scalar
                if event == "string":
                    w(_dump_string(value))
                elif event == "number":
                    w(str(value))
                elif event == "boolean":
                    w(_bool_to_json(bool(value)))
                elif event == "null":
                    w("null")
            else:
                # Other events should not appear in basic_parse
                raise ValueError(f"Unexpected event: {event}")

        # Finish with newline if pretty
        if pretty:
            w("\n")
    except ijson.common.IncompleteJSONError as e:
        raise ValueError("Invalid or incomplete JSON input") from e
    except StopIteration as e:
        # mismatched starts/ends (malformed JSON)
        raise ValueError("Unexpected end of JSON while parsing") from e


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="json-redactor",
        description="Redact or hash sensitive values in JSON (stream-safe).",
    )
    p.add_argument(
        "input",
        nargs="?",
        help="Path to JSON file. If omitted or '-', read from STDIN.",
        default="-",
    )
    m = p.add_mutually_exclusive_group()
    m.add_argument("--mask", action="store_true", help='Mask values with "***REDACTED***" (default).')
    m.add_argument("--hash", dest="do_hash", action="store_true", help="Hash values with SHA-256 hex.")
    p.add_argument("--keys", help="Comma-separated sensitive keys (case-insensitive).")
    p.add_argument("--key-file", help="Path to a text file with one sensitive key per line.")
    p.add_argument(
        "--keys-regex",
        help="Comma-separated regex patterns for key names (case-insensitive). Example: '(?i)^credit.*|card$'",
    )
    p.add_argument("--pretty", action="store_true", help="Pretty print the output JSON.")
    p.add_argument("--encoding", default="utf-8", help="Input file encoding (default: utf-8).")
    return p


def main_cli(args: Optional[Sequence[str]] = None) -> int:
    """_summary_

    Args:
        args (Optional[Sequence[str]], optional): _description_. Defaults to None.

    Returns:
        int: _description_
    """
    parser = build_arg_parser()
    known_keys = parser.parse_args(args=args)

    sensitive_keys: List[str] = []
    if known_keys.keys:
        sensitive_keys.extend([key.strip() for key in known_keys.keys.split(",") if key.strip()])
    if known_keys.key_file:
        try:
            sensitive_keys.extend(_load_keys_from_file(known_keys.key_file))
        except FileNotFoundError:
            sys.stderr.write(f"error: key file not found: {known_keys.key_file}\n")
            return 2
        except Exception as e:
            sys.stderr.write(f"error: failed reading key file '{known_keys.key_file}': {e}\n")
            return 2

    if not sensitive_keys and not known_keys.keys_regex:
        sys.stderr.write("error: no sensitive keys provided (--keys/--key-file/--keys-regex)\n")
        return 2

    mode = "hash" if known_keys.do_hash else "mask"

    # Open input
    try:
        if not known_keys.input or known_keys.input == "-":
            in_fh = io.TextIOWrapper(sys.stdin.buffer, encoding=known_keys.encoding)
        else:
            in_fh = open(known_keys.input, "r", encoding=known_keys.encoding)
    except FileNotFoundError:
        sys.stderr.write(f"error: input file not found: {known_keys.input}\n")
        return 2
    except Exception as e:
        sys.stderr.write(f"error: cannot open input '{known_keys.input}': {e}\n")
        return 2

    try:
        redact_stream(
            in_fh=in_fh,
            out_fh=io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8"),
            sensitive_keys=sensitive_keys,
            regex_csv=known_keys.keys_regex,
            mode=mode,
            pretty=known_keys.pretty,
        )
        return 0
    except ValueError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2
    except Exception as e:
        sys.stderr.write(f"error: unexpected failure: {e}\n")
        return 2
    finally:
        if in_fh is not sys.stdin:
            try:
                in_fh.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main_cli())
