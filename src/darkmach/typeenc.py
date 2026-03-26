"""ObjC type encoding parser for method signature formatting.

Parses Objective-C type encoding strings (as returned by method_getTypeEncoding)
into structured TypeInfo objects. Used by the trace command formatter in the bridge
to render method arguments with human-readable type names.

Reference: https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/ObjCRuntimeGuide/Articles/ocrtTypeEncodings.html
"""

from __future__ import annotations

from dataclasses import dataclass

# -- Type mappings ---------------------------------------------------------

_PRIMITIVE_TYPES: dict[str, str] = {
    "v": "void",
    "c": "char",
    "C": "unsigned char",
    "s": "short",
    "S": "unsigned short",
    "i": "int",
    "I": "unsigned int",
    "l": "long",
    "L": "unsigned long",
    "q": "int64",
    "Q": "uint64",
    "f": "float",
    "d": "double",
    "B": "BOOL",
    "*": "char *",
    "#": "Class",
    ":": "SEL",
    "?": "unknown",
}

# Qualifier prefixes that modify the following type.
_QUALIFIERS: set[str] = {"r", "n", "N", "o", "O", "R", "V"}


@dataclass
class TypeInfo:
    """Parsed type from an ObjC type encoding."""

    encoding: str  # raw encoding string
    name: str  # human-readable name (e.g., "NSString *", "int", "CGRect")
    is_object: bool  # True for @ types (id, specific classes)
    is_pointer: bool  # True for ^ types
    is_struct: bool  # True for {} types
    is_block: bool  # True for @? type


# -- Parser ----------------------------------------------------------------


def parse_type(encoding: str, pos: int = 0) -> tuple[TypeInfo, int]:
    """Parse a single type starting at *pos* in the encoding string.

    Returns ``(TypeInfo, new_position)`` where *new_position* is the index
    immediately after the consumed type characters.
    """
    if pos >= len(encoding):
        return TypeInfo(encoding="", name="void", is_object=False, is_pointer=False,
                        is_struct=False, is_block=False), pos

    # Skip qualifier prefixes (r, n, N, o, O, R, V).
    qualifiers: list[str] = []
    while pos < len(encoding) and encoding[pos] in _QUALIFIERS:
        qualifiers.append(encoding[pos])
        pos += 1

    if pos >= len(encoding):
        return TypeInfo(encoding="", name="void", is_object=False, is_pointer=False,
                        is_struct=False, is_block=False), pos

    ch = encoding[pos]
    start = pos

    # -- Object type (@) ---------------------------------------------------
    if ch == "@":
        pos += 1
        # Block: @?
        if pos < len(encoding) and encoding[pos] == "?":
            pos += 1
            raw = encoding[start:pos]
            return TypeInfo(encoding=raw, name="block", is_object=False,
                            is_pointer=False, is_struct=False, is_block=True), pos
        # Quoted class name: @"ClassName"
        if pos < len(encoding) and encoding[pos] == '"':
            pos += 1  # skip opening quote
            end_quote = encoding.find('"', pos)
            if end_quote == -1:
                # Malformed -- consume rest
                class_name = encoding[pos:]
                pos = len(encoding)
            else:
                class_name = encoding[pos:end_quote]
                pos = end_quote + 1
            raw = encoding[start:pos]
            return TypeInfo(encoding=raw, name=f"{class_name} *", is_object=True,
                            is_pointer=False, is_struct=False, is_block=False), pos
        # Plain id
        raw = encoding[start:pos]
        return TypeInfo(encoding=raw, name="id", is_object=True,
                        is_pointer=False, is_struct=False, is_block=False), pos

    # -- Pointer (^) -------------------------------------------------------
    if ch == "^":
        pos += 1
        inner, pos = parse_type(encoding, pos)
        raw = encoding[start:pos]
        return TypeInfo(encoding=raw, name=f"{inner.name} *", is_object=False,
                        is_pointer=True, is_struct=False, is_block=False), pos

    # -- Struct ({Name=fields}) --------------------------------------------
    if ch == "{":
        pos += 1
        struct_name, pos = _parse_struct_body(encoding, pos, "}")
        raw = encoding[start:pos]
        return TypeInfo(encoding=raw, name=struct_name, is_object=False,
                        is_pointer=False, is_struct=True, is_block=False), pos

    # -- Union ((Name=fields)) ---------------------------------------------
    if ch == "(":
        pos += 1
        union_name, pos = _parse_struct_body(encoding, pos, ")")
        raw = encoding[start:pos]
        return TypeInfo(encoding=raw, name=union_name, is_object=False,
                        is_pointer=False, is_struct=True, is_block=False), pos

    # -- Array ([count type]) ----------------------------------------------
    if ch == "[":
        pos += 1
        # Skip digits (count)
        while pos < len(encoding) and encoding[pos].isdigit():
            pos += 1
        inner, pos = parse_type(encoding, pos)
        if pos < len(encoding) and encoding[pos] == "]":
            pos += 1
        raw = encoding[start:pos]
        return TypeInfo(encoding=raw, name=f"{inner.name}[]", is_object=False,
                        is_pointer=False, is_struct=False, is_block=False), pos

    # -- Primitive / known single-char types --------------------------------
    if ch in _PRIMITIVE_TYPES:
        pos += 1
        raw = encoding[start:pos]
        name = _PRIMITIVE_TYPES[ch]
        if "r" in qualifiers:
            name = f"const {name}"
        return TypeInfo(encoding=raw, name=name, is_object=False,
                        is_pointer=False, is_struct=False, is_block=False), pos

    # -- Unknown character -- consume it gracefully -------------------------
    pos += 1
    raw = encoding[start:pos]
    return TypeInfo(encoding=raw, name=f"?({ch})", is_object=False,
                    is_pointer=False, is_struct=False, is_block=False), pos


def _parse_struct_body(encoding: str, pos: int, close_char: str) -> tuple[str, int]:
    """Parse the inside of ``{Name=fields}`` or ``(Name=fields)``.

    *pos* should point to the character right after the opening brace/paren.
    Returns ``(struct_name, pos_after_close)``.
    """
    # Extract the name (everything up to '=' or the close char).
    name_start = pos
    while pos < len(encoding) and encoding[pos] not in ("=", close_char):
        pos += 1

    struct_name = encoding[name_start:pos]
    if not struct_name:
        struct_name = "struct"

    if pos < len(encoding) and encoding[pos] == "=":
        pos += 1  # skip '='
        # Parse (and discard) field types until the matching close char.
        depth = 1
        while pos < len(encoding) and depth > 0:
            if encoding[pos] == "{" or encoding[pos] == "(":
                depth += 1
            elif encoding[pos] == close_char:
                depth -= 1
                if depth == 0:
                    break
            elif encoding[pos] == "}" and close_char == ")":
                # Nested struct inside a union -- track separately.
                pass
            pos += 1

    # Consume the closing character.
    if pos < len(encoding) and encoding[pos] == close_char:
        pos += 1

    return struct_name, pos


# -- Method signature parser -----------------------------------------------


def parse_method_signature(encoding: str) -> list[TypeInfo]:
    """Parse a full ObjC method type encoding string.

    Returns a list of :class:`TypeInfo`: ``[return_type, self, _cmd, arg0, arg1, ...]``.
    Numeric stack offsets between types are skipped automatically.
    """
    if not encoding:
        return []

    result: list[TypeInfo] = []
    pos = 0

    while pos < len(encoding):
        # Skip numeric offsets.
        while pos < len(encoding) and encoding[pos].isdigit():
            pos += 1
        if pos >= len(encoding):
            break

        type_info, pos = parse_type(encoding, pos)
        result.append(type_info)

    return result


# -- Formatters ------------------------------------------------------------

_MAX_DISPLAY_LEN = 200


def format_type_value(type_info: TypeInfo, raw_value: str) -> str:
    """Format a runtime value for display based on its parsed type.

    * Objects: returned as-is (already a description string from the C side).
    * Integers: formatted as decimal.
    * Pointers / addresses: formatted as hex with ``0x`` prefix.
    * SELs: shown as the selector name string.
    * Structs: ``StructName{raw_value}``.
    * Blocks: ``<block at 0x...>``.
    * Long strings are truncated to 200 characters.
    """
    if type_info.is_block:
        # raw_value is typically a hex address
        addr = _try_hex(raw_value)
        return f"<block at {addr}>"

    if type_info.is_struct:
        text = f"{type_info.name}{{{raw_value}}}"
        return _truncate(text)

    if type_info.is_object:
        return _truncate(raw_value)

    if type_info.is_pointer:
        return _try_hex(raw_value)

    name = type_info.name

    # SEL -- just show the selector string.
    if name == "SEL":
        return _truncate(raw_value)

    # Class
    if name == "Class":
        return _truncate(raw_value)

    # Numeric types -- try to format as a number.
    if name in ("int", "unsigned int", "short", "unsigned short",
                "long", "unsigned long", "int64", "uint64",
                "char", "unsigned char", "BOOL"):
        return _try_int(raw_value)

    if name in ("float", "double"):
        return _truncate(raw_value)

    if name in ("char *", "const char *"):
        return _truncate(raw_value)

    if name == "void":
        return "void"

    # Fallback
    return _truncate(raw_value)


def format_method_args(encoding: str, arg_values: list[str]) -> str:
    """Format method arguments for display using the type encoding.

    Given a method type encoding and a list of argument value strings
    (excluding self and _cmd), returns a formatted string like::

        (NSString *)arg0="hello" (int)arg1=42

    Parameters
    ----------
    encoding:
        The full ObjC method type encoding (e.g. ``v24@0:8@16``).
    arg_values:
        Values for user arguments only (i.e. not self/_cmd).
    """
    types = parse_method_signature(encoding)
    if not types:
        return ""

    # types[0] = return type, types[1] = self, types[2] = _cmd, types[3:] = user args
    user_types = types[3:] if len(types) > 3 else []

    parts: list[str] = []
    for i, val in enumerate(arg_values):
        if i < len(user_types):
            ti = user_types[i]
            formatted = format_type_value(ti, val)
            parts.append(f"({ti.name})arg{i}={formatted}")
        else:
            parts.append(f"(?)arg{i}={val}")

    return " ".join(parts)


# -- Helpers ---------------------------------------------------------------


def _truncate(s: str) -> str:
    if len(s) <= _MAX_DISPLAY_LEN:
        return s
    return s[:_MAX_DISPLAY_LEN - 3] + "..."


def _try_hex(raw: str) -> str:
    """Try to format *raw* as a hex address."""
    try:
        n = int(raw, 0)
        return f"0x{n:x}"
    except (ValueError, TypeError):
        return raw


def _try_int(raw: str) -> str:
    """Try to format *raw* as a decimal integer."""
    try:
        return str(int(raw, 0))
    except (ValueError, TypeError):
        return raw
