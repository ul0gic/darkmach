from __future__ import annotations

from dataclasses import dataclass

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

_QUALIFIERS: set[str] = {"r", "n", "N", "o", "O", "R", "V"}


@dataclass
class TypeInfo:
    encoding: str
    name: str
    is_object: bool
    is_pointer: bool
    is_struct: bool
    is_block: bool


def parse_type(encoding: str, pos: int = 0) -> tuple[TypeInfo, int]:
    """Parses one type at *pos*; the returned int is the index just past it."""
    if pos >= len(encoding):
        return TypeInfo(
            encoding="",
            name="void",
            is_object=False,
            is_pointer=False,
            is_struct=False,
            is_block=False,
        ), pos

    qualifiers: list[str] = []
    while pos < len(encoding) and encoding[pos] in _QUALIFIERS:
        qualifiers.append(encoding[pos])
        pos += 1

    if pos >= len(encoding):
        return TypeInfo(
            encoding="",
            name="void",
            is_object=False,
            is_pointer=False,
            is_struct=False,
            is_block=False,
        ), pos

    ch = encoding[pos]
    start = pos

    if ch == "@":
        pos += 1
        if pos < len(encoding) and encoding[pos] == "?":
            pos += 1
            raw = encoding[start:pos]
            return TypeInfo(
                encoding=raw,
                name="block",
                is_object=False,
                is_pointer=False,
                is_struct=False,
                is_block=True,
            ), pos
        if pos < len(encoding) and encoding[pos] == '"':
            pos += 1
            end_quote = encoding.find('"', pos)
            if end_quote == -1:
                class_name = encoding[pos:]
                pos = len(encoding)
            else:
                class_name = encoding[pos:end_quote]
                pos = end_quote + 1
            raw = encoding[start:pos]
            return TypeInfo(
                encoding=raw,
                name=f"{class_name} *",
                is_object=True,
                is_pointer=False,
                is_struct=False,
                is_block=False,
            ), pos
        raw = encoding[start:pos]
        return TypeInfo(
            encoding=raw,
            name="id",
            is_object=True,
            is_pointer=False,
            is_struct=False,
            is_block=False,
        ), pos

    if ch == "^":
        pos += 1
        inner, pos = parse_type(encoding, pos)
        raw = encoding[start:pos]
        return TypeInfo(
            encoding=raw,
            name=f"{inner.name} *",
            is_object=False,
            is_pointer=True,
            is_struct=False,
            is_block=False,
        ), pos

    if ch == "{":
        pos += 1
        struct_name, pos = _parse_struct_body(encoding, pos, "}")
        raw = encoding[start:pos]
        return TypeInfo(
            encoding=raw,
            name=struct_name,
            is_object=False,
            is_pointer=False,
            is_struct=True,
            is_block=False,
        ), pos

    if ch == "(":
        pos += 1
        union_name, pos = _parse_struct_body(encoding, pos, ")")
        raw = encoding[start:pos]
        return TypeInfo(
            encoding=raw,
            name=union_name,
            is_object=False,
            is_pointer=False,
            is_struct=True,
            is_block=False,
        ), pos

    if ch == "[":
        pos += 1
        while pos < len(encoding) and encoding[pos].isdigit():
            pos += 1
        inner, pos = parse_type(encoding, pos)
        if pos < len(encoding) and encoding[pos] == "]":
            pos += 1
        raw = encoding[start:pos]
        return TypeInfo(
            encoding=raw,
            name=f"{inner.name}[]",
            is_object=False,
            is_pointer=False,
            is_struct=False,
            is_block=False,
        ), pos

    if ch in _PRIMITIVE_TYPES:
        pos += 1
        raw = encoding[start:pos]
        name = _PRIMITIVE_TYPES[ch]
        if "r" in qualifiers:
            name = f"const {name}"
        return TypeInfo(
            encoding=raw,
            name=name,
            is_object=False,
            is_pointer=False,
            is_struct=False,
            is_block=False,
        ), pos

    pos += 1
    raw = encoding[start:pos]
    return TypeInfo(
        encoding=raw,
        name=f"?({ch})",
        is_object=False,
        is_pointer=False,
        is_struct=False,
        is_block=False,
    ), pos


def _parse_struct_body(encoding: str, pos: int, close_char: str) -> tuple[str, int]:
    """*pos* must point just past the opening brace/paren of ``{Name=fields}``."""
    name_start = pos
    while pos < len(encoding) and encoding[pos] not in ("=", close_char):
        pos += 1

    struct_name = encoding[name_start:pos]
    if not struct_name:
        struct_name = "struct"

    if pos < len(encoding) and encoding[pos] == "=":
        pos += 1
        depth = 1
        while pos < len(encoding) and depth > 0:
            if encoding[pos] == "{" or encoding[pos] == "(":
                depth += 1
            elif encoding[pos] == close_char:
                depth -= 1
                if depth == 0:
                    break
            elif encoding[pos] == "}" and close_char == ")":
                pass
            pos += 1

    if pos < len(encoding) and encoding[pos] == close_char:
        pos += 1

    return struct_name, pos


def parse_method_signature(encoding: str) -> list[TypeInfo]:
    """Returns ``[return_type, self, _cmd, arg0, ...]``; numeric stack offsets are skipped."""
    if not encoding:
        return []

    result: list[TypeInfo] = []
    pos = 0

    while pos < len(encoding):
        while pos < len(encoding) and encoding[pos].isdigit():
            pos += 1
        if pos >= len(encoding):
            break

        type_info, pos = parse_type(encoding, pos)
        result.append(type_info)

    return result


_MAX_DISPLAY_LEN = 200


def format_type_value(type_info: TypeInfo, raw_value: str) -> str:
    """Output is truncated at 200 characters."""
    if type_info.is_block:
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

    if name == "SEL":
        return _truncate(raw_value)

    if name == "Class":
        return _truncate(raw_value)

    if name in (
        "int",
        "unsigned int",
        "short",
        "unsigned short",
        "long",
        "unsigned long",
        "int64",
        "uint64",
        "char",
        "unsigned char",
        "BOOL",
    ):
        return _try_int(raw_value)

    if name in ("float", "double"):
        return _truncate(raw_value)

    if name in ("char *", "const char *"):
        return _truncate(raw_value)

    if name == "void":
        return "void"

    return _truncate(raw_value)


def format_method_args(encoding: str, arg_values: list[str]) -> str:
    """*arg_values* excludes self and _cmd — renders as ``(NSString *)arg0="hi" (int)arg1=42``."""
    types = parse_method_signature(encoding)
    if not types:
        return ""

    # types[0:3] are the return type, self and _cmd.
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


def _truncate(s: str) -> str:
    if len(s) <= _MAX_DISPLAY_LEN:
        return s
    return s[: _MAX_DISPLAY_LEN - 3] + "..."


def _try_hex(raw: str) -> str:
    try:
        n = int(raw, 0)
        return f"0x{n:x}"
    except (ValueError, TypeError):
        return raw


def _try_int(raw: str) -> str:
    try:
        return str(int(raw, 0))
    except (ValueError, TypeError):
        return raw
