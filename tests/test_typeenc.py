"""Tests for sphinx.typeenc -- ObjC type encoding parser."""

from __future__ import annotations

from sphinx.typeenc import (
    TypeInfo,
    format_method_args,
    format_type_value,
    parse_method_signature,
    parse_type,
)

# ── parse_type: primitives ────────────────────────────────────────


class TestParseTypePrimitives:
    def test_void(self):
        ti, pos = parse_type("v")
        assert ti.name == "void"
        assert ti.encoding == "v"
        assert pos == 1
        assert not ti.is_object
        assert not ti.is_pointer
        assert not ti.is_struct
        assert not ti.is_block

    def test_char(self):
        ti, _ = parse_type("c")
        assert ti.name == "char"

    def test_unsigned_char(self):
        ti, _ = parse_type("C")
        assert ti.name == "unsigned char"

    def test_short(self):
        ti, _ = parse_type("s")
        assert ti.name == "short"

    def test_unsigned_short(self):
        ti, _ = parse_type("S")
        assert ti.name == "unsigned short"

    def test_int(self):
        ti, _ = parse_type("i")
        assert ti.name == "int"

    def test_unsigned_int(self):
        ti, _ = parse_type("I")
        assert ti.name == "unsigned int"

    def test_long(self):
        ti, _ = parse_type("l")
        assert ti.name == "long"

    def test_unsigned_long(self):
        ti, _ = parse_type("L")
        assert ti.name == "unsigned long"

    def test_long_long(self):
        ti, _ = parse_type("q")
        assert ti.name == "int64"

    def test_unsigned_long_long(self):
        ti, _ = parse_type("Q")
        assert ti.name == "uint64"

    def test_float(self):
        ti, _ = parse_type("f")
        assert ti.name == "float"

    def test_double(self):
        ti, _ = parse_type("d")
        assert ti.name == "double"

    def test_bool(self):
        ti, _ = parse_type("B")
        assert ti.name == "BOOL"

    def test_c_string(self):
        ti, _ = parse_type("*")
        assert ti.name == "char *"

    def test_position_advances_by_one(self):
        _, pos = parse_type("i")
        assert pos == 1

    def test_parse_at_offset(self):
        ti, pos = parse_type("xid", 1)
        assert ti.name == "int"
        assert pos == 2


# ── parse_type: object types ─────────────────────────────────────


class TestParseTypeObjects:
    def test_basic_object(self):
        ti, pos = parse_type("@")
        assert ti.name == "id"
        assert ti.is_object
        assert not ti.is_block
        assert pos == 1

    def test_block(self):
        ti, pos = parse_type("@?")
        assert ti.name == "block"
        assert ti.is_block
        assert not ti.is_object
        assert pos == 2

    def test_class(self):
        ti, _ = parse_type("#")
        assert ti.name == "Class"
        assert not ti.is_object

    def test_sel(self):
        ti, _ = parse_type(":")
        assert ti.name == "SEL"

    def test_quoted_class_name(self):
        ti, pos = parse_type('@"NSString"')
        assert ti.name == "NSString *"
        assert ti.is_object
        assert pos == len('@"NSString"')

    def test_quoted_class_name_in_context(self):
        ti, pos = parse_type('@"UIView"i', 0)
        assert ti.name == "UIView *"
        assert ti.is_object
        assert pos == len('@"UIView"')


# ── parse_type: complex types ────────────────────────────────────


class TestParseTypeComplex:
    def test_pointer_to_int(self):
        ti, pos = parse_type("^i")
        assert ti.name == "int *"
        assert ti.is_pointer
        assert pos == 2

    def test_pointer_to_object(self):
        ti, pos = parse_type("^@")
        assert ti.name == "id *"
        assert ti.is_pointer
        assert pos == 2

    def test_double_pointer(self):
        ti, pos = parse_type("^^i")
        assert ti.name == "int * *"
        assert ti.is_pointer
        assert pos == 3

    def test_simple_struct(self):
        ti, pos = parse_type("{CGPoint=dd}")
        assert ti.name == "CGPoint"
        assert ti.is_struct
        assert pos == len("{CGPoint=dd}")

    def test_nested_struct(self):
        ti, pos = parse_type("{CGRect={CGPoint=dd}{CGSize=dd}}")
        assert ti.name == "CGRect"
        assert ti.is_struct
        assert pos == len("{CGRect={CGPoint=dd}{CGSize=dd}}")

    def test_struct_with_mixed_types(self):
        ti, pos = parse_type("{MyStruct=i@d}")
        assert ti.name == "MyStruct"
        assert ti.is_struct
        assert pos == len("{MyStruct=i@d}")

    def test_unnamed_struct(self):
        ti, _ = parse_type("{=ii}")
        assert ti.name == "struct"
        assert ti.is_struct

    def test_union(self):
        ti, pos = parse_type("(MyUnion=id)")
        assert ti.name == "MyUnion"
        assert ti.is_struct  # unions reported as struct-like
        assert pos == len("(MyUnion=id)")

    def test_array(self):
        ti, pos = parse_type("[10i]")
        assert ti.name == "int[]"
        assert pos == len("[10i]")

    def test_pointer_to_struct(self):
        ti, _pos = parse_type("^{CGPoint=dd}")
        assert ti.name == "CGPoint *"
        assert ti.is_pointer


# ── parse_type: qualifiers ───────────────────────────────────────


class TestParseTypeQualifiers:
    def test_const_char_star(self):
        ti, pos = parse_type("r*")
        assert ti.name == "const char *"
        assert pos == 2

    def test_const_object(self):
        # r@ = const id -- qualifier stripped, base type is id
        ti, pos = parse_type("r@")
        assert ti.name == "id"
        assert ti.is_object
        assert pos == 2

    def test_multiple_qualifiers(self):
        # rn@ = const in id
        ti, pos = parse_type("rn@")
        assert ti.is_object
        assert pos == 3

    def test_oneway_void(self):
        ti, _ = parse_type("Vv")
        assert ti.name == "void"


# ── parse_type: edge cases ───────────────────────────────────────


class TestParseTypeEdgeCases:
    def test_empty_string(self):
        ti, pos = parse_type("")
        assert ti.name == "void"
        assert pos == 0

    def test_single_char(self):
        ti, pos = parse_type("i")
        assert ti.name == "int"
        assert pos == 1

    def test_unknown_character(self):
        ti, pos = parse_type("Z")
        assert "Z" in ti.name  # graceful handling, contains the unknown char
        assert pos == 1

    def test_unknown_char_does_not_crash(self):
        # Should not raise any exception
        _ti, pos = parse_type("~!$")
        assert pos == 1  # consumed one character

    def test_past_end_position(self):
        ti, pos = parse_type("i", 5)
        assert ti.name == "void"
        assert pos == 5

    def test_struct_missing_close(self):
        # Malformed -- no closing brace. Should not crash.
        ti, pos = parse_type("{Foo=ii")
        assert ti.name == "Foo"
        assert pos == len("{Foo=ii")

    def test_quoted_class_missing_close_quote(self):
        ti, pos = parse_type('@"NSString')
        assert "NSString" in ti.name
        assert pos == len('@"NSString')


# ── parse_method_signature ───────────────────────────────────────


class TestParseMethodSignature:
    def test_void_method_one_object_arg(self):
        # v24@0:8@16 -- void, self, _cmd, one id arg
        types = parse_method_signature("v24@0:8@16")
        assert len(types) == 4
        assert types[0].name == "void"  # return
        assert types[1].name == "id"  # self
        assert types[2].name == "SEL"  # _cmd
        assert types[3].name == "id"  # arg0

    def test_returns_object_takes_int(self):
        # @24@0:8i16
        types = parse_method_signature("@24@0:8i16")
        assert len(types) == 4
        assert types[0].name == "id"
        assert types[3].name == "int"

    def test_void_two_object_args(self):
        # v32@0:8@16@24
        types = parse_method_signature("v32@0:8@16@24")
        assert len(types) == 5
        assert types[0].name == "void"
        assert types[3].name == "id"
        assert types[4].name == "id"

    def test_returns_bool_takes_sel(self):
        # B24@0:8:16
        types = parse_method_signature("B24@0:8:16")
        assert len(types) == 4
        assert types[0].name == "BOOL"
        assert types[3].name == "SEL"

    def test_returns_cgrect(self):
        # {CGRect={CGPoint=dd}{CGSize=dd}}48@0:8
        enc = "{CGRect={CGPoint=dd}{CGSize=dd}}48@0:8"
        types = parse_method_signature(enc)
        assert len(types) == 3
        assert types[0].name == "CGRect"
        assert types[0].is_struct
        assert types[1].name == "id"
        assert types[2].name == "SEL"

    def test_empty_string(self):
        types = parse_method_signature("")
        assert types == []

    def test_no_user_args(self):
        # v16@0:8 -- just self and _cmd, no user args
        types = parse_method_signature("v16@0:8")
        assert len(types) == 3
        assert types[0].name == "void"

    def test_multiple_typed_args(self):
        # v40@0:8@16i24d28 -- void, self, _cmd, id, int, double
        types = parse_method_signature("v40@0:8@16i24d28")
        assert len(types) == 6
        assert types[3].name == "id"
        assert types[4].name == "int"
        assert types[5].name == "double"

    def test_block_argument(self):
        # v24@0:8@?16 -- void, self, _cmd, block
        types = parse_method_signature("v24@0:8@?16")
        assert len(types) == 4
        assert types[3].is_block
        assert types[3].name == "block"


# ── format_type_value ────────────────────────────────────────────


class TestFormatTypeValue:
    def _ti(self, **kwargs):
        defaults = {
            "encoding": "", "name": "id", "is_object": False,
            "is_pointer": False, "is_struct": False, "is_block": False,
        }
        defaults.update(kwargs)
        return TypeInfo(**defaults)

    def test_object_value_passthrough(self):
        ti = self._ti(is_object=True, name="id")
        assert format_type_value(ti, "<NSString: hello>") == "<NSString: hello>"

    def test_integer_value(self):
        ti = self._ti(name="int")
        assert format_type_value(ti, "42") == "42"

    def test_integer_hex_input(self):
        ti = self._ti(name="int")
        assert format_type_value(ti, "0xff") == "255"

    def test_pointer_hex_format(self):
        ti = self._ti(is_pointer=True, name="int *")
        assert format_type_value(ti, "4294967296") == "0x100000000"

    def test_sel_value(self):
        ti = self._ti(name="SEL")
        assert format_type_value(ti, "viewDidLoad") == "viewDidLoad"

    def test_struct_value(self):
        ti = self._ti(is_struct=True, name="CGRect")
        result = format_type_value(ti, "0,0,375,812")
        assert result == "CGRect{0,0,375,812}"

    def test_block_value(self):
        ti = self._ti(is_block=True, name="block")
        result = format_type_value(ti, "0x1000abcde")
        assert result == "<block at 0x1000abcde>"

    def test_block_value_decimal(self):
        ti = self._ti(is_block=True, name="block")
        result = format_type_value(ti, "4294967296")
        assert result == "<block at 0x100000000>"

    def test_void_value(self):
        ti = self._ti(name="void")
        assert format_type_value(ti, "") == "void"

    def test_bool_value(self):
        ti = self._ti(name="BOOL")
        assert format_type_value(ti, "1") == "1"

    def test_float_value(self):
        ti = self._ti(name="float")
        assert format_type_value(ti, "3.14") == "3.14"

    def test_char_star_value(self):
        ti = self._ti(name="char *")
        assert format_type_value(ti, "hello world") == "hello world"

    def test_class_value(self):
        ti = self._ti(name="Class")
        assert format_type_value(ti, "NSObject") == "NSObject"

    def test_long_string_truncation(self):
        ti = self._ti(is_object=True, name="id")
        long_val = "A" * 300
        result = format_type_value(ti, long_val)
        assert len(result) == 200
        assert result.endswith("...")

    def test_pointer_non_numeric_passthrough(self):
        ti = self._ti(is_pointer=True, name="int *")
        assert format_type_value(ti, "not_a_number") == "not_a_number"

    def test_integer_non_numeric_passthrough(self):
        ti = self._ti(name="int")
        assert format_type_value(ti, "not_a_number") == "not_a_number"


# ── format_method_args ───────────────────────────────────────────


class TestFormatMethodArgs:
    def test_simple_one_arg(self):
        # v24@0:8@16 -- void method, one id arg
        result = format_method_args("v24@0:8@16", ["<NSString: hello>"])
        assert "(id)arg0=<NSString: hello>" in result

    def test_two_args(self):
        result = format_method_args("v32@0:8@16i24", ["some object", "42"])
        assert "(id)arg0=some object" in result
        assert "(int)arg1=42" in result

    def test_no_user_args(self):
        result = format_method_args("v16@0:8", [])
        assert result == ""

    def test_empty_encoding(self):
        result = format_method_args("", ["value"])
        assert result == ""

    def test_more_values_than_types(self):
        # Only one typed user arg but two values provided
        result = format_method_args("v24@0:8@16", ["val0", "val1"])
        assert "(id)arg0=val0" in result
        assert "(?)arg1=val1" in result

    def test_fewer_values_than_types(self):
        # Two typed user args but only one value provided
        result = format_method_args("v32@0:8@16i24", ["only one"])
        assert "(id)arg0=only one" in result
        assert "arg1" not in result

    def test_block_arg_formatted(self):
        result = format_method_args("v24@0:8@?16", ["0x1234"])
        assert "<block at 0x1234>" in result

    def test_struct_arg_formatted(self):
        enc = "v48@0:8{CGRect={CGPoint=dd}{CGSize=dd}}16"
        result = format_method_args(enc, ["0,0,100,200"])
        assert "CGRect" in result


# ── TypeInfo dataclass ───────────────────────────────────────────


class TestTypeInfoDataclass:
    def test_creation(self):
        ti = TypeInfo(encoding="@", name="id", is_object=True,
                      is_pointer=False, is_struct=False, is_block=False)
        assert ti.encoding == "@"
        assert ti.name == "id"
        assert ti.is_object

    def test_equality(self):
        ti1 = TypeInfo(encoding="i", name="int", is_object=False,
                       is_pointer=False, is_struct=False, is_block=False)
        ti2 = TypeInfo(encoding="i", name="int", is_object=False,
                       is_pointer=False, is_struct=False, is_block=False)
        assert ti1 == ti2

    def test_repr(self):
        ti = TypeInfo(encoding="i", name="int", is_object=False,
                      is_pointer=False, is_struct=False, is_block=False)
        r = repr(ti)
        assert "int" in r
        assert "TypeInfo" in r
