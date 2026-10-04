# -*- coding: utf-8 -*-
"""aotopsy_apply.py — IDA idalib script

Reads flutter_meta.json produced by `aotopsy meta`, applies:
  1. All struct types (DartThread + Dart classes) via parse_decls — one shot
  2. Function creation + renaming
  3. Function signatures with typed this pointers referencing structs
  4. EOL comments (THR fields, PP pool refs, string refs)
  5. Hex-Rays decompilation of focus functions

Pattern follows IL2CppDumper: generate C header, parse_decls(), apply_type().

Usage:
  python3 aotopsy_apply.py <libapp.so> <flutter_meta.json> [<output_dir>]

Requires:
  - IDA Pro with idalib (idapro Python package)
  - Hex-Rays decompiler for ARM64 (for decompilation phase)
"""

import json
import hashlib
import os
import sys
import time

try:
    _TEXT_TYPES = (basestring,)
    _INTEGER_TYPES = (int, long)
except NameError:
    _TEXT_TYPES = (str,)
    _INTEGER_TYPES = (int,)


def log(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


_C_KEYWORDS = set((
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if", "inline",
    "int", "long", "register", "restrict", "return", "short", "signed", "sizeof",
    "static", "struct", "switch", "typedef", "union", "unsigned", "void", "volatile",
    "while", "_Alignas", "_Alignof", "_Atomic", "_Bool", "_Complex", "_Generic",
    "_Imaginary", "_Noreturn", "_Static_assert", "_Thread_local",
    "alignas", "alignof", "and", "and_eq", "asm", "bitand", "bitor", "bool",
    "catch", "char16_t", "char32_t", "class", "compl", "concept", "consteval",
    "constexpr", "constinit", "const_cast", "co_await", "co_return", "co_yield",
    "decltype", "delete", "dynamic_cast", "explicit", "export", "false", "friend",
    "mutable", "namespace", "new", "noexcept", "not", "not_eq", "nullptr", "operator",
    "or", "or_eq", "private", "protected", "public", "reinterpret_cast", "requires",
    "static_assert", "static_cast", "template", "this", "thread_local", "throw", "true",
    "try", "typeid", "typename", "using", "virtual", "wchar_t", "xor", "xor_eq",
))


def sanitize(name):
    """Return an ASCII C-style identifier without merging distinct raw names."""
    raw = name or ""
    out = []
    changed = _has_identity_suffix(raw)
    for ch in raw:
        if ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9") or ch == "_":
            out.append(ch)
        else:
            out.append("_")
            changed = True
    s = "".join(out)
    if not s:
        s = "_anon"
        changed = True
    if "0" <= s[0] <= "9":
        s = "_" + s
        changed = True
    if s in _C_KEYWORDS:
        s = "_" + s
        changed = True
    suffix = ""
    if changed:
        suffix = "_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
    limit = 120 - len(suffix)
    if len(s) > limit:
        suffix = "_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
        s = s[:120 - len(suffix)]
    return s + suffix


def _has_identity_suffix(name):
    pos = name.rfind("_")
    if pos < 0 or len(name) - pos - 1 != 32:
        return False
    return all(ch in "0123456789abcdef" for ch in name[pos + 1:])


def function_identifier(name, addr):
    """Tool-boundary function identifier: readable raw identity + exact VA."""
    return "%s_a%x" % (sanitize(name), addr)


def _canonical_hex_addr(value, label):
    if not isinstance(value, _TEXT_TYPES) or not value.startswith("0x") or len(value) < 3:
        raise ValueError("%s must be a canonical 0x-prefixed address" % label)
    try:
        parsed = int(value[2:], 16)
    except Exception:
        raise ValueError("%s must be a canonical hexadecimal address" % label)
    if value != "0x%x" % parsed:
        raise ValueError("%s is not canonical: %r" % (label, value))
    return parsed


def _positive_int(value, label, allow_zero=False):
    if isinstance(value, bool) or not isinstance(value, _INTEGER_TYPES):
        raise ValueError("%s must be an integer" % label)
    if value < 0 or (value == 0 and not allow_zero):
        raise ValueError("%s has invalid value %r" % (label, value))
    return value


def validate_meta_records(meta):
    """Reject structurally unsafe/tampered schema-v3 records before mutation."""
    pointer_size = meta["pointer_size"]
    functions = meta.get("functions", [])
    if not isinstance(functions, list):
        raise ValueError("functions must be an array")
    function_addrs = set()
    for i, entry in enumerate(functions):
        if not isinstance(entry, dict):
            raise ValueError("functions[%d] must be an object" % i)
        addr = entry.get("addr")
        _canonical_hex_addr(addr, "functions[%d].addr" % i)
        if addr in function_addrs:
            raise ValueError("duplicate function address %s" % addr)
        function_addrs.add(addr)
        name = entry.get("name")
        if not isinstance(name, _TEXT_TYPES) or not name:
            raise ValueError("functions[%d].name must be non-empty" % i)
        size = _positive_int(entry.get("size"), "functions[%d].size" % i)
        if size > 64 * 1024 * 1024:
            raise ValueError("functions[%d].size exceeds the 64 MiB artifact limit" % i)
        _positive_int(entry.get("param_count", 0), "functions[%d].param_count" % i, allow_zero=True)

    focus = meta.get("focus_functions", [])
    if not isinstance(focus, list):
        raise ValueError("focus_functions must be an array")
    seen_focus = set()
    for i, addr in enumerate(focus):
        _canonical_hex_addr(addr, "focus_functions[%d]" % i)
        if addr not in function_addrs:
            raise ValueError("focus function %s is absent from functions" % addr)
        if addr in seen_focus:
            raise ValueError("duplicate focus function %s" % addr)
        seen_focus.add(addr)

    comments = meta.get("comments", [])
    if not isinstance(comments, list):
        raise ValueError("comments must be an array")
    seen_comments = set()
    for i, entry in enumerate(comments):
        if not isinstance(entry, dict):
            raise ValueError("comments[%d] must be an object" % i)
        addr = entry.get("addr")
        _canonical_hex_addr(addr, "comments[%d].addr" % i)
        if addr in seen_comments:
            raise ValueError("duplicate comment address %s" % addr)
        seen_comments.add(addr)
        if not isinstance(entry.get("text"), _TEXT_TYPES):
            raise ValueError("comments[%d].text must be a string" % i)

    thr_fields = meta["thr_fields"]
    seen_thr_offsets = set()
    for i, field in enumerate(thr_fields):
        if not isinstance(field, dict):
            raise ValueError("thr_fields[%d] must be an object" % i)
        off = _positive_int(field.get("offset"), "thr_fields[%d].offset" % i, allow_zero=True)
        if off in seen_thr_offsets:
            raise ValueError("duplicate THR field offset 0x%x" % off)
        seen_thr_offsets.add(off)
        if not isinstance(field.get("name"), _TEXT_TYPES) or not field.get("name"):
            raise ValueError("thr_fields[%d].name must be non-empty" % i)

    classes = meta.get("classes", [])
    if not isinstance(classes, list):
        raise ValueError("classes must be an array")
    seen_cids = set()
    for i, cls in enumerate(classes):
        if not isinstance(cls, dict):
            raise ValueError("classes[%d] must be an object" % i)
        cname = cls.get("class_name")
        if not isinstance(cname, _TEXT_TYPES) or not cname:
            raise ValueError("classes[%d].class_name must be non-empty" % i)
        cid = _positive_int(cls.get("class_id"), "classes[%d].class_id" % i)
        if cid in seen_cids:
            raise ValueError("duplicate class_id %d" % cid)
        seen_cids.add(cid)
        size = _positive_int(cls.get("instance_size"), "classes[%d].instance_size" % i)
        if size < 8 or size % pointer_size != 0:
            raise ValueError("classes[%d].instance_size is not a valid Dart word layout" % i)
        fields = cls.get("fields")
        if not isinstance(fields, list):
            raise ValueError("classes[%d].fields must be an array" % i)
        offsets = set()
        for j, field in enumerate(fields):
            if not isinstance(field, dict):
                raise ValueError("classes[%d].fields[%d] must be an object" % (i, j))
            name = field.get("name")
            if not isinstance(name, _TEXT_TYPES) or not name:
                raise ValueError("classes[%d].fields[%d].name must be non-empty" % (i, j))
            off = _positive_int(field.get("byte_offset"), "classes[%d].fields[%d].byte_offset" % (i, j))
            if off < 8 or off % pointer_size != 0 or off + pointer_size > size:
                raise ValueError("classes[%d].fields[%d] has invalid byte_offset" % (i, j))
            if off in offsets:
                raise ValueError("classes[%d] has duplicate field offset 0x%x" % (i, off))
            offsets.add(off)
            is_reference = field.get("is_reference")
            if not isinstance(is_reference, bool):
                raise ValueError("classes[%d].fields[%d].is_reference must be boolean" % (i, j))
            slot_type = field.get("slot_type")
            if slot_type not in ("type_arguments_field", "instance_field", "unknown_slot"):
                raise ValueError("classes[%d].fields[%d] has invalid slot_type" % (i, j))
            if slot_type == "type_arguments_field" and not is_reference:
                raise ValueError("classes[%d].fields[%d] has non-reference type_arguments_field" % (i, j))


def resolve_meta_path(argv):
    """Resolve flutter_meta.json path from argv or relative to this script."""
    if len(argv) >= 3 and argv[2]:
        return argv[2]
    # Standalone mode: look for ../flutter_meta.json relative to this script.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(script_dir, "..", "flutter_meta.json")
    if os.path.exists(candidate):
        return candidate
    return None


def apply_metadata(meta, idc, ida_funcs, ida_typeinf, ida_auto=None, binary_path=None):
    """Apply aotopsy metadata to an open IDA database (phases 1-4).

    Importable by ida-headless-mcp's worker without opening a database.

    Args:
        meta: parsed flutter_meta.json dict
        idc: IDA idc module
        ida_funcs: IDA ida_funcs module
        ida_typeinf: IDA ida_typeinf module
        ida_auto: IDA ida_auto module (optional, for re-analysis after func creation)

    Returns:
        dict with stats: functions_created, functions_named, structs_created,
        signatures_applied, comments_set
    """
    if meta.get("version") != "3" or meta.get("arch") != "arm64":
        raise ValueError("flutter_meta.json must be schema version 3 for arch arm64")
    missing = [k for k in ("dart_version", "binary_sha256", "binary_size", "compressed_pointers", "pointer_size", "thr_fields")
               if k not in meta]
    if missing:
        raise ValueError("flutter_meta.json missing required field(s): %s" % ", ".join(missing))
    if not isinstance(meta["compressed_pointers"], bool):
        raise ValueError("compressed_pointers must be a boolean")
    expected_pointer_size = 4 if meta["compressed_pointers"] else 8
    if meta["pointer_size"] != expected_pointer_size:
        raise ValueError("pointer_size %r disagrees with compressed_pointers=%r (want %d)" % (
            meta["pointer_size"], meta["compressed_pointers"], expected_pointer_size))
    if not isinstance(meta["dart_version"], _TEXT_TYPES) or not meta["dart_version"] or not isinstance(meta["thr_fields"], list):
        raise ValueError("dart_version must be non-empty and thr_fields must be an array")
    binary_sha256 = meta["binary_sha256"]
    binary_size = meta["binary_size"]
    if not isinstance(binary_sha256, _TEXT_TYPES) or len(binary_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in binary_sha256):
        raise ValueError("binary_sha256 must be 64 lowercase hex characters")
    if isinstance(binary_size, bool) or not isinstance(binary_size, _INTEGER_TYPES) or binary_size <= 0:
        raise ValueError("binary_size must be a positive integer")
    validate_meta_records(meta)
    if not binary_path or not os.path.isfile(binary_path):
        raise ValueError("binary path is required to verify flutter_meta.json provenance")
    if os.path.getsize(binary_path) != binary_size:
        raise ValueError("binary size does not match flutter_meta.json provenance")
    digest = hashlib.sha256()
    with open(binary_path, "rb") as bf:
        while True:
            chunk = bf.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    if digest.hexdigest() != binary_sha256:
        raise ValueError("binary SHA-256 does not match flutter_meta.json provenance")

    pointer_size = meta["pointer_size"]
    log("  pointer_size: %d" % pointer_size)

    stats = {
        "functions_created": 0,
        "functions_named": 0,
        "structs_created": 0,
        "signatures_applied": 0,
        "comments_set": 0,
    }

    # ================================================================
    # Phase 1: Generate C header and parse all types at once
    # ================================================================
    thr_fields = meta.get("thr_fields", [])
    classes = meta.get("classes", [])
    struct_names = {}  # dart class_name -> C struct name
    owner_counts = {}
    for cls in classes:
        cname = cls["class_name"]
        owner_counts[cname] = owner_counts.get(cname, 0) + 1

    header_lines = []
    header_lines.append("// Auto-generated by aotopsy for IDA")
    header_lines.append("")

    if thr_fields:
        header_lines.append(build_dart_thread_struct(thr_fields))
        header_lines.append("")

    for cls in classes:
        cname = cls.get("class_name", "")
        if not cname:
            continue
        sname = "Dart_%s_cid%d" % (sanitize(cname), cls["class_id"])
        size = cls.get("instance_size", 0)
        if size <= 0:
            continue
        fields = cls.get("fields", [])
        header_lines.append(build_class_struct(sname, size, fields, pointer_size))
        header_lines.append("")
        if owner_counts[cname] == 1:
            struct_names[cname] = sname

    header = "\n".join(header_lines)

    if header.strip():
        nerr = ida_typeinf.idc_parse_types(header, 0)
        stats["structs_created"] = len(struct_names) + (1 if thr_fields else 0)
        if nerr == 0:
            log("Phase 1: parsed %d struct types (0 errors)" % stats["structs_created"])
        else:
            log("Phase 1: WARN: %d parse errors" % nerr)
    else:
        log("Phase 1: skipped (no types)")

    # ================================================================
    # Phase 2: Create/rename functions
    # ================================================================
    functions = meta.get("functions", [])
    log("Phase 2: creating/renaming %d functions..." % len(functions))

    # P2.5-5: Build a set of known function start addresses from metadata.
    # Only split mid-function at addresses that ARE in this set — prevents
    # stale flutter_meta.json from corrupting the IDA database by splitting
    # at wrong addresses.
    known_starts = set()
    for entry in functions:
        known_starts.add(int(entry["addr"], 16))

    split_count = 0
    split_skipped = 0
    for entry in functions:
        addr = int(entry["addr"], 16)
        name = function_identifier(entry["name"], addr)
        size = entry.get("size", 0)

        # Split mid-function addresses (Dart checked/unchecked entries).
        # P2.5-5: Only split if addr is a known function start (in our metadata).
        fn = ida_funcs.get_func(addr)
        if fn is not None and fn.start_ea != addr:
            # Verify the current function's start is NOT in our known set
            # (if it is, we'd be splitting a valid function at a wrong address).
            if fn.start_ea in known_starts and addr in known_starts:
                # Both are known starts — this is a legitimate split point
                # (e.g., Dart checked/unchecked entry pairs).
                ida_funcs.del_func(fn.start_ea)
                ida_funcs.add_func(fn.start_ea, addr)
                fn = None
                split_count += 1
            elif addr in known_starts:
                # addr is known but the containing function's start isn't —
                # safe to split (the containing function was auto-detected, not ours).
                ida_funcs.del_func(fn.start_ea)
                ida_funcs.add_func(fn.start_ea, addr)
                fn = None
                split_count += 1
            else:
                split_skipped += 1

        if fn is None:
            end = addr + size if size > 0 else addr
            if ida_funcs.add_func(addr, end):
                stats["functions_created"] += 1
            else:
                idc.create_insn(addr)
                if ida_funcs.add_func(addr, end):
                    stats["functions_created"] += 1

        flags = idc.SN_NOWARN
        if not idc.set_name(addr, name, flags):
            raise ValueError("IDA rejected sanitized function identifier %r at 0x%x" % (name, addr))
        stats["functions_named"] += 1

    if split_count or split_skipped:
        log("  splits: %d performed, %d skipped (stale-protection)" % (split_count, split_skipped))

    log("  created=%d named=%d" % (stats["functions_created"], stats["functions_named"]))

    if ida_auto:
        log("  re-analyzing...")
        ida_auto.auto_wait()

    # ================================================================
    # Phase 3: Apply function signatures
    # ================================================================
    log("Phase 3: applying function signatures...")
    sig_failed = 0
    for entry in functions:
        addr = int(entry["addr"], 16)
        owner = entry.get("owner", "")
        pc = entry.get("param_count", 0)
        name = function_identifier(entry["name"], addr)

        proto = build_function_prototype(name, owner, pc, struct_names)
        if not proto:
            continue

        try:
            decl = idc.parse_decl(proto, 0)
            if decl and idc.apply_type(addr, decl, 1) != False:
                stats["signatures_applied"] += 1
            else:
                sig_failed += 1
        except Exception:
            sig_failed += 1

    log("  applied=%d failed=%d" % (stats["signatures_applied"], sig_failed))

    # ================================================================
    # Phase 4: Set comments
    # ================================================================
    comments = meta.get("comments", [])
    log("Phase 4: setting %d comments..." % len(comments))
    for entry in comments:
        addr = int(entry["addr"], 16)
        text = entry["text"]
        try:
            idc.set_cmt(addr, text, 1)
            stats["comments_set"] += 1
        except Exception:
            pass
    log("  set=%d" % stats["comments_set"])

    return stats


def main():
    if len(sys.argv) < 2:
        log("Usage: python3 aotopsy_apply.py <libapp.so> [<flutter_meta.json>] [<output_dir>]")
        sys.exit(1)

    binary_path = sys.argv[1]
    meta_path = resolve_meta_path(sys.argv)
    out_dir = sys.argv[3] if len(sys.argv) > 3 else None

    if not os.path.exists(binary_path):
        log("ERROR: binary not found: %s" % binary_path)
        sys.exit(1)
    if meta_path is None or not os.path.exists(meta_path):
        log("ERROR: flutter_meta.json not found. Pass as argument or place script in <output>/ida/")
        sys.exit(1)

    log("aotopsy_apply (IDA): loading %s" % meta_path)
    with open(meta_path, "r") as f:
        meta = json.load(f)

    # ---- Open database ----
    log("Opening binary in IDA: %s" % binary_path)
    import idapro
    idapro.enable_console_messages(False)

    result = idapro.open_database(binary_path, True)
    if result != 0:
        # Try fresh — delete stale database files.
        for ext in (".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til"):
            p = binary_path + ext
            if os.path.exists(p):
                os.remove(p)
        result = idapro.open_database(binary_path, True)
        if result != 0:
            log("ERROR: failed to open database (code %d)" % result)
            sys.exit(1)
    log("  database opened")

    # ---- Import IDA modules (only after db is open) ----
    import ida_auto
    import ida_funcs
    import ida_typeinf
    import idautils
    import idc

    has_decompiler = False
    try:
        import ida_hexrays
        has_decompiler = ida_hexrays.init_hexrays_plugin()
    except Exception:
        pass
    log("  decompiler: %s" % ("yes" if has_decompiler else "no"))

    # ---- Wait for auto-analysis ----
    log("Waiting for auto-analysis...")
    t0 = time.time()
    ida_auto.auto_wait()
    log("  done (%.1fs)" % (time.time() - t0))

    stats = apply_metadata(meta, idc, ida_funcs, ida_typeinf, ida_auto, binary_path)

    # ================================================================
    # Phase 5: Decompile focus functions
    # ================================================================
    functions = meta.get("functions", [])
    thr_fields = meta.get("thr_fields", [])
    focus = meta.get("focus_functions", [])
    decompiled = 0
    decompile_failed = 0

    if out_dir and focus and has_decompiler:
        log("Phase 5: decompiling %d focus functions..." % len(focus))
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        name_by_addr = {}
        for entry in functions:
            a = entry["addr"]
            name_by_addr[a] = entry["name"]

        index = []
        for addr_str in focus:
            addr = int(addr_str, 16)
            fn = ida_funcs.get_func(addr)
            if fn is None:
                index.append({
                    "addr": addr_str,
                    "name": name_by_addr.get(addr_str, "unknown"),
                    "file": None,
                    "decompile_ok": False,
                    "reason": "no_function",
                })
                decompile_failed += 1
                continue

            fn_name = idc.get_func_name(fn.start_ea)
            try:
                cfunc = ida_hexrays.decompile(fn.start_ea)
                if cfunc is None:
                    raise Exception("decompile returned None")

                if _retype_ida_registers(
                        cfunc, fn.start_ea, ida_hexrays, thr_fields):
                    cfunc = ida_hexrays.decompile(fn.start_ea)
                    if cfunc is None:
                        raise Exception("re-decompile returned None")
                    _retype_ida_registers(
                        cfunc, fn.start_ea, ida_hexrays, thr_fields)

                c_code = str(cfunc)

                # Address is the artifact identity. Avoid a separate recovered
                # owner directory sanitizer whose case/device/truncation rules
                # could merge distinct paths on Windows.
                safe_name = addr_str.replace("0x", "") + "_" + sanitize(fn_name)
                out_file = safe_name + ".c"

                with open(os.path.join(out_dir, out_file), "w") as cf:
                    cf.write(c_code)

                index.append({
                    "addr": addr_str,
                    "name": fn_name,
                    "file": out_file,
                    "decompile_ok": True,
                })
                decompiled += 1
            except Exception as e:
                index.append({
                    "addr": addr_str,
                    "name": fn_name,
                    "file": None,
                    "decompile_ok": False,
                    "reason": str(e)[:100],
                })
                decompile_failed += 1

        with open(os.path.join(out_dir, "index.json"), "w") as idx:
            json.dump(index, idx, indent=2)
        log("  decompiled=%d failed=%d" % (decompiled, decompile_failed))
    elif not has_decompiler:
        log("Phase 5: skipped (no Hex-Rays)")
    elif not out_dir:
        log("Phase 5: skipped (no output dir)")
    else:
        log("Phase 5: skipped (no focus functions)")

    # ================================================================
    # Save and close
    # ================================================================
    log("Saving database...")
    idapro.close_database(1)

    log("DONE: created=%d named=%d structs=%d sigs=%d comments=%d "
        "decompiled=%d" % (
            stats["functions_created"],
            stats["functions_named"],
            stats["structs_created"],
            stats["signatures_applied"],
            stats["comments_set"],
            decompiled,
        ))


# ============================================================
# C header generation
# ============================================================

def build_dart_thread_struct(thr_fields):
    """Build DartThread struct as C declaration."""
    sorted_fields = sorted(thr_fields, key=lambda f: f["offset"])
    max_off = max(f["offset"] for f in sorted_fields)
    struct_size = max_off + 8

    lines = ["struct DartThread {"]
    prev_end = 0
    pad_idx = 0
    skipped_overlap = []
    for f in sorted_fields:
        off = f["offset"]
        name = "%s_o%x" % (sanitize(f["name"]), off)
        if off > prev_end:
            lines.append("  char _pad%d[%d];" % (pad_idx, off - prev_end))
            pad_idx += 1
        elif off < prev_end:
            # P2.5-6: Log overlapping THR fields instead of silently skipping.
            skipped_overlap.append("%s @ 0x%x" % (f["name"], off))
            continue
        lines.append("  void* %s;" % name)
        prev_end = off + 8

    if prev_end < struct_size:
        lines.append("  char _pad_tail[%d];" % (struct_size - prev_end))

    lines.append("};")
    if skipped_overlap:
        log("  WARN: %d overlapping THR field(s) skipped: %s" % (
            len(skipped_overlap), ", ".join(skipped_overlap[:5])))
    return "\n".join(lines)


def build_class_struct(sname, size, fields, pointer_size):
    """Build a Dart class struct as C declaration."""
    field_sz = pointer_size

    sorted_fields = sorted(fields, key=lambda f: f.get("byte_offset", 0))

    lines = ["struct %s {" % sname]
    prev_end = 0
    pad_idx = 0
    for f in sorted_fields:
        off = f.get("byte_offset", 0)
        fname = "%s_o%x" % (sanitize(f.get("name", "field_%x" % off)), off)
        if pointer_size == 4:
            # A compressed Dart reference is a 32-bit encoded pointer value;
            # do not lie to IDA by widening it to a host void*. Raw slots are
            # also 32-bit, but remain honest integer storage either way.
            field_type = "unsigned int"
        elif f["is_reference"]:
            field_type = "void*"
        else:
            field_type = "unsigned long long"
        if off < prev_end:
            continue
        if off > prev_end:
            lines.append("  char _pad%d[%d];" % (pad_idx, off - prev_end))
            pad_idx += 1
        if off + field_sz <= size:
            lines.append("  %s %s;" % (field_type, fname))
            prev_end = off + field_sz
        else:
            prev_end = off

    if prev_end < size:
        lines.append("  char _pad_tail[%d];" % (size - prev_end))

    lines.append("};")
    return "\n".join(lines)


def build_function_prototype(name, owner, param_count, struct_names):
    """Build C function prototype. Returns None if no params to apply."""
    cname = sanitize(name)
    params = []

    if owner:
        if owner in struct_names:
            params.append("struct %s* this" % struct_names[owner])
        else:
            params.append("void* this")

    for i in range(param_count):
        params.append("void* p%d" % i)

    if not params:
        return "void* __fastcall %s(void);" % cname

    return "void* __fastcall %s(%s);" % (cname, ", ".join(params))


def _retype_ida_registers(cfunc, ea, ida_hexrays, has_thr_fields):
    """Rename and type Dart register variables in Hex-Rays decompilation.

    64-bit registers:
      x15 → SHADOW_SP (long*)   — indexed stack access: SHADOW_SP[-2]
      x21 → DT        (long)    — dispatch table
      x22 → DART_NULL (long)    — null sentinel
      x26 → THR       (DartThread*) — struct field resolution
      x27 → PP        (long*)   — indexed pool access: PP[8]
      x28 → HEAP_BASE (long)    — compressed pointer base
      x29 → FP        (long)    — frame pointer
      x30 → LR        (long)    — return address

    Also handles 32-bit subregister variants (w15, w22, etc.).

    Returns True if any symbols were retyped (caller should re-decompile).
    """
    import ida_typeinf

    # Build typed tinfo objects once.
    long_tinfo = ida_typeinf.tinfo_t()
    long_tinfo.create_simple_type(ida_typeinf.BTF_INT64)

    long_ptr_tinfo = ida_typeinf.tinfo_t()
    long_ptr_tinfo.create_ptr(long_tinfo)

    int_tinfo = ida_typeinf.tinfo_t()
    int_tinfo.create_simple_type(ida_typeinf.BTF_INT32)

    thr_ptr_tinfo = None
    if has_thr_fields:
        thr_tinfo = ida_typeinf.tinfo_t()
        if thr_tinfo.get_named_type(None, "DartThread"):
            thr_ptr_tinfo = ida_typeinf.tinfo_t()
            thr_ptr_tinfo.create_ptr(thr_tinfo)

    # Map register name → (display_name, tinfo or None).
    RENAMES = {
        # 64-bit
        "x15": ("SHADOW_SP", long_ptr_tinfo),
        "x21": ("DT",        long_tinfo),
        "x22": ("DART_NULL",  long_tinfo),
        "x26": ("THR",        thr_ptr_tinfo),
        "x27": ("PP",         long_ptr_tinfo),
        "x28": ("HEAP_BASE",  long_tinfo),
        "x29": ("FP",         long_tinfo),
        "x30": ("LR",         long_tinfo),
        # 32-bit subregisters — suffixed _lo to avoid duplicate variable
        # declarations when both x-reg and w-reg appear in decompilation
        "w15": ("SHADOW_SP_lo", int_tinfo),
        "w21": ("DT_lo",        int_tinfo),
        "w22": ("DART_NULL_lo", int_tinfo),
        "w26": ("THR_lo",       int_tinfo),
        "w27": ("PP_lo",        int_tinfo),
        "w28": ("HEAP_BASE_lo", int_tinfo),
        "w29": ("FP_lo",        int_tinfo),
        "w30": ("LR_lo",        int_tinfo),
    }

    renamed = False
    try:
        for lvar in cfunc.lvars:
            loc = lvar.location
            if not loc.is_reg1():
                continue
            mreg = loc.reg1()
            try:
                reg_name = ida_hexrays.get_mreg_name(mreg, lvar.width)
            except Exception:
                continue
            if not reg_name:
                continue

            entry = RENAMES.get(reg_name)
            if entry is None:
                continue

            new_name, new_type = entry
            lvar.name = new_name
            if new_type is not None:
                lvar.set_lvar_type(new_type)
            renamed = True

        if renamed:
            cfunc.save_user_lvars()
    except Exception:
        pass

    return renamed


if __name__ == "__main__":
    main()
