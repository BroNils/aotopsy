# -*- coding: utf-8 -*-
# aotopsy_apply.py - Ghidra headless postScript
#
# Reads flutter_meta.json produced by `aotopsy meta`, applies:
#   1. Function creation + renaming
#   2. Struct types for Dart classes + typed function signatures
#   3. EOL comments (THR fields, PP pool references)
#   4. Selective decompilation export for signal (focus) functions
#
# Usage (headless):
#   analyzeHeadless <project_dir> <project_name> \
#       -import <libapp.so> -overwrite \
#       -scriptPath <path_to_this_dir> \
#       -preScript aotopsy_prescript.py \
#       -postScript aotopsy_apply.py <flutter_meta.json> [<output_dir>]
#
# Script args:
#   arg[0]: path to flutter_meta.json (required)
#   arg[1]: output directory for decompiled .c files (optional)

import json
import hashlib
import os


APPLY_OK_FILE = ".aotopsy-apply-ok"
APPLY_FAILED_FILE = ".aotopsy-apply-failed"


class ApplyError(RuntimeError):
    pass


def _ensure_output_dir(out_dir):
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir)


def _write_apply_failed(out_dir, message):
    if not out_dir:
        return
    _ensure_output_dir(out_dir)
    ok_path = os.path.join(out_dir, APPLY_OK_FILE)
    if os.path.exists(ok_path):
        os.remove(ok_path)
    with open(os.path.join(out_dir, APPLY_FAILED_FILE), "w") as f:
        json.dump({"error": str(message)}, f)


def _write_apply_ok(out_dir, stats, focus_count, binary_sha256):
    if not out_dir:
        return
    _ensure_output_dir(out_dir)
    failed_path = os.path.join(out_dir, APPLY_FAILED_FILE)
    if os.path.exists(failed_path):
        os.remove(failed_path)
    payload = {
        "functions": stats["functions"],
        "decompiled": stats["decompiled"],
        "failed": stats["decompile_failed"],
        "focus": focus_count,
        "binary_sha256": binary_sha256,
    }
    with open(os.path.join(out_dir, APPLY_OK_FILE), "w") as f:
        json.dump(payload, f)

try:
    _TEXT_TYPES = (basestring,)
    _INTEGER_TYPES = (int, long)
except NameError:
    _TEXT_TYPES = (str,)
    _INTEGER_TYPES = (int,)

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    Pointer64DataType, Pointer32DataType, PointerDataType,
    StructureDataType, CategoryPath, VoidDataType, LongDataType,
    IntegerDataType,
)
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.listing import Function as GhidraFunction
from java.util import ArrayList
from ghidra.app.decompiler import DecompInterface

try:
    from ghidra.program.model.pcode import HighFunctionDBUtil
    HAS_HFDB_UTIL = True
except Exception as e:
    HAS_HFDB_UTIL = False

try:
    from ghidra.program.model.data import DataTypeConflictHandler
    REPLACE_HANDLER = DataTypeConflictHandler.REPLACE_HANDLER
except Exception as e:
    REPLACE_HANDLER = None


def resolve_meta_path(args):
    """Resolve flutter_meta.json path from script args or relative to this script."""
    if args and len(args) >= 1 and args[0]:
        return args[0]
    # Standalone mode: look for ../flutter_meta.json relative to this script.
    try:
        script_dir = os.path.dirname(os.path.abspath(sourceFile.getAbsolutePath()))
    except Exception:
        script_dir = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(script_dir, "..", "flutter_meta.json")
    if os.path.exists(candidate):
        return candidate
    raise RuntimeError(
        "flutter_meta.json not found. Pass as script argument or place this script in <output>/ghidra/"
    )


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


def main(args):
    meta_path = resolve_meta_path(args)
    out_dir = args[1] if len(args) > 1 else None

    println("aotopsy_apply: loading %s" % meta_path)

    with open(meta_path, "r") as f:
        meta = json.load(f)

    if meta.get("version") != "3" or meta.get("arch") != "arm64":
        raise ApplyError("flutter_meta.json must be schema version 3 for arch arm64")
    missing = [k for k in ("dart_version", "binary_sha256", "binary_size", "compressed_pointers", "pointer_size", "thr_fields")
               if k not in meta]
    if missing:
        raise ApplyError("flutter_meta.json missing required field(s): %s" % ", ".join(missing))
    if not isinstance(meta["compressed_pointers"], bool):
        raise ApplyError("compressed_pointers must be a boolean")
    expected_pointer_size = 4 if meta["compressed_pointers"] else 8
    if meta["pointer_size"] != expected_pointer_size:
        raise ApplyError("pointer_size %r disagrees with compressed_pointers=%r (want %d)" % (
            meta["pointer_size"], meta["compressed_pointers"], expected_pointer_size))
    if not isinstance(meta["dart_version"], _TEXT_TYPES) or not meta["dart_version"] or not isinstance(meta["thr_fields"], list):
        raise ApplyError("dart_version must be non-empty and thr_fields must be an array")
    if not isinstance(meta["binary_sha256"], _TEXT_TYPES):
        raise ApplyError("binary_sha256 must be a string")
    binary_sha256 = str(meta["binary_sha256"])
    if isinstance(meta["binary_size"], bool) or not isinstance(meta["binary_size"], _INTEGER_TYPES):
        raise ApplyError("binary_size must be a positive integer")
    binary_size = meta["binary_size"]
    if len(binary_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in binary_sha256):
        raise ApplyError("binary_sha256 must be 64 lowercase hex characters")
    if binary_size <= 0 or binary_size != meta["binary_size"]:
        raise ApplyError("binary_size must be a positive integer")
    try:
        validate_meta_records(meta)
    except ValueError as e:
        raise ApplyError("invalid flutter_meta.json records: %s" % str(e))

    executable_path = str(currentProgram.getExecutablePath() or "")
    if not executable_path or not os.path.isfile(executable_path):
        raise ApplyError("cannot verify imported binary path for flutter_meta.json provenance")
    if os.path.getsize(executable_path) != binary_size:
        raise ApplyError("imported binary size does not match flutter_meta.json provenance")
    digest = hashlib.sha256()
    with open(executable_path, "rb") as bf:
        while True:
            chunk = bf.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    if digest.hexdigest() != binary_sha256:
        raise ApplyError("imported binary SHA-256 does not match flutter_meta.json provenance")

    stats = {
        "functions": len(meta.get("functions", [])),
        "renamed": 0,
        "created": 0,
        "create_failed": 0,
        "labels": 0,
        "comments": 0,
        "comment_failed": 0,
        "decompiled": 0,
        "decompile_failed": 0,
    }

    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    symtab = currentProgram.getSymbolTable()

    # Detect image base: Ghidra rebases shared objects (typically +0x100000).
    mem = currentProgram.getMemory()
    image_base = currentProgram.getImageBase().getOffset()
    println("  image base: 0x%x" % image_base)

    # Determine pointer size from metadata (compressed pointers = 4 bytes).
    pointer_size = meta["pointer_size"]
    println("  pointer_size: %d" % pointer_size)

    # ptr_type = pointer to void (for return types, params — always 8 bytes in AArch64).
    # PointerDataType(VoidDataType()) renders as "void *" instead of "undefined *".
    ptr_type = PointerDataType(VoidDataType())

    # field_type = type used for Dart object fields inside structs.
    # With compressed pointers (4 bytes), fields are 32-bit pointers.
    # Without compression (8 bytes), fields are 64-bit pointers.
    if pointer_size == 4:
        field_type = Pointer32DataType()
        raw_field_type = IntegerDataType()
    else:
        field_type = PointerDataType(VoidDataType())
        raw_field_type = LongDataType()

    # Phase 1a: Force disassembly at all function addresses.
    # Ghidra's auto-analysis skips Dart AOT code (no standard prologues).
    println("Phase 1a: disassembling at %d addresses..." % stats["functions"])
    disasm_ok = 0
    disasm_fail = 0
    for entry in meta.get("functions", []):
        addr_int = int(entry["addr"], 16) + image_base
        addr = toAddr(addr_int)
        if listing.getInstructionAt(addr) is not None:
            disasm_ok += 1
            continue
        try:
            clearListing(addr)
            disassemble(addr)
            if listing.getInstructionAt(addr) is not None:
                disasm_ok += 1
            else:
                disasm_fail += 1
        except Exception as e:
            disasm_fail += 1
    println("  disassembled=%d failed=%d" % (disasm_ok, disasm_fail))

    # Phase 1b: Create/rename functions.
    println("Phase 1b: creating/renaming %d functions..." % stats["functions"])
    for entry in meta.get("functions", []):
        addr_int = int(entry["addr"], 16) + image_base
        addr = toAddr(addr_int)
        name = function_identifier(entry["name"], int(entry["addr"], 16))

        fn = fm.getFunctionAt(addr)
        if fn is not None:
            try:
                fn.setName(name, SourceType.USER_DEFINED)
                stats["renamed"] += 1
            except Exception as e:
                println("  WARN: rename failed at %s: %s" % (entry["addr"], str(e)[:80]))
            continue

        # Try to create function.
        try:
            fn = createFunction(addr, name)
            if fn is not None:
                stats["created"] += 1
                continue
        except Exception as e:
            pass

        # Fallback: disassemble at the address, then try again.
        try:
            disassemble(addr)
            fn = createFunction(addr, name)
            if fn is not None:
                stats["created"] += 1
                continue
        except Exception as e:
            pass

        # Last resort: create a label so the name appears.
        try:
            symtab.createLabel(addr, name, SourceType.USER_DEFINED)
            stats["labels"] += 1
        except Exception as e:
            stats["create_failed"] += 1

    println("  created=%d renamed=%d labels=%d failed=%d" % (
        stats["created"], stats["renamed"], stats["labels"], stats["create_failed"]))

    # Verify: count how many functions exist now at our addresses.
    verify_count = 0
    for entry in meta.get("functions", []):
        addr = toAddr(int(entry["addr"], 16) + image_base)
        if fm.getFunctionAt(addr) is not None:
            verify_count += 1
    println("  verified: %d/%d addresses have functions" % (verify_count, stats["functions"]))

    # Phase 1c: Create struct types for Dart classes.
    # Must run BEFORE param application so typed 'this' pointers can reference structs.
    classes = meta.get("classes", [])
    struct_by_owner = {}  # class_name -> Ghidra DataType
    if classes:
        println("Phase 1c: creating %d class struct types..." % len(classes))
        dtm = currentProgram.getDataTypeManager()
        cat = CategoryPath("/DartClasses")
        struct_created = 0
        struct_failed = 0
        owner_counts = {}
        for cls in classes:
            cname = cls["class_name"]
            owner_counts[cname] = owner_counts.get(cname, 0) + 1

        for cls in classes:
            try:
                cname = cls["class_name"]
                cid = cls["class_id"]
                sname = "Dart_%s_cid%d" % (sanitize_identifier(cname), cid)
                size = cls["instance_size"]
                if size <= 0:
                    continue
                fields = cls.get("fields", [])

                struct_dt = StructureDataType(cat, sname, size)
                for field in fields:
                    offset = field["byte_offset"]
                    fname = "%s_o%x" % (sanitize_identifier(field["name"]), offset)
                    slot_type = field_type if field["is_reference"] else raw_field_type
                    if offset >= 0 and offset + pointer_size <= size:
                        struct_dt.replaceAtOffset(offset, slot_type, pointer_size, fname, "")

                resolved = dtm.addDataType(struct_dt, REPLACE_HANDLER)
                # Function metadata carries an owner display name, not a CID.
                # Only type `this` when that name identifies exactly one class;
                # otherwise choosing one duplicate would be a fabricated type.
                if owner_counts[cname] == 1:
                    struct_by_owner[cname] = resolved
                struct_created += 1
            except Exception as e:
                struct_failed += 1
                if struct_failed <= 5:
                    println("  WARN: struct %s: %s" % (cls.get("class_name", "?"), str(e)[:80]))

        println("  structs created=%d failed=%d (lookup=%d)" % (struct_created, struct_failed, len(struct_by_owner)))
    else:
        println("Phase 1c: skipped (no class layouts)")

    # Phase 1c2: Create DartThread struct from THR fields.
    thr_fields = meta.get("thr_fields", [])
    if thr_fields:
        println("Phase 1c2: creating DartThread struct (%d fields)..." % len(thr_fields))
        dtm = currentProgram.getDataTypeManager()
        cat = CategoryPath("/DartClasses")
        try:
            # Find max offset to determine struct size.
            max_off = max(f["offset"] for f in thr_fields)
            thr_size = max_off + 8  # last field is a pointer
            thr_dt = StructureDataType(cat, "DartThread", thr_size)
            thr_placed = 0
            for tf in thr_fields:
                off = tf["offset"]
                tname = "%s_o%x" % (sanitize_identifier(tf["name"]), off)
                if off >= 0 and off + 8 <= thr_size:
                    thr_dt.replaceAtOffset(off, ptr_type, 8, tname, "")
                    thr_placed += 1
            dtm.addDataType(thr_dt, REPLACE_HANDLER)
            println("  DartThread: %d/%d fields placed (size=%d)" % (thr_placed, len(thr_fields), thr_size))
        except Exception as e:
            println("  WARN: DartThread creation failed: %s" % str(e)[:120])
    else:
        println("Phase 1c2: skipped (no THR fields)")

    # Prepare DartThread* type for register retyping in decompiler output.
    # When x26 is typed as DartThread*, the decompiler resolves
    # *(long *)(unaff_x26 + 0x38) → THR->stack_limit automatically.
    dart_thread_ptr_dt = None
    if thr_fields and HAS_HFDB_UTIL:
        dtm_check = currentProgram.getDataTypeManager()
        resolved = dtm_check.getDataType(CategoryPath("/DartClasses"), "DartThread")
        if resolved:
            dart_thread_ptr_dt = PointerDataType(resolved)
            println("  DartThread* ready for register retyping")

    # Phase 1d: Apply function signatures (typed parameters + return type).
    # For methods (functions with an owner class):
    #   - First param = this: Dart_OwnerClass* (typed pointer to owner struct)
    #   - Remaining params = generic pointers
    # For all functions:
    #   - Calling convention = __dartcall (registered by prescript via SpecExtension)
    #   - Return type = pointer (Dart functions return objects, not undefined)
    println("Phase 1d: applying function signatures...")
    sig_applied = 0
    sig_failed = 0
    ret_applied = 0
    this_typed = 0
    for entry in meta.get("functions", []):
        addr = toAddr(int(entry["addr"], 16) + image_base)
        fn = fm.getFunctionAt(addr)
        if fn is None:
            continue

        owner = entry.get("owner", "")
        pc = entry.get("param_count", 0)

        # Set calling convention to __dartcall (registered by prescript).
        # Must happen BEFORE replaceParameters to avoid "Unknown calling convention" warning.
        try:
            fn.setCallingConventionName("__dartcall")
        except Exception as e:
            pass

        # Set return type to pointer (Dart returns objects, not undefined).
        try:
            fn.setReturnType(ptr_type, SourceType.USER_DEFINED)
            ret_applied += 1
        except Exception as e:
            pass

        # Build parameter list (ArrayList for JPype/PyGhidra overload resolution).
        params = ArrayList()

        # Methods get typed 'this' as first parameter.
        # param_count excludes implicit 'this', so we add it separately.
        if owner:
            if owner in struct_by_owner:
                this_dt = PointerDataType(struct_by_owner[owner])
                this_typed += 1
            else:
                this_dt = ptr_type
            params.add(ParameterImpl("this", this_dt, currentProgram))

        # Explicit parameters.
        for i in range(pc):
            params.add(ParameterImpl("p%d" % i, ptr_type, currentProgram))

        if params.size() == 0:
            continue

        try:
            fn.replaceParameters(params,
                GhidraFunction.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                True, SourceType.USER_DEFINED)
            # P2.5-4: replaceParameters can reset the calling convention
            # back to the default. Re-apply __dartcall after replaceParameters.
            try:
                fn.setCallingConventionName("__dartcall")
            except Exception:
                pass
            sig_applied += 1
        except Exception as e:
            sig_failed += 1
            if sig_failed <= 3:
                println("  WARN: replaceParameters failed for %s: %s" % (entry.get("name", "?"), str(e)[:120]))

    println("  signatures applied=%d failed=%d return_types=%d this_typed=%d" % (
        sig_applied, sig_failed, ret_applied, this_typed))

    # Phase 2: Set EOL comments.
    # P2.5-2: Prefix aotopsy comments with a marker so re-runs only
    # replace our own comments, preserving user-added comments.
    AOTOPSY_COMMENT_PREFIX = "aotopsy: "
    comment_entries = meta.get("comments", [])
    println("Phase 2: setting %d comments..." % len(comment_entries))
    comments_preserved = 0
    for entry in comment_entries:
        addr_int = int(entry["addr"], 16) + image_base
        addr = toAddr(addr_int)
        text = entry["text"]
        # Check if there's an existing comment.
        existing = getEOLComment(addr)
        if existing:
            # Check if the aotopsy marker is already present to avoid
            # duplicating aotopsy comments on re-runs. If the marker is
            # already in the existing comment, replace only the aotopsy
            # portion; otherwise append.
            if AOTOPSY_COMMENT_PREFIX in existing:
                # Split on the marker: everything before is user comment,
                # everything from the marker onward is the old aotopsy block.
                idx = existing.find(AOTOPSY_COMMENT_PREFIX)
                user_part = existing[:idx].rstrip("\n")
                text = (user_part + "\n" if user_part else "") + AOTOPSY_COMMENT_PREFIX + text
            else:
                # User has added their own comment here — append ours.
                comments_preserved += 1
                text = existing + "\n" + AOTOPSY_COMMENT_PREFIX + text
        else:
            text = AOTOPSY_COMMENT_PREFIX + text
        try:
            setEOLComment(addr, text)
            stats["comments"] += 1
        except Exception as e:
            stats["comment_failed"] += 1
    if comments_preserved > 0:
        println("  preserved %d user comment(s) by appending" % comments_preserved)

    println("  set=%d failed=%d" % (stats["comments"], stats["comment_failed"]))

    # Phase 3: Selective decompilation.
    focus = meta.get("focus_functions", [])
    if out_dir and focus:
        println("Phase 3: decompiling %d focus functions..." % len(focus))
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        ifc = DecompInterface()
        # Use "decompile" simplification to reduce VarnodeContext pressure.
        ifc.setSimplificationStyle("decompile")
        ifc.openProgram(currentProgram)

        index = []
        not_found = 0
        for addr_str in focus:
            addr_int = int(addr_str, 16) + image_base
            addr = toAddr(addr_int)

            # Try exact match first, then containing.
            fn = fm.getFunctionAt(addr)
            if fn is None:
                fn = fm.getFunctionContaining(addr)

            if fn is None:
                not_found += 1
                if not_found <= 5:
                    println("  WARN: no function at %s" % addr_str)
                index.append({
                    "addr": addr_str,
                    "name": "unknown",
                    "file": None,
                    "decompile_ok": False,
                    "reason": "no_function",
                })
                stats["decompile_failed"] += 1
                continue

            fn_name = fn.getName()
            try:
                result = ifc.decompileFunction(fn, 60, monitor)
            except Exception as e:
                index.append({
                    "addr": addr_str,
                    "name": fn_name,
                    "file": None,
                    "decompile_ok": False,
                    "reason": str(e)[:100],
                })
                stats["decompile_failed"] += 1
                continue

            # Retype Dart registers for readable decompiler output:
            #   x26 → THR (DartThread*)  — resolves field accesses
            #   x27 → PP               — object pool pointer
            #   x28 → HEAP_BASE        — compressed pointer base
            #   x15 → SHADOW_SP        — Dart shadow call stack
            if result and result.decompileCompleted() and HAS_HFDB_UTIL:
                hfunc = result.getHighFunction()
                if hfunc:
                    retyped = _retype_dart_registers(
                        hfunc, dart_thread_ptr_dt, ptr_type)
                    if retyped:
                        try:
                            result = ifc.decompileFunction(fn, 60, monitor)
                        except Exception as e:
                            pass

            if result and result.decompileCompleted():
                decomp = result.getDecompiledFunction()
                if decomp:
                    c_code = decomp.getC()
                    # Strip cosmetic warning from SpecExtension-registered CC.
                    # The native decompiler doesn't receive SpecExtension CCs,
                    # so it flags __dartcall as unknown. The CC works functionally.
                    c_code = c_code.replace(
                        "/* WARNING: Unknown calling convention -- yet parameter storage is locked */\n\n", "")
                    c_code = c_code.replace(
                        "/* WARNING: Unknown calling convention -- yet parameter storage is locked */\n", "")
                    # Address is the stable artifact identity. Do not derive a
                    # directory component from the recovered owner name: that
                    # reintroduced a second filename sanitizer with Windows
                    # device/case-fold/truncation collision hazards.
                    safe_name = addr_str.replace("0x", "") + "_" + sanitize_identifier(fn_name)
                    out_file = safe_name + ".c"
                    out_path = os.path.join(out_dir, out_file)
                    with open(out_path, "w") as cf:
                        cf.write(c_code)
                    index.append({
                        "addr": addr_str,
                        "name": fn_name,
                        "file": out_file,
                        "decompile_ok": True,
                    })
                    stats["decompiled"] += 1
                    continue

            reason = "decompile_incomplete"
            if result:
                err_msg = result.getErrorMessage()
                if err_msg:
                    reason = err_msg[:100]

            index.append({
                "addr": addr_str,
                "name": fn_name,
                "file": None,
                "decompile_ok": False,
                "reason": reason,
            })
            stats["decompile_failed"] += 1

        if not_found > 0:
            println("  %d focus functions not found" % not_found)

        ifc.dispose()

        # Write index.json.
        index_path = os.path.join(out_dir, "index.json")
        with open(index_path, "w") as idx:
            json.dump(index, idx, indent=2)
        println("  decompiled=%d failed=%d" % (stats["decompiled"], stats["decompile_failed"]))
    elif focus:
        println("Phase 3: skipped (no output directory specified)")
    else:
        println("Phase 3: skipped (no focus functions)")

    # Disable Decompiler Parameter ID before exiting.
    # Ghidra auto-re-analyzes after postScript changes. The re-analysis triggers
    # "VarnodeContext: out of address spaces" errors on large Dart AOT binaries.
    # Since we already applied our own signatures, this analyzer is redundant.
    try:
        setAnalysisOption(currentProgram, "Decompiler Parameter ID", "false")
    except Exception as e:
        pass

    # Summary.
    println("AOTOPSY_APPLY: functions=%d renamed=%d created=%d labels=%d comments=%d decompiled=%d failed=%d" % (
        stats["functions"],
        stats["renamed"],
        stats["created"],
        stats["labels"],
        stats["comments"],
        stats["decompiled"],
        stats["decompile_failed"],
    ))
    _write_apply_ok(out_dir, stats, len(focus), binary_sha256)


def _retype_dart_registers(hfunc, dart_thread_ptr_dt, ptr_type):
    """Retype Dart-specific unaffected registers for readable decompiler output.

    Renames and types:
      x15 → SHADOW_SP   (long*)  Dart shadow call stack
      x21 → DT          (long)  dispatch table pointer
      x22 → DART_NULL   (long)  Dart null object
      x26 → THR         (DartThread*)  resolves struct field accesses
      x27 → PP          (long*)  object pool pointer (indexed)
      x28 → HEAP_BASE   (long)  compressed pointer base
      x29 → FP          (long)  frame pointer
      x30 → LR          (long)  link register / return address

    Also handles 32-bit subregister variants (w22, etc.) and Ghidra's
    internal register-space names (unaff_000040b4 = upper half of x22).

    Returns True if any symbols were retyped (caller should re-decompile).
    """
    long_type = LongDataType()
    int_type = IntegerDataType()  # 4 bytes — for w-regs and upper halves
    long_ptr_type = PointerDataType(long_type)  # long * — for stack/pool pointers

    # Map unaff_/in_ names to (readable_name, type).
    # None type = keep existing type.
    RENAMES = {
        # 64-bit registers — typed to eliminate undefined8
        "unaff_x15": ("SHADOW_SP",    long_ptr_type),  # Dart shadow stack
        "unaff_x21": ("DT",           long_type),
        "unaff_x22": ("DART_NULL",    long_type),
        "unaff_x26": ("THR",          dart_thread_ptr_dt),  # DartThread*
        "unaff_x27": ("PP",           long_ptr_type),  # pool pointer — indexed
        "unaff_x28": ("HEAP_BASE",    long_type),
        "unaff_x29": ("FP",           long_type),
        "unaff_x30": ("LR",           long_type),
        # 32-bit subregister variants (w-regs) — suffixed _lo to avoid
        # duplicate variable declarations when both x-reg and w-reg appear
        "unaff_w15": ("SHADOW_SP_lo", int_type),
        "unaff_w21": ("DT_lo",        int_type),
        "unaff_w22": ("DART_NULL_lo", int_type),
        "unaff_w26": ("THR_lo",       int_type),
        "unaff_w27": ("PP_lo",        int_type),
        "unaff_w28": ("HEAP_BASE_lo", int_type),
        "unaff_w29": ("FP_lo",        int_type),
        "unaff_w30": ("LR_lo",        int_type),
        # Upper 32-bit halves (Ghidra register-space offsets)
        # These are internal split-register names — type as int
        "unaff_000040b4":         ("DART_NULL_HI", int_type),   # upper x22
        "in_register_00004004":   ("x0_HI",        int_type),   # upper x0
        "in_register_0000400c":   ("x1_HI",        int_type),   # upper x1
        "in_register_00004014":   ("x2_HI",        int_type),   # upper x2
        "in_register_0000401c":   ("x3_HI",        int_type),   # upper x3
        "in_register_00004024":   ("x4_HI",        int_type),   # upper x4
        "in_register_0000402c":   ("x5_HI",        int_type),   # upper x5
        "in_register_00004034":   ("x6_HI",        int_type),   # upper x6
        "in_register_0000403c":   ("x7_HI",        int_type),   # upper x7
        # 32-bit parameter in-registers (w0-w7)
        "in_w0":  ("p0",    int_type),
        "in_w1":  ("p1",    int_type),
        "in_w2":  ("p2",    int_type),
        "in_w3":  ("p3",    int_type),
        "in_w4":  ("p4",    int_type),
        "in_w5":  ("p5",    int_type),
        "in_w6":  ("p6",    int_type),
        "in_w7":  ("p7",    int_type),
    }

    did_retype = False
    lsm = hfunc.getLocalSymbolMap()
    # Snapshot the iterator to avoid ConcurrentModificationException.
    symbols = list(lsm.getSymbols())
    for sym in symbols:
        sym_name = sym.getName()
        entry = RENAMES.get(sym_name)
        if entry is None:
            # P2.5-3: Dynamic fallback for register-space offset names.
            # Hardcoded offsets (e.g., unaff_000040b4) break on Ghidra upgrades
            # because the register space base offset can change. Try to match
            # by pattern: unaff_<hex> or in_register_<hex> are upper halves
            # of registers. Map them based on the offset relative to x0's
            # register-space offset.
            #
            # L-2 (oracle-audit): 0x4004 is Ghidra 10.x-specific (x0 at 0x4000,
            # upper half at 0x4004). On Ghidra 11+ this offset may differ.
            # If this fallback produces wrong xN_HI names or all indices are
            # out of range (silently skipped by the 0<=reg_idx<=31 check),
            # verify the register-space base offset for your Ghidra version
            # by checking a known register (e.g., x26 = THR) in the decompiler
            # and updating 0x4004 accordingly. The primary RENAMES map above
            # is not affected by this issue.
            if sym_name.startswith("unaff_") and len(sym_name) > 10:
                # Try to compute which register this is an upper half of.
                # Format: unaff_<8-hex-digits> — offset in register space.
                try:
                    offset = int(sym_name[6:], 16)
                    # x0 is at 0x4000, each register is 8 bytes apart.
                    # Upper half = base + 4.
                    reg_idx = (offset - 0x4004) // 8
                    if 0 <= reg_idx <= 31:
                        entry = ("x%d_HI" % reg_idx, int_type)
                except ValueError:
                    pass
            elif sym_name.startswith("in_register_") and len(sym_name) > 16:
                try:
                    offset = int(sym_name[12:], 16)
                    reg_idx = (offset - 0x4004) // 8
                    if 0 <= reg_idx <= 31:
                        entry = ("x%d_HI" % reg_idx, int_type)
                except ValueError:
                    pass
        if entry is None:
            continue
        new_name, new_dt = entry
        try:
            dt = new_dt if new_dt else sym.getDataType()
            HighFunctionDBUtil.updateDBVariable(
                sym, new_name, dt, SourceType.USER_DEFINED)
            did_retype = True
        except Exception as e:
            pass
    return did_retype


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


def sanitize_identifier(name):
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
    s += suffix
    return s


def _has_identity_suffix(name):
    pos = name.rfind("_")
    if pos < 0 or len(name) - pos - 1 != 32:
        return False
    return all(ch in "0123456789abcdef" for ch in name[pos + 1:])


def function_identifier(name, addr):
    """Tool-boundary function identifier: readable raw identity + exact VA."""
    return "%s_a%x" % (sanitize_identifier(name), addr)


def _run_main():
    args = getScriptArgs()
    out_dir = args[1] if len(args) > 1 else None
    try:
        main(args)
    except Exception as e:
        println("ERROR: %s" % str(e))
        _write_apply_failed(out_dir, str(e))


_run_main()
