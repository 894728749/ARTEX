"""Minimal, non-executing ELF64 x86-64 metadata reader."""
import hashlib
import os
import struct
from pathlib import Path

ELF_MACHINE_X86_64 = 62
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
SHF_EXECINSTR = 0x4
MAX_NOTE_BYTES = 1024 * 1024


def _notes_build_id(data):
    pos = 0
    while pos + 12 <= len(data):
        namesz, descsz, note_type = struct.unpack_from("<III", data, pos)
        pos += 12
        if namesz > 4096 or descsz > 65536 or pos + namesz + descsz > len(data):
            break
        name = data[pos:pos + namesz].rstrip(b"\0")
        pos += namesz
        desc = data[pos:pos + descsz]
        pos += descsz
        # Align the next note to four bytes.
        pos = (pos + 3) & ~3
        if note_type == 3 and name == b"GNU" and desc:
            return desc.hex()
    return None


def _text_section(f, size, shoff, shentsize, shnum, shstrndx):
    if not shoff or not shnum or shentsize < 64 or shnum > 4096:
        return None, None
    if shoff + shentsize * shnum > size:
        return None, None
    headers = []
    for index in range(shnum):
        f.seek(shoff + index * shentsize)
        row = f.read(64)
        if len(row) != 64:
            return None, None
        (name, sect_type, flags, addr, offset, sect_size,
         link, info, addralign, entsize) = struct.unpack("<IIQQQQIIQQ", row)
        if sect_type != 8 and offset + sect_size > size:  # SHT_NOBITS has no file bytes
            return None, None
        headers.append((name, flags, addr, offset, sect_size))
    names = b""
    if shstrndx < shnum:
        _, _, _, name_off, name_size = headers[shstrndx]
        if name_size > 1024 * 1024:
            return None, None
        f.seek(name_off)
        names = f.read(name_size)
    chosen = None
    for name_off, flags, addr, offset, sect_size in headers:
        if not names or name_off >= len(names):
            continue
        end = names.find(b"\0", name_off)
        name = names[name_off:end if end >= 0 else len(names)].decode("utf-8", "replace")
        if name == ".text":
            chosen = (addr, sect_size)
            break
        if chosen is None and flags & SHF_EXECINSTR:
            chosen = (addr, sect_size)
    return chosen if chosen else (None, None)


def inspect_elf(path):
    p = Path(path)
    size = p.stat().st_size
    if size < 64:
        raise ValueError("artifact is shorter than an ELF64 header")
    with p.open("rb") as f:
        hdr = f.read(64)
        if hdr[:4] != b"\x7fELF" or hdr[4] != 2 or hdr[5] != 1 or int.from_bytes(hdr[18:20], "little") != ELF_MACHINE_X86_64:
            raise ValueError("artifact must be a little-endian ELF64 x86-64 binary")
        e_type = struct.unpack_from("<H", hdr, 16)[0]
        phoff = struct.unpack_from("<Q", hdr, 32)[0]
        shoff = struct.unpack_from("<Q", hdr, 40)[0]
        phentsize, phnum = struct.unpack_from("<HH", hdr, 54)
        shentsize = struct.unpack_from("<H", hdr, 58)[0]
        shnum, shstrndx = struct.unpack_from("<HH", hdr, 60)
        if phentsize < 56 or phnum > 4096 or phoff + phentsize * phnum > size:
            raise ValueError("invalid ELF program-header table")
        ph = []
        for i in range(phnum):
            f.seek(phoff + i * phentsize)
            row = f.read(56)
            if len(row) != 56:
                raise ValueError("truncated ELF program header")
            typ, flags, off, vaddr, paddr, filesz, memsz, align = struct.unpack("<IIQQQQQQ", row)
            if off + filesz > size:
                raise ValueError("ELF segment extends beyond artifact")
            ph.append((typ, flags, off, vaddr, paddr, filesz, memsz, align))
        interpreter = None
        for typ, flags, off, vaddr, paddr, filesz, memsz, align in ph:
            if typ == PT_INTERP:
                f.seek(off)
                interpreter = f.read(filesz).split(b"\0", 1)[0].decode("utf-8", "strict")
                if not interpreter.startswith("/"):
                    raise ValueError("ELF PT_INTERP must be an absolute path")
        needed = []
        dyn = next((s for s in ph if s[0] == PT_DYNAMIC), None)
        if dyn:
            _, _, off, vaddr, _, filesz, _, _ = dyn
            strtab = None
            strsz = 0
            offsets = []
            f.seek(off)
            for _ in range(filesz // 16):
                raw = f.read(16)
                if len(raw) != 16:
                    break
                tag, val = struct.unpack("<qQ", raw)
                if tag == 0:
                    break
                if tag == 1:
                    offsets.append(val)
                elif tag == 5:
                    strtab = val
                elif tag == 10:
                    strsz = val
            if offsets:
                if strtab is None or not strsz:
                    raise ValueError("ELF DT_NEEDED has no valid string table")
                str_off = None
                for t, _, seg_off, seg_va, _, seg_filesz, _, _ in ph:
                    if t == PT_LOAD and seg_va <= strtab < seg_va + seg_filesz:
                        str_off = seg_off + (strtab - seg_va)
                        break
                if str_off is None or str_off + strsz > size:
                    raise ValueError("ELF dynamic string table is outside loadable segments")
                for idx in offsets:
                    if idx >= strsz:
                        raise ValueError("ELF DT_NEEDED string offset is invalid")
                    f.seek(str_off + idx)
                    name = f.read(min(4096, strsz - idx)).split(b"\0", 1)[0].decode("utf-8", "strict")
                    if not name or "/" in name:
                        raise ValueError("ELF dependency must be a basename")
                    needed.append(name)
        loads = [{"offset": off, "vaddr": vaddr, "filesz": filesz, "memsz": memsz, "flags": flags}
                 for typ, flags, off, vaddr, paddr, filesz, memsz, align in ph if typ == PT_LOAD]
        build_id = None
        for typ, flags, off, vaddr, paddr, filesz, memsz, align in ph:
            if typ != PT_NOTE:
                continue
            if filesz > MAX_NOTE_BYTES:
                continue
            f.seek(off)
            build_id = _notes_build_id(f.read(filesz))
            if build_id:
                break
        try:
            text_vaddr, text_size = _text_section(f, size, shoff, shentsize, shnum, shstrndx)
        except (struct.error, OSError):
            text_vaddr, text_size = None, None
    h = hashlib.sha256()
    with p.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return {"sha256": h.hexdigest(), "size": size, "type": e_type,
            "type_name": {2: "ET_EXEC", 3: "ET_DYN"}.get(e_type, "OTHER"),
            "interpreter": interpreter, "needed": needed, "build_id": build_id,
            "loads": loads, "text_vaddr": text_vaddr, "text_size": text_size}


def elf_file_offset(meta, vaddr):
    """Translate a link-time virtual address to an ELF file offset."""
    if not isinstance(vaddr, int) or vaddr < 0:
        return None
    for load in meta.get("loads", []):
        start = load["vaddr"]
        if start <= vaddr < start + load["memsz"]:
            return load["offset"] + (vaddr - start)
    return None


def safe_basename(value):
    if (not isinstance(value, str) or not value or value in (".", "..")
            or os.path.basename(value) != value or "/" in value or "\\" in value
            or any(ord(c) < 32 for c in value)
            or any(c in value for c in ',="')):
        raise ValueError("artifact name must be a safe basename")
    return value
