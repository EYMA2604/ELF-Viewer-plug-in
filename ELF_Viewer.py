#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ELF_Viewer.py - read-only annotated hex viewer for ELF files.

One continuous hex table (offset, 16 bytes per line, ASCII column). Annotations
are drawn on the table itself: a tag column (EHDR, PHDR, SHDR, STR, SYM, ...),
separator characters in front of every field / region, colors (optional) and a
notes column.  The cursor byte is explained in the status lines at the bottom.

  python3 ELF_Viewer.py ./main            interactive (curses)
  python3 ELF_Viewer.py --dump ./main     same table as plain text

Only the Python standard library is used.  The file is never modified.
"""

import argparse
import bisect
import heapq
import locale
import os
import sys

try:
    import curses
except ImportError:  # --dump still works without curses
    curses = None

# ---------------------------------------------------------------- constants

PR_GAP = -1       # synthetic "unclaimed" bytes
PR_SEG = 10       # segment contents (overlay, lowest real priority)

PR_REGION = 30    # tables and sections
PR_FIELD = 50     # fields, records' leaves, strings

CAP_RECORDS = 20000
CAP_STRINGS = 50000
CAP_PHDRS = 4096
CAP_SHDRS = 65536
CAP_DYN = 4096
MAX_BYTES = 256 * 1024 * 1024

# A byte gets a four-column slot: marker, two hex digits, and breathing room.
HEX_X = 14
BYTE_PITCH = 4
ASCII_X = HEX_X + 16 * BYTE_PITCH + 2
NOTES_X = ASCII_X + 18

TAGS = {
    'ehdr': 'EHDR', 'phdr': 'PHDR', 'shdr': 'SHDR', 'strtab': 'STR',
    'symtab': 'SYM', 'dynamic': 'DYN', 'reloc': 'REL', 'code': 'CODE',
    'data': 'DATA', 'sec': 'SEC', 'seg': 'SEG', 'gap': 'gap',
    'tail': 'TAIL', 'bad': 'RAW',
}

UNI = {'rs': '\u2503', 'fs': '\u2502', 'ps': '\u00bb', 'lab': '\u25b8',
       'arr': '\u2192', 'warn': '\u26a0', 'ell': '\u2026', 'cont': '\u00b7'}
ASC = {'rs': '#', 'fs': '|', 'ps': '>', 'lab': '*',
       'arr': '->', 'warn': '!', 'ell': '~', 'cont': '.'}

CLASS = {1: 'ELFCLASS32', 2: 'ELFCLASS64'}
DATA = {1: 'ELFDATA2LSB (little-endian)', 2: 'ELFDATA2MSB (big-endian)'}
OSABI = {0: 'ELFOSABI_NONE (System V)', 1: 'HP-UX', 2: 'NetBSD', 3: 'GNU/Linux',
         6: 'Solaris', 9: 'FreeBSD', 12: 'OpenBSD', 97: 'ARM', 255: 'standalone'}
ET = {0: 'ET_NONE', 1: 'ET_REL', 2: 'ET_EXEC', 3: 'ET_DYN', 4: 'ET_CORE'}
EM = {0: 'none', 3: 'x86 (i386)', 8: 'MIPS', 20: 'PowerPC', 21: 'PowerPC64',
      22: 'S390', 40: 'ARM', 42: 'SuperH', 50: 'IA-64', 62: 'x86-64',
      183: 'AArch64', 243: 'RISC-V', 247: 'BPF', 258: 'LoongArch'}
PT = {0: 'PT_NULL', 1: 'PT_LOAD', 2: 'PT_DYNAMIC', 3: 'PT_INTERP', 4: 'PT_NOTE',
      5: 'PT_SHLIB', 6: 'PT_PHDR', 7: 'PT_TLS', 0x6474e550: 'PT_GNU_EH_FRAME',

      0x6474e551: 'PT_GNU_STACK', 0x6474e552: 'PT_GNU_RELRO',
      0x6474e553: 'PT_GNU_PROPERTY'}
SHT = {0: 'SHT_NULL', 1: 'SHT_PROGBITS', 2: 'SHT_SYMTAB', 3: 'SHT_STRTAB',
       4: 'SHT_RELA', 5: 'SHT_HASH', 6: 'SHT_DYNAMIC', 7: 'SHT_NOTE',
       8: 'SHT_NOBITS', 9: 'SHT_REL', 10: 'SHT_SHLIB', 11: 'SHT_DYNSYM',
       14: 'SHT_INIT_ARRAY', 15: 'SHT_FINI_ARRAY', 16: 'SHT_PREINIT_ARRAY',
       17: 'SHT_GROUP', 18: 'SHT_SYMTAB_SHNDX', 0x6ffffff6: 'SHT_GNU_HASH',
       0x6ffffffd: 'SHT_GNU_verdef', 0x6ffffffe: 'SHT_GNU_verneed',
       0x6fffffff: 'SHT_GNU_versym'}
LINKED = (2, 11, 6, 4, 9, 5, 17, 18, 0x6ffffff6, 0x6ffffffd, 0x6ffffffe, 0x6fffffff)
SHF = [(1, 'WRITE'), (2, 'ALLOC'), (4, 'EXECINSTR'), (0x10, 'MERGE'),
       (0x20, 'STRINGS'), (0x40, 'INFO_LINK'), (0x80, 'LINK_ORDER'),
       (0x100, 'OS_NONCONFORMING'), (0x200, 'GROUP'), (0x400, 'TLS'),
       (0x800, 'COMPRESSED')]
STB = {0: 'LOCAL', 1: 'GLOBAL', 2: 'WEAK', 10: 'GNU_UNIQUE'}
STT = {0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC', 3: 'SECTION', 4: 'FILE',
       5: 'COMMON', 6: 'TLS', 10: 'GNU_IFUNC'}
STV = {0: 'DEFAULT', 1: 'INTERNAL', 2: 'HIDDEN', 3: 'PROTECTED'}
SHN = {0: 'SHN_UNDEF', 0xfff1: 'SHN_ABS', 0xfff2: 'SHN_COMMON', 0xffff: 'SHN_XINDEX'}
DT = {0: 'DT_NULL', 1: 'DT_NEEDED', 2: 'DT_PLTRELSZ', 3: 'DT_PLTGOT',
      4: 'DT_HASH', 5: 'DT_STRTAB', 6: 'DT_SYMTAB', 7: 'DT_RELA',
      8: 'DT_RELASZ', 9: 'DT_RELAENT', 10: 'DT_STRSZ', 11: 'DT_SYMENT',
      12: 'DT_INIT', 13: 'DT_FINI', 14: 'DT_SONAME', 15: 'DT_RPATH',
      16: 'DT_SYMBOLIC', 17: 'DT_REL', 18: 'DT_RELSZ', 19: 'DT_RELENT',
      20: 'DT_PLTREL', 21: 'DT_DEBUG', 22: 'DT_TEXTREL', 23: 'DT_JMPREL',
      24: 'DT_BIND_NOW', 25: 'DT_INIT_ARRAY', 26: 'DT_FINI_ARRAY',
      27: 'DT_INIT_ARRAYSZ', 28: 'DT_FINI_ARRAYSZ', 29: 'DT_RUNPATH',
      30: 'DT_FLAGS', 0x6ffffef5: 'DT_GNU_HASH', 0x6ffffff0: 'DT_VERSYM',
      0x6ffffff9: 'DT_RELACOUNT', 0x6ffffffa: 'DT_RELCOUNT',
      0x6ffffffb: 'DT_FLAGS_1', 0x6ffffffc: 'DT_VERDEF',
      0x6ffffffd: 'DT_VERDEFNUM', 0x6ffffffe: 'DT_VERNEED',
      0x6fffffff: 'DT_VERNEEDNUM'}

DT_STRING = (1, 14, 15, 29)
DT_ADDR = (3, 4, 5, 6, 7, 12, 13, 17, 23, 25, 26, 0x6ffffef5, 0x6ffffff0,
           0x6ffffffc, 0x6ffffffe)
DT_SIZE = (2, 8, 9, 10, 11, 18, 19, 27, 28, 0x6ffffff9, 0x6ffffffa,
           0x6ffffffd, 0x6fffffff)

DESC = {
    'EI_MAG': 'Magic number: 7f 45 4c 46 = DEL "ELF"',
    'EI_CLASS': 'File class: 32-bit or 64-bit layout of all structures',
    'EI_DATA': 'Byte order of all multi-byte fields in the file',
    'EI_VERSION': 'ELF version (always 1)',
    'EI_OSABI': 'Target OS ABI',
    'EI_ABIVERSION': 'ABI version',
    'EI_PAD': 'Padding (should be zero)',
    'e_type': 'Object file type',
    'e_machine': 'Target CPU architecture',
    'e_version': 'ELF version (1)',
    'e_entry': 'Virtual address of the entry point',
    'e_phoff': 'File offset of the program header table',
    'e_shoff': 'File offset of the section header table (0 = none)',
    'e_flags': 'Processor-specific flags',
    'e_ehsize': 'Size of this ELF header in bytes',
    'e_phentsize': 'Size of one program header entry',
    'e_phnum': 'Number of program header entries',
    'e_shentsize': 'Size of one section header entry',
    'e_shnum': 'Number of section header entries',
    'e_shstrndx': 'Index of the section that holds the section names',
    'p_type': 'Segment type',
    'p_flags': 'Segment permissions (Read / Write / eXecute)',
    'p_offset': 'File offset of the segment contents',
    'p_vaddr': 'Virtual address of the segment in memory',
    'p_paddr': 'Physical address (usually the same as p_vaddr)',

    'p_filesz': 'Number of segment bytes that are present in the file',
    'p_memsz': 'Number of segment bytes in memory',
    'p_align': 'Required alignment of offset and address',
    'sh_name': 'Offset of the section name inside the section-name string table',
    'sh_type': 'Section type',
    'sh_flags': 'Section flags',
    'sh_addr': 'Virtual address when loaded (0 = not loaded)',
    'sh_offset': 'File offset of the section contents',
    'sh_size': 'Size of the section in bytes',
    'sh_link': 'Index of a related section (meaning depends on the type)',
    'sh_info': 'Extra information (meaning depends on the type)',
    'sh_addralign': 'Required alignment of the section',
    'sh_entsize': 'Size of one entry for table-like sections (0 = not a table)',
    'st_name': 'Offset of the symbol name inside the linked string table',
    'st_info': 'Symbol binding (high 4 bits) and type (low 4 bits)',
    'st_other': 'Symbol visibility',
    'st_shndx': 'Index of the section the symbol belongs to',
    'st_value': 'Symbol value (usually an address)',
    'st_size': 'Size of the symbol in bytes',
    'r_offset': 'Location the relocation applies to',
    'r_info': 'Symbol index and relocation type',
    'r_addend': 'Constant addend used to compute the value',
    'd_tag': 'Dynamic entry tag',
    'd_un': 'Value or address of the dynamic entry (depends on d_tag)',
}

IDENT_LAYOUT = [('EI_MAG', 4), ('EI_CLASS', 1), ('EI_DATA', 1),
                ('EI_VERSION', 1), ('EI_OSABI', 1), ('EI_ABIVERSION', 1),
                ('EI_PAD', 7)]
BYTES_FIELDS = ('EI_MAG', 'EI_PAD')

HELP_LINES = [

    'Keys',
    '  /           search structures by name; choose when there are several matches',
    '  z           fold/unfold current zero content range (at least 64 B)',
    '  Z           collapse all zero ranges / expand all (starts expanded)',
    '  v in tag column: click to fold; > zero summary: click to expand',
    '  Folds retain original offsets and region names. Headers/strings/symbols stay visible.',
    '  Search / goto / pointer jumps automatically reveal their destination.',
    '  Mouse wheel up/down          scroll the file by 3 displayed rows',
    '  Wheel respects collapsed ranges and stops at the file boundaries.',
    '  If the selected byte leaves the screen, selection moves to the nearest visible row.',
    '  Mouse move / left click       inspect a byte (hex or ASCII column)',
    '  m           mouse tracking on/off (off allows normal text selection)',
    '  Hover needs terminal support for all-motion mouse events; arrows always work.',
    '  If a terminal/multiplexer filters motion, try clicking or a direct terminal.',
    '  Use a wide terminal (at least 96 columns for hex + ASCII).',
    '  arrows, PgUp, PgDn, Home, End   move the cursor',
    '  Enter       follow the pointer stored in the field under the cursor',
    '  Backspace   go back to where you came from',
    '  g           go to an offset (hex, for example 40 or 0x1040)',
    '  n / N       next / previous annotated item',
    '  w           warnings and structures that are not in the file',
    '  ?           this help          q   quit',
    '',
    'Table',
    '  separator before a byte:  # region starts   | field starts   > field that points elsewhere',
    '  left tag: EHDR PHDR SHDR STR SYM DYN REL CODE DATA SEC SEG gap TAIL RAW',
    '            a trailing ! means a warning (for example an overlap) on that line',
    '  current field is underlined, the pointer target is shown in reverse video',
    '  the file is never modified',
]


# ------------------------------------------------------------------ helpers

def hx(v):
    return '0x%x' % v


def trunc(s, k):
    return s if len(s) <= k else s[:k] + '...'


def nm(tbl, v):
    s = tbl.get(v)
    return s if s is not None else 'unknown 0x%x' % v



def ptshort(t):
    s = PT.get(t)
    return s[3:] if s else '0x%x' % t


def pflags(v):
    s = ('R' if v & 4 else '-') + ('W' if v & 2 else '-') + ('X' if v & 1 else '-')
    if v & ~7:
        s += '|0x%x' % (v & ~7)
    return s


def flags_str(v, table):
    out = [name for bit, name in table if v & bit]
    rest = v
    for bit, _ in table:
        rest &= ~bit
    if rest:
        out.append('0x%x' % rest)
    return '|'.join(out) if out else '0'


def lsize(layout):
    return sum(sz for _, sz in layout)


def ehdr_layout(is64):
    w = 8 if is64 else 4
    return [('e_type', 2), ('e_machine', 2), ('e_version', 4), ('e_entry', w),
            ('e_phoff', w), ('e_shoff', w), ('e_flags', 4), ('e_ehsize', 2),
            ('e_phentsize', 2), ('e_phnum', 2), ('e_shentsize', 2),

            ('e_shnum', 2), ('e_shstrndx', 2)]


def phdr_layout(is64):
    if is64:
        return [('p_type', 4), ('p_flags', 4), ('p_offset', 8), ('p_vaddr', 8),
                ('p_paddr', 8), ('p_filesz', 8), ('p_memsz', 8), ('p_align', 8)]
    return [('p_type', 4), ('p_offset', 4), ('p_vaddr', 4), ('p_paddr', 4),
            ('p_filesz', 4), ('p_memsz', 4), ('p_flags', 4), ('p_align', 4)]


def shdr_layout(is64):
    w = 8 if is64 else 4
    return [('sh_name', 4), ('sh_type', 4), ('sh_flags', w), ('sh_addr', w),
            ('sh_offset', w), ('sh_size', w), ('sh_link', 4), ('sh_info', 4),
            ('sh_addralign', w), ('sh_entsize', w)]


def sym_layout(is64):
    if is64:
        return [('st_name', 4), ('st_info', 1), ('st_other', 1), ('st_shndx', 2),
                ('st_value', 8), ('st_size', 8)]
    return [('st_name', 4), ('st_value', 4), ('st_size', 4), ('st_info', 1),
            ('st_other', 1), ('st_shndx', 2)]


def rela_layout(is64):
    w = 8 if is64 else 4
    return [('r_offset', w), ('r_info', w), ('r_addend', w)]


def rel_layout(is64):

    w = 8 if is64 else 4
    return [('r_offset', w), ('r_info', w)]


def dyn_layout(is64):
    w = 8 if is64 else 4
    return [('d_tag', w), ('d_un', w)]


def sec_group(t, flags):
    if t == 3:
        return 'strtab'
    if t in (2, 11):
        return 'symtab'
    if t == 6:
        return 'dynamic'
    if t in (4, 9):
        return 'reloc'
    if flags & 4:
        return 'code'
    if flags & 2:
        return 'data'
    return 'sec'


# -------------------------------------------------------------------- model

class Ann(object):
    """A byte range with a meaning. kind: field | string | region | gap."""
    __slots__ = ('start', 'end', 'prio', 'kind', 'group', 'name', 'rec', 'val',
                 'desc', 'target', 'tlen', 'tlabel', 'region', 'warn', 'first',
                 'idx')


    def __init__(self, start, end, prio, kind, group, name, rec='', val='',
                 desc='', region=None):
        self.start = start
        self.end = end
        self.prio = prio
        self.kind = kind
        self.group = group
        self.name = name
        self.rec = rec
        self.val = val
        self.desc = desc
        self.target = None
        self.tlen = 1
        self.tlabel = ''
        self.region = region if region is not None else self
        self.warn = None
        self.first = False
        self.idx = 0


class Model(object):
    def __init__(self, data):
        self.data = data
        self.size = len(data)
        self.is64 = False
        self.order = 'little'
        self.anns = []
        self.warnings = []
        self.memonly = []
        self.segs = []
        self.seg_ev = {}

        self.loads = []
        self.pieces = []
        self.starts = []
        self.refs_in = {}
        self.summary = ''
        self.gap_name = None
        self.gap_group = 'gap'
        self.gap_desc = ''
        self.counter = 0

    def warn(self, msg):
        if len(self.warnings) < 300:
            self.warnings.append(msg)
        elif len(self.warnings) == 300:
            self.warnings.append('... further warnings suppressed')

    def add(self, a):
        a.idx = self.counter
        self.counter += 1
        self.anns.append(a)

    def region(self, start, end, group, name, val='', desc=''):
        end = min(end, self.size)
        a = Ann(start, end, PR_REGION, 'region', group, name, '', val, desc)
        if end > start:
            self.add(a)
        return a

    def v2o(self, v):
        for vaddr, filesz, off in self.loads:
            if vaddr <= v < vaddr + filesz:
                o = v - vaddr + off

                if 0 <= o < self.size:
                    return o
        return None


def read_vals(m, off, layout):
    vals = {}
    pos = off
    for name, size in layout:
        if pos + size > m.size:
            break
        vals[name] = int.from_bytes(m.data[pos:pos + size], m.order)
        pos += size
    return vals


def cstr_at(m, off, maxlen=4096):
    if off < 0 or off >= m.size:
        return None
    lim = min(m.size, off + maxlen)
    e = m.data.find(b'\x00', off, lim)
    if e < 0:
        e = lim
        nb = e - off
    else:
        nb = e - off + 1
    return m.data[off:e].decode('utf-8', 'replace'), nb


def off_target(m, off, label, length=1):
    if 0 <= off < m.size:
        return (off, max(1, length), label)

    return None


def sec_target(ex, i):
    return (ex['shoff'] + i * ex['shentsize'], ex['shentsize'],
            'section header [%d]' % i)


# ----------------------------------------------------------- field decoding

def describe(m, name, val, raw, full, ex):
    """Return (value text, description, target or None)."""
    desc = DESC.get(name, '')
    tgt = None
    is64 = m.is64
    names = ex.get('names', [])
    if val is None:
        txt = ' '.join('%02x' % b for b in raw)
        if name == 'EI_MAG' and bytes(raw) != b'\x7fELF':
            desc += ' [INVALID]'
        return txt, desc, None
    txt = str(val)
    if name == 'EI_CLASS':
        txt = nm(CLASS, val)
    elif name == 'EI_DATA':
        txt = nm(DATA, val)
    elif name == 'EI_VERSION':
        txt = '1 (EV_CURRENT)' if val == 1 else str(val)
    elif name == 'EI_OSABI':
        txt = nm(OSABI, val)
    elif name == 'e_type':
        txt = nm(ET, val)

    elif name == 'e_machine':
        txt = nm(EM, val)
    elif name == 'e_entry':
        txt = hx(val)
        o = m.v2o(val)
        if o is not None:
            tgt = (o, 1, 'entry point, file offset 0x%x' % o)
    elif name == 'e_phoff':
        txt = hx(val)
        if val:
            tgt = off_target(m, val, 'program header table',
                             ex.get('phcount', 0) * full.get('e_phentsize', 0))
    elif name == 'e_shoff':
        txt = hx(val)
        if val:
            tgt = off_target(m, val, 'section header table',
                             ex.get('shnum', 0) * ex.get('shentsize', 0))
    elif name == 'e_flags':
        txt = hx(val)
    elif name in ('e_ehsize', 'e_phentsize', 'e_shentsize'):
        exp = {'e_ehsize': 64 if is64 else 52,
               'e_phentsize': 56 if is64 else 32,
               'e_shentsize': 64 if is64 else 40}[name]
        if val != exp:
            desc += ' [expected %d]' % exp
    elif name == 'e_shnum':
        if val == 0 and ex.get('shnum', 0):
            txt = '0 (real count %d is in section 0 sh_size)' % ex['shnum']
    elif name == 'e_shstrndx':
        eff = ex.get('shstrndx', val) if val == 0xffff else val
        if val == 0xffff:
            txt = '0xffff (SHN_XINDEX, real index %d is in section 0 sh_link)' % eff

        if 0 < eff < ex.get('shnum', 0):
            tgt = sec_target(ex, eff)
            if eff < len(names):
                txt += ' (%s)' % names[eff]
    elif name == 'p_type':
        txt = nm(PT, val)
    elif name == 'p_flags':
        txt = pflags(val)
    elif name == 'p_offset':
        txt = hx(val)
        if full.get('p_filesz'):
            tgt = off_target(m, val, 'segment contents', full['p_filesz'])
    elif name in ('p_vaddr', 'p_paddr', 'p_align'):
        txt = hx(val)
    elif name == 'p_memsz':
        fs = full.get('p_filesz', 0)
        if val > fs:
            desc += ' [%d bytes are zero-filled in memory only]' % (val - fs)
    elif name == 'sh_name':
        so = ex.get('shstr')
        if so is not None:
            r = cstr_at(m, so + val)
            if r:
                txt = "%d '%s'" % (val, trunc(r[0], 30))
                tgt = (so + val, r[1], 'section name')
    elif name == 'sh_type':
        txt = nm(SHT, val)
    elif name == 'sh_flags':
        txt = flags_str(val, SHF)
    elif name == 'sh_addr':
        txt = hx(val)
    elif name == 'sh_offset':

        txt = hx(val)
        t = full.get('sh_type', 0)
        if t == 8:
            desc = 'NOBITS section: has an offset but NO bytes in the file (like .bss)'
        elif t != 0 and full.get('sh_size'):
            tgt = off_target(m, val, 'section contents', full['sh_size'])
    elif name == 'sh_size':
        if full.get('sh_type') == 8:
            desc += ' [memory size only, not stored in the file]'
    elif name == 'sh_link':
        if val and val < ex.get('shnum', 0) and full.get('sh_type') in LINKED:
            tgt = sec_target(ex, val)
            if val < len(names):
                txt = '%d (%s)' % (val, names[val])
    elif name == 'st_name':
        so = ex.get('str')
        if so is not None:
            r = cstr_at(m, so + val)
            if r:
                txt = "%d '%s'" % (val, trunc(r[0], 30))
                tgt = (so + val, r[1], 'symbol name')
    elif name == 'st_info':
        txt = '%s %s' % (nm(STB, val >> 4), nm(STT, val & 15))
    elif name == 'st_other':
        txt = nm(STV, val & 3)
    elif name == 'st_shndx':
        if val in SHN:
            txt = SHN[val]
        elif 0 < val < ex.get('shnum', 0):
            tgt = sec_target(ex, val)
            if val < len(names):
                txt = '%d (%s)' % (val, names[val])

    elif name == 'st_value':
        txt = hx(val)
    elif name == 'r_offset':
        txt = hx(val)
    elif name == 'r_info':
        if is64:
            txt = 'sym=%d type=%d' % (val >> 32, val & 0xffffffff)
        else:
            txt = 'sym=%d type=%d' % (val >> 8, val & 0xff)
    elif name == 'r_addend':
        bits = 64 if is64 else 32
        if val >= 1 << (bits - 1):
            val -= 1 << bits
        txt = str(val)
    elif name == 'd_tag':
        txt = nm(DT, val)
    elif name == 'd_un':
        tag = full.get('d_tag')
        if tag in DT_STRING:
            do = ex.get('dynstr')
            if do is not None:
                r = cstr_at(m, do + val)
                if r:
                    txt = "%d '%s'" % (val, trunc(r[0], 30))
                    tgt = (do + val, r[1], 'dynamic string')
        elif tag in DT_ADDR:
            txt = hx(val)
            o = m.v2o(val)
            if o is not None:
                tgt = (o, 1, 'DT address, file offset 0x%x' % o)
        elif tag in DT_SIZE:
            txt = str(val)

        else:
            txt = hx(val)
    return txt, desc, tgt


def emit_record(m, off, layout, rec, region, ex):
    full = read_vals(m, off, layout)
    pos = off
    first = True
    for name, size in layout:
        if pos + size > m.size:
            m.warn('%s %s: cut off by the end of the file at field %s (offset 0x%x)'
                   % (region.name, rec, name, pos))
            break
        raw = m.data[pos:pos + size]
        val = None if name in BYTES_FIELDS else int.from_bytes(raw, m.order)
        txt, desc, tgt = describe(m, name, val, raw, full, ex)
        a = Ann(pos, pos + size, PR_FIELD, 'field', region.group, name, rec,
                txt, desc, region)
        a.first = first
        first = False
        if tgt:
            a.target, a.tlen, a.tlabel = tgt
        m.add(a)
        pos += size


def emit_table(m, region, layout, prefix, stride, ex, cap):
    count = (region.end - region.start) // stride
    if count > cap:
        m.warn('%s: %d records, only the first %d are decoded'
               % (region.name, count, cap))

        count = cap
    for i in range(count):
        emit_record(m, region.start + i * stride, layout,
                    '%s[%d]' % (prefix, i), region, ex)


def emit_strings(m, region):
    d = m.data
    pos = region.start
    count = 0
    while pos < region.end:
        if count >= CAP_STRINGS:
            m.warn('%s: more than %d strings, the rest is not split into strings'
                   % (region.name, CAP_STRINGS))
            break
        e = d.find(b'\x00', pos, region.end)
        if e < 0:
            end = region.end
            text = d[pos:end]
            desc = 'String without a NUL terminator (runs to the end of the section)'
        else:
            end = e + 1
            text = d[pos:e]
            desc = 'NUL-terminated string'
        s = repr(text.decode('utf-8', 'replace'))
        if len(s) > 60:
            s = s[:57] + '...'
        a = Ann(pos, end, PR_FIELD, 'string', region.group, 'str', '', s, desc,
                region)
        a.first = pos == region.start
        m.add(a)
        pos = end

        count += 1


def read_dyn_tags(m, off, size):
    tags = {}
    w = 8 if m.is64 else 4
    for k in range(min(size // (2 * w), CAP_DYN)):
        p = off + k * 2 * w
        if p + 2 * w > m.size:
            break
        tag = int.from_bytes(m.data[p:p + w], m.order)
        val = int.from_bytes(m.data[p + w:p + 2 * w], m.order)
        if tag == 0:
            break
        tags.setdefault(tag, val)
    return tags


# ----------------------------------------------------------------- analysis

def _analyze(m):
    d = m.data
    n = m.size
    if n < 4 or d[:4] != b'\x7fELF':
        m.warn('Not an ELF file (the magic is not 7f 45 4c 46): showing raw bytes only')
        m.gap_name = 'raw bytes (not an ELF file)'
        m.gap_group = 'bad'
        m.gap_desc = 'There is no ELF magic at offset 0'
        m.summary = 'not an ELF file'
        return
    if n < 16:
        m.warn('The file is shorter than e_ident (16 bytes)')

        r = m.region(0, n, 'ehdr', 'ELF header (truncated)', '',
                     'The file ends inside e_ident')
        emit_record(m, 0, IDENT_LAYOUT, '', r, {})
        m.summary = 'truncated ELF'
        return
    cls, dat = d[4], d[5]
    if cls not in (1, 2) or dat not in (1, 2):
        m.warn('Invalid EI_CLASS (%d) or EI_DATA (%d): multi-byte fields cannot be '
               'decoded, only e_ident is annotated' % (cls, dat))
        r = m.region(0, 16, 'ehdr', 'ELF header (e_ident only)', '',
                     'e_ident is readable, the rest cannot be decoded')
        emit_record(m, 0, IDENT_LAYOUT, '', r, {})
        m.summary = 'ELF with an invalid class/data byte'
        return

    m.is64 = cls == 2
    m.order = 'little' if dat == 1 else 'big'
    w = 8 if m.is64 else 4
    elayout = IDENT_LAYOUT + ehdr_layout(m.is64)
    esz = lsize(elayout)
    if n < esz:
        m.warn('The file is shorter than the ELF header (%d bytes needed)' % esz)
        r = m.region(0, n, 'ehdr', 'ELF header (truncated)', '', '')
        emit_record(m, 0, elayout, '', r, {})
        m.summary = 'truncated ELF%d' % (64 if m.is64 else 32)
        return
    eh = read_vals(m, 0, elayout)
    m.summary = 'ELF%d %s-endian %s %s' % (
        64 if m.is64 else 32, 'little' if dat == 1 else 'big',
        nm(ET, eh['e_type']), nm(EM, eh['e_machine']))

    # ---- phase 1: raw reads (no annotations yet)

    shoff, shentsize = eh['e_shoff'], eh['e_shentsize']
    shnum, shstrndx, phnum = eh['e_shnum'], eh['e_shstrndx'], eh['e_phnum']
    shl = shdr_layout(m.is64)
    shexp = lsize(shl)
    sec0 = None
    if shoff:
        if shentsize < shexp:
            m.warn('e_shentsize is %d, smaller than the %d bytes of a section header: '
                   'section headers are not decoded' % (shentsize, shexp))
        elif shoff + shexp > n:
            m.warn('e_shoff 0x%x points outside the file (or the first section '
                   'header is cut off)' % shoff)
        else:
            sec0 = read_vals(m, shoff, shl)
    if sec0 is not None:
        if shnum == 0 and sec0['sh_size']:
            shnum = sec0['sh_size']
        if shstrndx == 0xffff:
            shstrndx = sec0['sh_link']
        if phnum == 0xffff:
            phnum = sec0['sh_info']
        if shnum == 0:
            m.warn('e_shoff is set but the section count is 0: no section headers')

    phoff, phentsize = eh['e_phoff'], eh['e_phentsize']
    play = phdr_layout(m.is64)
    phexp = lsize(play)
    phdrs = []
    if phnum and phoff:
        if phentsize < phexp:
            m.warn('e_phentsize is %d, smaller than the %d bytes of a program '
                   'header: program headers are not decoded' % (phentsize, phexp))

        elif phoff >= n:
            m.warn('e_phoff 0x%x is outside the file' % phoff)
        else:
            cnt = phnum
            if cnt > CAP_PHDRS:
                m.warn('e_phnum is %d, only the first %d are decoded' % (cnt, CAP_PHDRS))
                cnt = CAP_PHDRS
            avail = (n - phoff) // phentsize
            if cnt > avail:
                m.warn('The program header table is cut off by the end of the file '
                       '(%d of %d entries present)' % (avail, cnt))
                cnt = avail
            if phentsize != phexp:
                m.warn('e_phentsize is %d, expected %d' % (phentsize, phexp))
            for i in range(cnt):
                v = read_vals(m, phoff + i * phentsize, play)
                v['idx'] = i
                phdrs.append(v)
    elif phnum:
        m.warn('e_phnum is %d but e_phoff is 0' % phnum)
    m.loads = [(v['p_vaddr'], v['p_filesz'], v['p_offset'])
               for v in phdrs if v['p_type'] == 1]

    secs = []
    if sec0 is not None and shnum:
        cnt = shnum
        if cnt > CAP_SHDRS:
            m.warn('Section count is %d, only the first %d are decoded' % (cnt, CAP_SHDRS))
            cnt = CAP_SHDRS
        avail = (n - shoff) // shentsize
        if cnt > avail:
            m.warn('The section header table is cut off by the end of the file '

                   '(%d of %d entries present)' % (avail, cnt))
            cnt = avail
        if shentsize != shexp:
            m.warn('e_shentsize is %d, expected %d' % (shentsize, shexp))
        for i in range(cnt):
            v = read_vals(m, shoff + i * shentsize, shl)
            v['idx'] = i
            secs.append(v)

    shstr_off = None
    if secs:
        if shstrndx < len(secs):
            s = secs[shstrndx]
            if s['sh_type'] != 8 and s['sh_offset'] < n:
                shstr_off = s['sh_offset']
                if s['sh_type'] != 3:
                    m.warn('The section-name section [%d] is not SHT_STRTAB' % shstrndx)
            else:
                m.warn('The section-name section [%d] has no usable bytes in the file'
                       % shstrndx)
        else:
            m.warn('e_shstrndx %d is out of range (only %d sections)'
                   % (shstrndx, len(secs)))
    names = []
    for s in secs:
        i = s['idx']
        r = cstr_at(m, shstr_off + s['sh_name']) if shstr_off is not None else None
        if r and r[0]:
            names.append(r[0])
        else:
            names.append('(null)' if i == 0 else 'section[%d]' % i)


    dyn_tags = {}
    dyn_seg = None
    for v in phdrs:
        if v['p_type'] == 2 and v['p_offset'] < n:
            dyn_seg = v
            dyn_tags = read_dyn_tags(m, v['p_offset'], v['p_filesz'])
            break

    ex = {'shoff': shoff, 'shentsize': shentsize, 'shnum': len(secs),
          'shstr': shstr_off, 'names': names, 'shstrndx': shstrndx,
          'phcount': len(phdrs), 'str': None, 'dynstr': None}

    # ---- phase 2: annotations
    ereg = m.region(0, esz, 'ehdr', 'ELF header', m.summary,
                    'Fixed-size header at the start of every ELF file')
    emit_record(m, 0, elayout, '', ereg, ex)

    if phdrs:
        preg = m.region(phoff, phoff + len(phdrs) * phentsize, 'phdr',
                        'Program header table',
                        '%d x %d B' % (len(phdrs), phentsize),
                        'Array of program headers: each one describes a segment '
                        '(what the loader maps)')
        for v in phdrs:
            emit_record(m, phoff + v['idx'] * phentsize, play,
                        'ph[%d]' % v['idx'], preg, ex)
        for v in phdrs:
            t, i = v['p_type'], v['idx']
            fs, mem, po = v['p_filesz'], v['p_memsz'], v['p_offset']
            if mem > fs:
                m.memonly.append('%s (ph[%d]): %d bytes are zero-filled in memory only '
                                 '(p_memsz > p_filesz)' % (nm(PT, t), i, mem - fs))

            if fs and po < n and t not in (0, 6):
                e = min(n, po + fs)
                if po + fs > n:
                    m.warn('ph[%d] (%s) extends %d bytes past the end of the file'
                           % (i, nm(PT, t), po + fs - n))
                if len(m.segs) < 2000:
                    m.segs.append((po, e, '%s%d' % (ptshort(t), i)))
                a = Ann(po, e, PR_SEG, 'region', 'seg', '%s[%d] content' % (nm(PT, t), i),
                        '', pflags(v['p_flags']),
                        'Bytes covered by this segment (an overlay: other regions '
                        'may sit inside it)')
                m.add(a)

    if secs:
        sreg = m.region(shoff, shoff + len(secs) * shentsize, 'shdr',
                        'Section header table',
                        '%d x %d B' % (len(secs), shentsize),
                        'Array of section headers (linker view); names are in the '
                        'section-name string table')
        for s in secs:
            emit_record(m, shoff + s['idx'] * shentsize, shl,
                        'sh[%d]' % s['idx'], sreg, ex)
        for s in secs:
            i, t = s['idx'], s['sh_type']
            off, size = s['sh_offset'], s['sh_size']
            if i == 0 or t == 0:
                continue
            if t == 8:
                if size:
                    m.memonly.append('%s (sh[%d]): %d bytes in memory only (SHT_NOBITS)'
                                     % (names[i], i, size))
                continue

            if size == 0:
                continue
            if off >= n:
                m.warn('%s (sh[%d]): sh_offset 0x%x is outside the file' % (names[i], i, off))
                continue
            end = off + size
            if end > n:
                m.warn('%s (sh[%d]) extends %d bytes past the end of the file'
                       % (names[i], i, end - n))
                end = n
            grp = sec_group(t, s['sh_flags'])
            r = m.region(off, end, grp, names[i], '%s, %d B' % (nm(SHT, t), size),
                         'section [%d]: %s, flags %s, address %s'
                         % (i, nm(SHT, t), flags_str(s['sh_flags'], SHF), hx(s['sh_addr'])))
            ex2 = dict(ex)
            link = s['sh_link']
            lk = None
            if link < len(secs) and secs[link]['sh_type'] == 3 and secs[link]['sh_offset'] < n:
                lk = secs[link]['sh_offset']
            if t == 3:
                emit_strings(m, r)
            elif t in (2, 11):
                ex2['str'] = lk
                sl = sym_layout(m.is64)
                stride = s['sh_entsize'] if s['sh_entsize'] >= lsize(sl) else lsize(sl)
                emit_table(m, r, sl, 'sym', stride, ex2, CAP_RECORDS)
            elif t == 6:
                ex2['dynstr'] = lk
                dl = dyn_layout(m.is64)
                stride = s['sh_entsize'] if s['sh_entsize'] >= lsize(dl) else lsize(dl)
                emit_table(m, r, dl, 'dyn', stride, ex2, CAP_DYN)
            elif t in (4, 9):

                rl = rela_layout(m.is64) if t == 4 else rel_layout(m.is64)
                stride = s['sh_entsize'] if s['sh_entsize'] >= lsize(rl) else lsize(rl)
                emit_table(m, r, rl, 'rel', stride, ex2, CAP_RECORDS)
    else:
        if shoff == 0:
            m.warn('No section headers (e_shoff = 0): section-level structure is '
                   'not available, the viewer works from the program headers')
        if dyn_seg is None:
            m.warn('No section headers and no PT_DYNAMIC: only the headers and the '
                   'segments are annotated')
        else:
            m.warn('Tables below marked "inferred" are reconstructed from PT_DYNAMIC '
                   'and may be incomplete')
            off, sz = dyn_seg['p_offset'], dyn_seg['p_filesz']
            dstr = m.v2o(dyn_tags[5]) if 5 in dyn_tags else None
            ex2 = dict(ex)
            ex2['dynstr'] = dstr
            dl = dyn_layout(m.is64)
            if sz:
                r = m.region(off, off + sz, 'dynamic', 'Dynamic table (PT_DYNAMIC)',
                             '', 'Entries describing dynamic linking information')
                emit_table(m, r, dl, 'dyn', lsize(dl), ex2, CAP_DYN)
            if dstr is not None and dyn_tags.get(10):
                r = m.region(dstr, dstr + dyn_tags[10], 'strtab',
                             '.dynstr (inferred from DT_STRTAB)',
                             '%d B' % dyn_tags[10],
                             'Dynamic string table found through PT_DYNAMIC')
                emit_strings(m, r)
            sy = m.v2o(dyn_tags[6]) if 6 in dyn_tags else None
            sl = sym_layout(m.is64)
            if sy is not None and dstr is not None and dstr > sy and \
                    (dstr - sy) >= lsize(sl):

                r = m.region(sy, dstr, 'symtab',
                             '.dynsym (inferred: DT_SYMTAB up to DT_STRTAB)',
                             '', 'Dynamic symbol table; its size is guessed from '
                             'the address of the string table')
                ex3 = dict(ex)
                ex3['str'] = dstr
                emit_table(m, r, sl, 'sym', lsize(sl), ex3, CAP_RECORDS)
            pltrel = dyn_tags.get(20)
            for (ptag, stag, label, kind) in (
                    (7, 8, '.rela.dyn (inferred from DT_RELA)', 4),
                    (17, 18, '.rel.dyn (inferred from DT_REL)', 9),
                    (23, 2, '.rela.plt/.rel.plt (inferred from DT_JMPREL)',
                     4 if pltrel == 7 else 9)):
                if ptag in dyn_tags and dyn_tags.get(stag):
                    ro = m.v2o(dyn_tags[ptag])
                    if ro is None:
                        continue
                    rl = rela_layout(m.is64) if kind == 4 else rel_layout(m.is64)
                    r = m.region(ro, ro + dyn_tags[stag], 'reloc', label,
                                 '%d B' % dyn_tags[stag], 'Relocation entries')
                    emit_table(m, r, rl, 'rel', lsize(rl), ex, CAP_RECORDS)


def make_gap(m, s, e, last_end):
    if m.gap_name:
        name, group, desc = m.gap_name, m.gap_group, m.gap_desc
    elif s >= last_end:
        name, group = 'trailing data after the last known structure', 'tail'
        desc = 'Nothing in the ELF headers describes these bytes (overlay, signature, ...)'
    elif m.data.count(b'\x00', s, e) == e - s:
        name, group = 'padding (all zero)', 'gap'
        desc = 'Zero bytes between structures (alignment padding)'

    else:
        name, group = 'unclaimed bytes', 'gap'
        desc = 'Bytes not described by any header or section the viewer understands'
    a = Ann(s, e, PR_GAP, 'gap', group, name, '', '', desc)
    a.idx = m.counter
    m.counter += 1
    return a


def build_pieces(m):
    n = m.size
    anns = [a for a in m.anns if a.start < n and a.end > a.start]
    anns.sort(key=lambda a: a.start)
    last_end = max([a.end for a in anns] or [0])
    heap = []
    i = 0
    na = len(anns)
    pos = 0
    raw = []
    while pos < n:
        while i < na and anns[i].start <= pos:
            a = anns[i]
            i += 1
            if a.end > pos:
                heapq.heappush(heap, (-a.prio, a.end - a.start, i, a))
        while heap and heap[0][3].end <= pos:
            heapq.heappop(heap)
        nxt = n
        if i < na and anns[i].start < nxt:
            nxt = anns[i].start
        if heap:
            top = heap[0][3]

            if top.end < nxt:
                nxt = top.end
            raw.append([pos, nxt, top])
        else:
            raw.append([pos, nxt, None])
        pos = nxt
    merged = []
    for s, e, a in raw:
        if merged and merged[-1][2] is a and merged[-1][1] == s:
            merged[-1][1] = e
        else:
            merged.append([s, e, a])
    pieces = []
    for s, e, a in merged:
        if a is None:
            a = make_gap(m, s, e, last_end)
        pieces.append((s, e, a))
    m.pieces = pieces
    m.starts = [p[0] for p in pieces]


def finish(m):
    tops = sorted((a for a in m.anns if a.kind == 'region' and a.prio == PR_REGION),
                  key=lambda a: (a.start, a.end))
    cur = None
    for a in tops:
        if cur is not None and a.start < cur.end:
            if not a.warn:
                a.warn = 'overlaps %s' % cur.name
            if not cur.warn:
                cur.warn = 'overlaps %s' % a.name
            m.warn('Overlap: %s [0x%x-0x%x] and %s [0x%x-0x%x]'

                   % (cur.name, cur.start, cur.end - 1, a.name, a.start, a.end - 1))
        if cur is None or a.end > cur.end:
            cur = a
    build_pieces(m)
    for a in m.anns:
        if a.target is not None:
            m.refs_in.setdefault(a.target, []).append(a)
    for s, e, label in m.segs:
        m.seg_ev.setdefault(s // 16 * 16, []).append('[' + label)
        m.seg_ev.setdefault((e - 1) // 16 * 16, []).append(label + ']')


def analyze(data):
    m = Model(data)
    try:
        _analyze(m)
    except Exception as exc:  # hostile or broken files must never crash the viewer
        m.warn('Internal analysis error (%s: %s): annotations may be incomplete'
               % (type(exc).__name__, exc))
    finish(m)
    return m


# ----------------------------------------------------------------- rendering

def ann_at(m, off):
    i = bisect.bisect_right(m.starts, off) - 1
    return m.pieces[i][2] if i >= 0 else None


class Line(object):
    pass



def build_line(m, lo, cs, notes_w):
    hi = min(lo + 16, m.size)
    pcs = m.pieces
    j = bisect.bisect_right(m.starts, lo) - 1
    inline = []
    q = j
    while q < len(pcs) and pcs[q][0] < hi:
        inline.append(pcs[q])
        q += 1
    cells = []
    k = j
    asc = []
    for p in range(lo, hi):
        while pcs[k][1] <= p:
            k += 1
        a = pcs[k][2]
        if a.region.start == p:
            sep = cs['rs']
        elif a.start == p:
            sep = cs['ps'] if a.target is not None else cs['fs']
        else:
            sep = ' '
        b = m.data[p]
        cells.append((sep, '%02x' % b, a, p))
        asc.append(chr(b) if 32 <= b < 127 else '.')
    L = Line()
    L.lo = lo
    L.cells = cells
    L.ascii = ''.join(asc)
    first = inline[0][2]

    L.group = first.group
    L.flagged = any(a.warn or a.region.warn for _, _, a in inline)
    L.tag = '%-4s%s ' % (TAGS.get(first.group, '?'), '!' if L.flagged else ' ')
    L.notes = ''
    if notes_w > 0:
        parts = []
        for s, e, a in inline:
            if s < lo or s != a.start:
                continue
            r = a.region
            if r.start == s:
                t = cs['lab'] + ' ' + r.name
                if r.val:
                    t += ' (' + r.val + ')'
                if r.warn:
                    t += ' ' + cs['warn'] + ' ' + r.warn
                parts.append(t)
                if r is a:
                    continue
            if a.kind == 'field':
                v = a.val if len(a.val) <= 28 else a.val[:27] + cs['ell']
                t = a.name + '=' + v
                if a.first and a.rec:
                    t = a.rec + ' ' + t
                if a.target is not None:
                    t += cs['arr']
                parts.append(t)
            elif a.kind == 'string':
                parts.append(a.val)
        if not parts:
            parts.append(cs['cont'] + ' ' + first.region.name)
        parts.extend(m.seg_ev.get(lo, []))

        s = '  '.join(parts)
        if len(s) > notes_w:
            s = s[:max(0, notes_w - 1)] + cs['ell']
        L.notes = s
    return L


def format_line(m, lo, cs, notes_w):
    L = build_line(m, lo, cs, notes_w)
    cells = ''.join(sep + hexs + ' ' for sep, hexs, _, _ in L.cells)
    cells += '    ' * (16 - len(L.cells))
    out = '%s%08x%s  %-16s  %s' % (L.tag, lo, cells, L.ascii, L.notes)
    return out.rstrip()


def info_lines(m, prefix=''):
    out = ['Summary: ' + m.summary, '']
    if m.memonly:
        out.append('Present in memory only (no bytes in the file):')
        out.extend('  ' + s for s in m.memonly)
        out.append('')
    if m.warnings:
        out.append('Warnings (%d):' % len(m.warnings))
        out.extend('  ' + s for s in m.warnings)
    else:
        out.append('No warnings.')
    return [prefix + s for s in out]


def pick_charset(encoding, force_ascii):
    if force_ascii:
        return ASC

    try:
        for ch in UNI.values():
            ch.encode(encoding or 'ascii')
    except (UnicodeEncodeError, LookupError):
        return ASC
    return UNI


# ---------------------------------------------------------------------- dump

def parse_range(text, size):
    a, _, b = text.partition(':')
    lo = int(a, 16) if a else 0
    hi = int(b, 16) if b else size
    return lo, hi


def do_dump(m, args, cs):
    lo, hi = 0, m.size
    if args.range:
        lo, hi = parse_range(args.range, m.size)
    lo -= lo % 16
    out = []
    pos = lo
    while pos < hi and pos < m.size:
        out.append(format_line(m, pos, cs, args.notes_width))
        pos += 16
    footer = ['# file: %s, %d bytes (0x%x); %s' % (args.file, m.size, m.size, m.summary)]
    if getattr(m, 'real_size', None):
        footer.append('# PARTIAL VIEW: the file really has %d bytes; only the first %d bytes '
                      '(%d MiB) are shown and analysed, everything after is NOT shown'
                      % (m.real_size, m.size, m.size >> 20))
    footer += [
              '# legend: %s region start, %s field start, %s field that points elsewhere; '
              'tag column: %s; "!" = warning on that line'
              % (cs['rs'], cs['fs'], cs['ps'], ' '.join(sorted(set(TAGS.values()))))]
    footer.extend(info_lines(m, '# ')[2:])

    sys.stdout.write('\n'.join(out + footer) + '\n')


# ---------------------------------------------------------------- interactive

def put(win, y, x, s, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w or x < 0:
        return
    s = s[:max(0, w - x)]
    try:
        win.addstr(y, x, s, attr)
    except (curses.error, UnicodeEncodeError):
        pass


def show_text(stdscr, lines):
    off = 0
    while True:
        h, w = stdscr.getmaxyx()
        stdscr.erase()
        for i, ln in enumerate(lines[off:off + h - 1]):
            put(stdscr, i, 0, ln)
        put(stdscr, h - 1, 0, ' arrows/PgUp/PgDn: scroll   any other key: back '.ljust(w),
            curses.A_REVERSE)
        stdscr.refresh()
        k = stdscr.getch()
        last = max(0, len(lines) - 1)
        if k in (curses.KEY_UP, ord('k')):
            off = max(0, off - 1)
        elif k in (curses.KEY_DOWN, ord('j')):
            off = min(last, off + 1)

        elif k == curses.KEY_PPAGE:
            off = max(0, off - max(1, h - 2))
        elif k == curses.KEY_NPAGE:
            off = min(last, off + max(1, h - 2))
        elif k == curses.KEY_RESIZE:
            continue
        else:
            return


def prompt(stdscr, text):
    h, w = stdscr.getmaxyx()
    stdscr.move(h - 1, 0)
    stdscr.clrtoeol()
    put(stdscr, h - 1, 0, text, curses.A_BOLD)
    curses.echo()
    try:
        curses.curs_set(1)
    except curses.error:
        pass
    try:
        s = stdscr.getstr(h - 1, len(text), 24)
    except curses.error:
        s = b''
    finally:
        curses.noecho()
        try:
            curses.curs_set(0)
        except curses.error:
            pass
    return s.decode('ascii', 'replace').strip()



def init_pairs(use_color):
    pairs = {}
    if not use_color:
        return pairs
    try:
        curses.start_color()
    except curses.error:
        return pairs
    dfl = True
    try:
        curses.use_default_colors()
    except curses.error:
        dfl = False

    def fix(c, fg):
        if c == -1 and not dfl:
            return curses.COLOR_WHITE if fg else curses.COLOR_BLACK
        return c

    C = curses
    spec = {
        'ehdr': (C.COLOR_BLACK, C.COLOR_CYAN),
        'phdr': (C.COLOR_BLACK, C.COLOR_YELLOW),
        'shdr': (C.COLOR_BLACK, C.COLOR_MAGENTA),
        'strtab': (C.COLOR_BLACK, C.COLOR_GREEN),
        'symtab': (C.COLOR_WHITE, C.COLOR_BLUE),
        'dynamic': (C.COLOR_WHITE, C.COLOR_RED),
        'reloc': (C.COLOR_BLACK, C.COLOR_WHITE),
        'code': (C.COLOR_CYAN, -1),
        'data': (C.COLOR_YELLOW, -1),
        'sec': (-1, -1),

        'seg': (C.COLOR_GREEN, -1),
        'gap': (-1, -1),
        'tail': (C.COLOR_RED, -1),
        'bad': (-1, -1),
    }
    k = 1
    for group, (fg, bg) in spec.items():
        try:
            curses.init_pair(k, fix(fg, True), fix(bg, False))
            pairs[group] = curses.color_pair(k)
        except curses.error:
            pass
        k += 1
    return pairs


def cell_attr(a, p, cur, la, trange, pairs):
    at = pairs.get(a.group, 0)
    if a.idx & 1:
        at |= curses.A_BOLD
    if a.group == 'gap':
        at |= curses.A_DIM
    if la.start <= p < la.end:
        at |= curses.A_UNDERLINE | curses.A_BOLD
    if trange is not None and trange[0] <= p < trange[1]:
        at |= curses.A_REVERSE
    if p == cur:
        at = curses.A_REVERSE | curses.A_BOLD | curses.A_UNDERLINE
    return at


def mouse_offset(m, x, y, top, height, width):
    """Map a visible hex pair or ASCII character to a file offset, never a gap."""
    if not (1 <= y <= height - 4) or not (0 <= x < width):
        return None
    relative = x - HEX_X
    if 0 <= relative < 16 * BYTE_PITCH and relative % BYTE_PITCH in (1, 2):
        column = relative // BYTE_PITCH
    elif width >= ASCII_X + 16 and ASCII_X <= x < ASCII_X + 16:
        column = x - ASCII_X
    else:
        return None
    offset = top + (y - 1) * 16 + column
    return offset if 0 <= offset < m.size else None


def read_input(stdscr):
    """Read keys and SGR mouse reports without ncurses' version-specific decoder.

    Some ncurses versions drop SGR no-button motion. keypad(False) keeps these
    reports intact. Coordinates in the protocol are one-based terminal cells.
    """
    key = stdscr.getch()
    if key != 27:
        return key, None
    seq = bytearray(b'\x1b')
    stdscr.timeout(35)
    try:
        while len(seq) < 64:
            ch = stdscr.getch()
            if ch < 0:
                break
            if ch > 255:
                return ch, None
            seq.append(ch)
            if len(seq) == 2 and ch not in (ord('['), ord('O')):
                break
            if len(seq) >= 3 and (64 <= ch <= 126) and ch != ord('['):
                break
    finally:
        stdscr.timeout(-1)
    data = bytes(seq)
    if data.startswith(b'\x1b[<') and data[-1:] in (b'M', b'm'):
        try:
            button, x, y = map(int, data[3:-1].split(b';'))
            return curses.KEY_MOUSE, (x - 1, y - 1, button, data[-1:] == b'M')
        except ValueError:
            return -1, None
    keys = {
        b'\x1b[A': curses.KEY_UP, b'\x1bOA': curses.KEY_UP,
        b'\x1b[B': curses.KEY_DOWN, b'\x1bOB': curses.KEY_DOWN,
        b'\x1b[C': curses.KEY_RIGHT, b'\x1bOC': curses.KEY_RIGHT,
        b'\x1b[D': curses.KEY_LEFT, b'\x1bOD': curses.KEY_LEFT,
        b'\x1b[5~': curses.KEY_PPAGE, b'\x1b[6~': curses.KEY_NPAGE,
        b'\x1b[H': curses.KEY_HOME, b'\x1bOH': curses.KEY_HOME,
        b'\x1b[1~': curses.KEY_HOME, b'\x1b[7~': curses.KEY_HOME,
        b'\x1b[F': curses.KEY_END, b'\x1bOF': curses.KEY_END,
        b'\x1b[4~': curses.KEY_END, b'\x1b[8~': curses.KEY_END,
        b'\x1bOM': curses.KEY_ENTER,
    }
    for cap, value in [('kcuu1', curses.KEY_UP), ('kcud1', curses.KEY_DOWN),
                       ('kcub1', curses.KEY_LEFT), ('kcuf1', curses.KEY_RIGHT),
                       ('kpp', curses.KEY_PPAGE), ('knp', curses.KEY_NPAGE),
                       ('khome', curses.KEY_HOME), ('kend', curses.KEY_END),
                       ('kent', curses.KEY_ENTER)]:
        code = curses.tigetstr(cap)
        if code:
            keys[code] = value
    return keys.get(data, -1), None


def set_mouse(enabled):
    """Request xterm all-motion + SGR events; this is not a support probe."""
    if not enabled:
        sys.stdout.write('\x1b[?1003l\x1b[?1002l\x1b[?1000l\x1b[?1006l')
    else:
        sys.stdout.write('\x1b[?1006h\x1b[?1003h')
    sys.stdout.flush()
    return enabled


import re


class FoldView(object):
    """Compressed display rows; file offsets and annotations never change."""
    def __init__(self, m):
        self.m = m
        self.folds = []
        self.closed = set()
        # Protect structured metadata, strings and symbol records. Only fold
        # full zero rows in one unambiguous content region at a time.
        allowed = ('gap', 'tail', 'data', 'code', 'sec', 'seg')
        spans = []
        for s, e, a in m.pieces:
            if a.group not in allowed or a.warn or a.region.warn:
                continue
            if spans and spans[-1][1] == s and spans[-1][2] is a.region:
                spans[-1] = (spans[-1][0], e, a.region)
            else:
                spans.append((s, e, a.region))
        for s, e, region in spans:
            for hit in re.compile(b'\x00{64,}').finditer(m.data, s, e):
                lo = (hit.start() + 15) // 16 * 16
                hi = hit.end() // 16 * 16
                if hi - lo >= 64:
                    self.folds.append((lo, hi, region))
        self.starts = [f[0] for f in self.folds]
        self.rebuild()

    def rebuild(self):
        self.blocks = []
        offset = row = 0
        for i in sorted(self.closed):
            lo, hi, _ = self.folds[i]
            if lo > offset:
                n = (lo - offset) // 16
                self.blocks.append((row, row + n, offset, None))
                row += n
            self.blocks.append((row, row + 1, lo, i))
            row += 1
            offset = hi
        if offset < self.m.size:
            n = (self.m.size - offset + 15) // 16
            self.blocks.append((row, row + n, offset, None))
            row += n
        self.count = row
        self.row_starts = [b[0] for b in self.blocks]
        self.file_starts = [b[2] for b in self.blocks]

    def fold_at(self, offset):
        i = bisect.bisect_right(self.starts, offset) - 1
        return i if i >= 0 and offset < self.folds[i][1] else None

    def row_at(self, offset):
        i = bisect.bisect_right(self.file_starts, offset) - 1
        first, _, lo, fold = self.blocks[max(0, i)]
        return first if fold is not None else first + (offset - lo) // 16

    def item(self, row):
        row = max(0, min(row, self.count - 1))
        i = bisect.bisect_right(self.row_starts, row) - 1
        first, _, lo, fold = self.blocks[i]
        return (lo if fold is not None else lo + (row - first) * 16), fold

    def toggle(self, i):
        if i in self.closed:
            self.closed.remove(i)
        else:
            self.closed.add(i)
        self.rebuild()

    def reveal(self, offset):
        i = self.fold_at(offset)
        if i in self.closed:
            self.toggle(i)

    def step(self, offset, delta):
        row = max(0, min(self.row_at(offset) + delta, self.count - 1))
        lo, fold = self.item(row)
        return lo if fold is not None else min(lo + offset % 16, self.m.size - 1)


def structure_matches(m, query):
    """Search byte-backed structures, not arbitrary claims about absent tables."""
    query = query.strip().lower().replace('symbole', 'symbol')
    aliases = {'symbol table': 'symtab', 'symbol tables': 'symtab',
               'string table': 'strtab', 'string tables': 'strtab',
               'program header': 'phdr', 'program headers': 'phdr',
               'section header': 'shdr', 'section headers': 'shdr',
               'elf header': 'ehdr', 'dynamic table': 'dynamic',
               'relocation table': 'reloc'}
    group = aliases.get(query)
    words = query.split()
    result = []
    seen = set()
    for a in m.anns:
        if a.kind != 'region' or a.group == 'seg' or a.end <= a.start:
            continue
        haystack = (a.name + ' ' + a.val + ' ' + a.desc).lower()
        if (group and a.group == group) or (words and all(w in haystack for w in words)):
            key = (a.start, a.end, a.name)
            if key not in seen:
                result.append(a)
                seen.add(key)
    return sorted(result, key=lambda a: (a.start, a.name))


def search_structure(stdscr, m, query):
    matches = structure_matches(m, query)
    if not matches:
        return None, 'No byte-backed structure matches %r (absent or not identified)' % query
    if len(matches) == 1:
        return matches[0].start, 'Found ' + matches[0].name
    selected = 0
    while True:
        h, w = stdscr.getmaxyx()
        capacity = max(1, h - 3)
        top = max(0, selected - capacity + 1)
        stdscr.erase()
        put(stdscr, 0, 0, (' Search: %s | %d matches ' % (query, len(matches))).ljust(w), curses.A_REVERSE)
        for y, a in enumerate(matches[top:top + capacity], 1):
            i = top + y - 1
            label = ' %s 0x%x-0x%x (%d B) | %s' % ('>' if i == selected else ' ', a.start, a.end - 1, a.end - a.start, a.name)
            put(stdscr, y, 0, label, curses.A_REVERSE if i == selected else 0)
        put(stdscr, h - 1, 0, ' Up/Down: choose | Enter: jump | Esc/q: cancel ')
        stdscr.refresh()
        k = stdscr.getch()
        if k in (27, ord('q')):
            return None, 'Search cancelled'
        if k == curses.KEY_UP:
            selected = max(0, selected - 1)
        elif k == curses.KEY_DOWN:
            selected = min(len(matches) - 1, selected + 1)
        elif k in (10, 13, curses.KEY_ENTER):
            return matches[selected].start, 'Found ' + matches[selected].name


def draw(stdscr, m, cs, cur, top, msg, pairs, path, view):

    stdscr.erase()
    h, w = stdscr.getmaxyx()
    if h < 6 or w < 40:
        put(stdscr, 0, 0, 'terminal too small (need at least 40x6)')
        stdscr.refresh()
        return
    rows = h - 4
    la = ann_at(m, cur)
    trange = None
    if la.target is not None:
        trange = (la.target, la.target + max(1, la.tlen))
    bar = ' %s | %s | %d bytes | cursor 0x%x | warnings: %d | ?: help ' % (
        os.path.basename(path), m.summary, m.size, cur, len(m.warnings))
    if getattr(m, 'real_size', None):
        bar = ' PARTIAL: first %d of %d bytes |' % (m.size, m.real_size) + bar
    if msg:
        bar = ' ' + msg + ' |' + bar
    put(stdscr, 0, 0, bar.ljust(w), curses.A_REVERSE)
    show_ascii = w >= ASCII_X + 16
    notes_x = NOTES_X
    notes_w = w - notes_x - 1
    for r in range(rows):
        if top + r >= view.count:
            break
        lo, folded = view.item(top + r)
        if folded is not None:
            start, end, region = view.folds[folded]
            label = "> zeros 0x%x-0x%x | %d bytes hidden | %s [z/click to expand]" % (start, end - 1, end - start, region.name)
            put(stdscr, 1 + r, 0, label, curses.A_REVERSE if start <= cur < end else curses.A_BOLD)
            continue
        L = build_line(m, lo, cs, notes_w if (show_ascii and notes_w >= 10) else 0)
        y = 1 + r
        put(stdscr, y, 0, L.tag, pairs.get(L.group, 0) | curses.A_BOLD)
        fold_id = view.fold_at(lo)
        if fold_id is not None and lo == view.folds[fold_id][0]:
            put(stdscr, y, 5, 'v', curses.A_BOLD)
        put(stdscr, y, 6, '%08x' % lo, curses.A_DIM)
        for i, (sep, hexs, a, p) in enumerate(L.cells):
            x = HEX_X + BYTE_PITCH * i
            put(stdscr, y, x, sep, curses.A_BOLD)
            put(stdscr, y, x + 1, hexs, cell_attr(a, p, cur, la, trange, pairs))
        if show_ascii:

            put(stdscr, y, ASCII_X, L.ascii)
            if lo <= cur < lo + 16:
                c = cur - lo
                put(stdscr, y, ASCII_X + c, L.ascii[c], curses.A_REVERSE | curses.A_BOLD)
            if L.notes:
                put(stdscr, y, notes_x, L.notes)
    ident = ((la.rec + '.') if la.rec else '') + la.name
    rng = '0x%x-0x%x (%d B)' % (la.start, la.end - 1, la.end - la.start)
    raw = m.data[la.start:min(la.end, la.start + 16)]
    byt = ' '.join('%02x' % b for b in raw)
    if la.end - la.start > 16:
        byt += ' ...'
    endian = ' %s' % ('LE' if m.order == 'little' else 'BE') if la.kind == 'field' else ''
    s1 = ' %s  %s  bytes in file order%s: %s' % (ident, rng, endian, byt)
    s2 = ' value: %s' % la.val
    if la.target is not None:
        s2 += '   => 0x%x (%s, %d B)  [Enter]' % (la.target, la.tlabel, la.tlen)
    s3 = ' ' + la.desc
    if la.region is not la:
        s3 += ' | in: ' + la.region.name
    segs = [nme for (s, e, nme) in m.segs if s <= cur < e]
    if segs:
        s3 += ' | segments: ' + ','.join(segs[:4])
    refs = m.refs_in.get(la.start, [])
    if refs:
        s3 += ' | referenced by: ' + ', '.join(
            ((x.rec + '.') if x.rec else '') + x.name + '@0x%x' % x.start
            for x in refs[:3]) + (' ...' if len(refs) > 3 else '')
    if la.warn or la.region.warn:
        s3 += ' | WARNING: ' + (la.warn or la.region.warn)
    put(stdscr, h - 3, 0, s1.ljust(w), curses.A_REVERSE)
    put(stdscr, h - 2, 0, s2)

    put(stdscr, h - 1, 0, s3)
    stdscr.refresh()


def scroll_view(view, top, cur, rows, delta):
    """Scroll display rows, keeping a valid selection within the visible page."""
    top = max(0, min(top + delta, max(0, view.count - rows)))
    selected = view.row_at(cur)
    nearest = max(top, min(selected, top + rows - 1, view.count - 1))
    if nearest != selected:
        lo, folded = view.item(nearest)
        cur = lo if folded is not None else min(lo + cur % 16, view.m.size - 1)
    return top, cur


def run_curses(m, path, cs, no_color, no_mouse=False):
    def event_loop(stdscr):
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        stdscr.keypad(False)
        pairs = init_pairs(curses.has_colors() and not no_color)
        # Flush ncurses initialization before requesting terminal mouse modes.
        stdscr.refresh()
        mouse_on = set_mouse(True) if not no_mouse else False
        mouse_seen = False
        cur = 0
        top = 0
        hist = []
        msg = ''
        view = FoldView(m)
        while True:
            h, w = stdscr.getmaxyx()
            rows = max(1, h - 4)
            cur = max(0, min(cur, m.size - 1))
            line = view.row_at(cur)
            tl = top
            if line < tl:
                tl = line
            elif line >= tl + rows:
                tl = line - rows + 1
            top = max(0, tl)
            mouse_label = ('mouse: active' if mouse_seen else 'mouse: requested') if mouse_on else 'mouse: off'
            status = mouse_label + ' | / search | z fold | Z all'
            if w < HEX_X + 16 * BYTE_PITCH:
                status = 'Widen terminal to 78+ columns | ' + status
            draw(stdscr, m, cs, cur, top, (msg + ' | ' if msg else '') + status, pairs, path, view)
            k, mouse_event = read_input(stdscr)
            msg = ''
            if k in (ord('q'), ord('Q')):
                break

            elif k == curses.KEY_MOUSE:
                if not mouse_on or mouse_event is None:
                    continue
                mx, my, button, pressed = mouse_event
                mouse_seen = True
                # SGR 64/65 are wheel up/down. Low bits 2/3 are horizontal
                # wheel directions, not vertical scrolling. Modifiers are OK.
                if pressed and button & 64:
                    direction = button & 3
                    if direction in (0, 1) and 0 <= mx < w and 1 <= my <= rows:
                        top, cur = scroll_view(view, top, cur, rows, -3 if direction == 0 else 3)
                    continue
                # Motion (32-bit flag, including no-button 35) or left press.
                if pressed and (button & 32 or button & 3 == 0):
                    if 1 <= my <= rows and top + my - 1 < view.count:
                        lo, folded = view.item(top + my - 1)
                        fold_id = view.fold_at(lo)
                        click = not button & 32 and button & 3 == 0
                        if folded is not None:
                            cur = lo
                            if click:
                                view.toggle(folded)
                        elif click and mx == 5 and fold_id is not None and lo == view.folds[fold_id][0]:
                            cur = lo
                            view.toggle(fold_id)
                        else:
                            target = mouse_offset(m, mx, 1, lo, h, w)
                            if target is not None:
                                cur = target
            elif k == ord('z'):
                i = view.fold_at(cur)
                if i is None:
                    msg = 'No foldable all-zero content range here (minimum 64 B)'
                else:
                    view.toggle(i)
            elif k == ord('Z'):
                view.closed = set() if view.closed else set(range(len(view.folds)))
                view.rebuild()
            elif k == ord('m'):
                mouse_on = set_mouse(not mouse_on)
                mouse_seen = False
            elif k == curses.KEY_UP:
                cur = view.step(cur, -1)
            elif k == curses.KEY_DOWN:
                cur = view.step(cur, 1)
            elif k == curses.KEY_LEFT:
                fold = view.fold_at(cur)
                cur = view.folds[fold][0] - 1 if fold in view.closed else cur - 1
            elif k == curses.KEY_RIGHT:
                fold = view.fold_at(cur)
                cur = view.folds[fold][1] if fold in view.closed else cur + 1
            elif k == curses.KEY_PPAGE:
                cur = view.step(cur, -rows)
            elif k == curses.KEY_NPAGE:
                cur = view.step(cur, rows)
            elif k == curses.KEY_HOME:
                cur = 0
            elif k == curses.KEY_END:
                cur = m.size - 1
            elif k in (10, 13, curses.KEY_ENTER):
                a = ann_at(m, cur)
                if a.target is None:
                    msg = 'this item has no pointer to follow'
                elif 0 <= a.target < m.size:
                    hist.append(cur)
                    cur = a.target
                    view.reveal(cur)
                    top = max(0, view.row_at(cur) - rows // 3)
                else:
                    msg = 'target is outside the file'
            elif k in (curses.KEY_BACKSPACE, 127, 8):
                if hist:
                    cur = hist.pop()
                    view.reveal(cur)
                    top = max(0, view.row_at(cur) - rows // 3)
                else:
                    msg = 'no history'

            elif k == ord('g'):
                if mouse_on:
                    set_mouse(False)
                stdscr.keypad(True)
                try:
                    s = prompt(stdscr, 'go to offset (hex): ')
                finally:
                    stdscr.keypad(False)
                    if mouse_on:
                        mouse_on = set_mouse(True)
                if s:
                    try:
                        t = int(s, 16)
                        if 0 <= t < m.size:
                            hist.append(cur)
                            cur = t
                            view.reveal(cur)
                            top = max(0, view.row_at(cur) - rows // 3)
                        else:
                            msg = 'offset outside the file'
                    except ValueError:
                        msg = 'not a hex number'
            elif k == ord('n'):
                i = bisect.bisect_right(m.starts, cur)
                if i < len(m.starts):
                    cur = m.starts[i]
                    view.reveal(cur)
            elif k == ord('N'):
                i = bisect.bisect_left(m.starts, cur) - 1
                if i >= 0:
                    cur = m.starts[i]
                    view.reveal(cur)
            elif k == ord('/'):
                if mouse_on:
                    set_mouse(False)
                stdscr.keypad(True)
                try:
                    query = prompt(stdscr, 'search structure (e.g. symbol table or .symtab): ')
                    target, msg = search_structure(stdscr, m, query) if query else (None, 'Search cancelled')
                    if target is not None:
                        hist.append(cur)
                        cur = target
                        view.reveal(cur)
                        top = max(0, view.row_at(cur) - rows // 3)
                finally:
                    stdscr.keypad(False)
                    if mouse_on:
                        mouse_on = set_mouse(True)
            elif k in (ord('w'), ord('i'), ord('?'), ord('h')):
                if mouse_on:
                    set_mouse(False)
                stdscr.keypad(True)
                try:
                    show_text(stdscr, info_lines(m) if k in (ord('w'), ord('i')) else HELP_LINES)
                finally:
                    stdscr.keypad(False)
                    if mouse_on:
                        mouse_on = set_mouse(True)

    def inner(stdscr):
        try:
            event_loop(stdscr)
        finally:
            # Also runs for Ctrl-C, exceptions, and normal quit, before endwin.
            set_mouse(False)

    os.environ.setdefault('ESCDELAY', '25')
    curses.wrapper(inner)


# ---------------------------------------------------------------------- main


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='Read-only annotated hex viewer for ELF files.')
    ap.add_argument('file', help='ELF file to inspect')
    ap.add_argument('--dump', action='store_true',
                    help='print the annotated table as plain text and exit')
    ap.add_argument('--range', metavar='START[:END]',
                    help='with --dump: only this range of hex file offsets')
    ap.add_argument('--ascii', action='store_true',
                    help='use plain ASCII markers instead of box-drawing characters')
    ap.add_argument('--no-mouse', action='store_true',
                    help='do not request mouse tracking at startup (m toggles it)')
    ap.add_argument('--no-color', action='store_true', help='interactive mode without colors')
    ap.add_argument('--notes-width', type=int, default=110,
                    help='with --dump: maximum width of the notes column (default 110)')
    args = ap.parse_args(argv)
    if args.range:
        try:
            parse_range(args.range, 0)
        except ValueError:
            ap.error('--range expects hex offsets like 0:100')
    try:
        with open(args.file, 'rb') as f:
            data = f.read(MAX_BYTES + 1)
    except OSError as e:
        sys.stderr.write('cannot read %s: %s\n' % (args.file, e.strerror or e))
        return 2
    cut = len(data) > MAX_BYTES
    if cut:
        data = data[:MAX_BYTES]
        try:
            real = os.path.getsize(args.file)
        except OSError:
            real = None
    m = analyze(data)
    if cut:
        m.real_size = real or (MAX_BYTES + 1)
        m.warn('PARTIAL VIEW: only the first %d MiB of the file are shown and analysed; '
               'the file is larger (%s bytes)' % (MAX_BYTES >> 20, real if real else 'more than the limit'))
    if m.size == 0:

        sys.stderr.write('%s is empty\n' % args.file)
        return 1
    if args.dump or curses is None or not sys.stdout.isatty() or not sys.stdin.isatty():
        if not args.dump:
            sys.stderr.write('not running in a terminal (or curses is missing): '
                             'falling back to --dump\n')
        cs = pick_charset(sys.stdout.encoding, args.ascii)
        try:
            do_dump(m, args, cs)
        except BrokenPipeError:
            pass
        return 0
    locale.setlocale(locale.LC_ALL, '')
    cs = pick_charset(locale.getpreferredencoding(False), args.ascii)
    try:
        run_curses(m, args.file, cs, args.no_color, args.no_mouse)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
