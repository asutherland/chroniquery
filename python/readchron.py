#!/usr/bin/env python
import optparse, os.path, struct, sys, zlib
from ctypes import *

from pyflam import pout

# this and the functions that rely on it should instead have some form of
#  relationship to DBHeader or some other context object to tell them what
#  they are dealing with
PAD_TO = 4
# okay, this is just bad now; this forces us to be platform-specific
#  (namely, OUR platform that this is running on).  We should presumably
#  be generating parameterized structures on an as-needed basis.
c_uintptr = c_ulong

def pad(v, pad_to=None):
    pad_to = pad_to or PAD_TO
    if v%pad_to != 0:
        return v + (-v % pad_to)
    else:
        return v

def pad_read(f, l, max_size=None):
    if max_size > PAD_TO:
        max_size = None
    read_size = pad(l, max_size)
    return f.read(read_size)[:l]

def varistruct(f, s):
    pass

class DBHeader(object):
    def __init__(self, f):
        global PAD_TO, c_uintptr
        
        data = f.read(56)
        
        (self.magic,
         self.architecture,
         self.is_little_endian,
         self.version,
         self.dynamic_offsets_in_reg_log,
         self.have_reg_reads,
         self.have_mem_reads,
         self.effect_map_page_size_bits,
         self.reserved,
         self.directory_offset,
         self.name_offset,
         self.directory_count,
         self.name_size,
         self.end_tstamp) = struct.unpack('12sBBHBBBBIQQIIQ', data)
         
        if self.architecture == 0:
            self.architecture_name = 'x86'
            PAD_TO = 4
        elif self.architecture == 1:
            self.architecture_name = 'amd64'
            PAD_TO = 8 

class DBDirEntry(object):
    def __init__(self, f):
        data = pad_read(f, 20)
        
        (self.offset, self.length, self.name_offset) = struct.unpack('QQI',data)
        self.name = None

class DBEffectSetEntry(object):
    def __init__(self, f):
        data = pad_read(f, 12)
        
        (self.fileloc, self.compressed_size) = struct.unpack('QI', data)

class DBCodeInfoEntry(object):
    def __init__(self, f):
        data = pad_read(f, 12, 4)
        
        (self.effect_set, self.offset_in_effect_set, self.num_bunched_effects,
         self.num_reg_effects) = struct.unpack('IIHH', data)

class BunchedEffectAtom(Structure):
    _fields_ = [('instruction_index', c_uint8, 4),
                ('length_increment', c_uint8, 4),
                ]

class BunchedEffectAtoms(Structure):
    _fields_ = [('atoms', BunchedEffectAtom * 8),
                ]

MAP_TYPES = {0:  'INSTR    ', 1: 'MEM_READ ', 2:'MEM_WRITE', 3:'ENTER_SP ',
             255:'CUSTOM   '}
class BunchedEffect(Structure):
    _fields_ = [('static_offset', c_uintptr),
                ('map', c_uint8, 5),
                ('has_data', c_uint8, 1),
                ('has_dynamic_offset', c_uint8, 1),
                ('uses_dynamic_offset', c_uint8, 1),
                ('first_instruction_index', c_uint8),
                ('last_instruction_index', c_uint8),
                ('length', c_uint8),
                ('atoms', BunchedEffectAtoms),
                ]

REG_MAP_X86 = {0: 'eax', 1: 'ecx', 2: 'edx', 3: 'ebx',
               4: 'esp', 5: 'ebp', 6: 'esi', 7: 'edi',
               32: 'fp0', 33: 'fp1', 34: 'fp2', 35: 'fp3',
               36: 'fp4', 37: 'fp5', 38: 'fp6', 36: 'fp7',
               40: 'fptop',
               16: 'xmm0', 17: 'xmm1', 18: 'xmm2', 19: 'xmm3',
               20: 'xmm4', 21: 'xmm5', 22: 'xmm6', 23: 'xmm7',
               41: 'pc',
               }
REG_MAP_AMD64 = dict(REG_MAP_X86)
REG_MAP_AMD64.update({
               0: 'rax', 1: 'rcx', 2: 'rdx', 3: 'rbx',
               4: 'rsp', 5: 'rbp', 6: 'rsi', 7: 'rdi',
               8: 'r8',  9: 'r9', 10: 'r10',11: 'r11',
               12:'r12',13:'r13', 14: 'r14',15: 'r15',
               24: 'xmm8',  25: 'xmm9',  26: 'xmm10', 27: 'xmm11',
               28: 'xmm12', 29: 'xmm13', 30: 'xmm14', 31: 'xmm15', 
               })
EFFECT_MAP = {1: 'READ    ', 2: 'WRITE   ', 3: 'DYNREAD ', 4: 'DYNWRITE',
              5: 'SETCONST', 6: 'ADDCONST', 7: 'ADDREG  '}
class RegEffect(Structure):
    _fields_ = [('instruction_index', c_ubyte),
                ('type', c_ubyte, 5),
                ('bytes_pow2', c_ubyte, 3),
                ('reg', c_ubyte),
                ('imm1', c_ubyte),
                ('imm0', c_ubyte),
                ]

class DBRegLogEntry(object):
    def __init__(self, f):
        data = pad_read(f, 40)
        
        (self.first_tstamp, self.registers_maybe_modified,
         self.registers_maybe_modified, self.reg_log_chuck_fileloc,
         self.SP_max, self.reg_log_chunk_compressed_size, self.pthread_cookie,
         ) = struct.unpack('QQQQII', data)

class DBRegLogChunk(object):
    # this varies with the underlying architecture!
    def __init__(self, f, architecture_name):
        if architecture_name == 'x86':
            data = pad_read(f, 58*4)
            
            chewed = struct.unpack('8I8d16QBxxxI', data)
            self.regs_GP = chewed[0:8]
            self.regs_FP = chewed[8:16]
            self.regs_SSE = [(chewed[16+2*i],
                              chewed[16+2*i+1]) for i in range(8)]
            self.FP_top = chewed[32]
            self.num_codes_executed = chewed[33]
            
        elif architecture_name == 'amd64':
            data = pad_read(f, 57*8)
            
            chewed = struct.unpack('16Q8d32QBxxxI', data)
            
            self.regs_GP = chewed[0:16]
            self.regs_FP = chewed[16:24]
            self.regs_SSE = [(chewed[24+2*i],
                              chewed[24+2*i+1]) for i in range(16)]
            self.FP_top = chewed[56]
            self.num_codes_executed = chewed[57]
        else:
            raise Exception("Unknown Architecture: %s" % architecture_name)

class DBEffectMap(object):
    pass

class DBEffectPageEntry(object):
    pass

class DBEffectHistoryEntry(object):
    pass

class DBEffectItem(object):
    pass

class DBAddrMapEntry(object):
    def __init__(self, f):
        if PAD_TO == 4:
            data = pad_read(f, 76)
        else:
            # filename_fileloc gets an extra 4 bytes padded before it
            data = pad_read(f, 80)
        
        (self.tstamp,
         self.address,
         self.length,
         self.is_mapped,
         self.is_read,
         self.is_write,
         self.is_execute,
         self.is_file,
         self.suppress_debug_info,
         self.contents_will_follow,
         self.contents_set_zero,
         self.contents_from_file,
         self.contents_unchanged,
         self.reserved_zero_0, self.reserved_zero_1, self.reserved_zero_2,
         unplanned_padding0, unplanned_padding1, unplanned_padding2,
         self.filename_len,
         self.filename_fileloc,
         self.device,
         self.inode,
         self.offset) = struct.unpack('QQQ16BIQQQQ', data)
         
        if self.filename_len != 0:
            savepos = f.tell()
            
            f.seek(self.filename_fileloc)
            self.filename = f.read(self.filename_len)
            
            f.seek(savepos, 0)
        else:
            self.filename = None


class ChronReader(object):
    SECTION_TO_RECORD_TYPE = {
        'ADDRESS_MAP_EVENTS': (DBAddrMapEntry, False),
        'CODE_INFO': (DBCodeInfoEntry, False),
        'EFFECT_SET': (DBEffectSetEntry, True),
    }
    # we should have some form of size heuristic too...
    MAX_COMPRESSED_BLOCKS = 8
    
    def __init__(self, filename):
        self.f = open(filename, 'rb')
        
        self.dir_list = []
        self.dir_map = {}
        
        self.record_cache_by_section = {}
        
        self.compressed_block_cache = {}
        self.compressed_block_lru = []
        
        # Only load the header and directory automatically.  Everything else
        #  gets done on demand, lest we explode. 
        self.readHeader()
        self.readDirectory()
    
    def readHeader(self):
        self.f.seek(0, 0)
        self.header = DBHeader(self.f)
        
        if self.header.architecture_name == 'x86':
            self.REG_MAP = REG_MAP_X86
        else:
            self.REG_MAP = REG_MAP_AMD64
    
    def readDirectory(self):
        self.f.seek(self.header.directory_offset, 0)
        
        for i_dir_entry in range(self.header.directory_count):
            self.dir_list.append(DBDirEntry(self.f))
        
        self.f.seek(self.header.name_offset, 0)
        names = self.f.read(self.header.name_size) 
        
        for dir_entry in self.dir_list:
             name_end = names.find('\0', dir_entry.name_offset)
             dir_entry.name = names[dir_entry.name_offset:name_end]
             self.dir_map[dir_entry.name] = dir_entry
    
    def readMapContents(self, map_name, as_list=False):
        dir_entry = self.dir_map[map_name]
        rec_class, cache_it = self.SECTION_TO_RECORD_TYPE[map_name]
        
        if cache_it:
            if map_name in self.record_cache_by_section:
                return self.record_cache_by_section[map_name]
            else:
                cache = []
                self.record_cache_by_section[map_name] = cache
        else:
            cache = None
        
        if as_list:
            saved_file_pos = self.f.tell()
            rlist = list(self._readMapHelper(dir_entry, rec_class, cache))
            self.f.seek(saved_file_pos, 0)
            return rlist
        else:
            return self._readMapHelper(dir_entry, rec_class, cache)
    
    def _readMapHelper(self, dir_entry, rec_class, cache=None):
        self.f.seek(dir_entry.offset, 0)
        end_offset = dir_entry.offset + dir_entry.length
        while self.f.tell() < end_offset:
            rec = rec_class(self.f)
            if cache is not None:
                cache.append(rec)
            yield rec
    
    def readCompressedBlock(self, offset, compressed_size):
        '''
        Read a compressed block and cache it, or just return it from cache.
        Currently there is no way to deal with compressed blocks that are
        simply too giant, but that should be supported when needed.  (Maybe
        chronicle makes sure to keep things sane?  I forget.)
        '''
        block_info = (offset, compressed_size)
        if block_info in self.compressed_block_cache:
            self.compressed_block_lru.remove(block_info)
            self.compressed_block_lru.append(block_info)
            return self.compressed_block_cache[block_info]
        
        # flush something from the cache first if needed, noting that this
        #  may not actually work depending upon how sub-string sharing works
        #  if someone sliced the block at some point and retains the slice...
        if len(self.compressed_block_lru) >= self.MAX_COMPRESSED_BLOCKS:
            kill_block_info = self.compressed_block_lru[0]
            del self.compressed_block_lru[0]
            del self.compressed_block_cache[kill_block_info]
        
        # okay we should really chunk things now that we are going ctypes
        saved_file_pos = self.f.tell()
        
        self.f.seek(offset, 0)
        compressed_data = self.f.read(compressed_size)
        self.f.seek(saved_file_pos, 0)
        
        data = zlib.decompress(compressed_data, -15)
        
        block = create_string_buffer(data)
        
        self.compressed_block_cache[block_info] = block
        self.compressed_block_lru.append(block_info)

        return block

    def getCodeInfoDetails(self, code_info):
        effect_sets = self.readMapContents('EFFECT_SET', as_list=True)

        effect_set = effect_sets[code_info.effect_set]
        block = self.readCompressedBlock(effect_set.fileloc,
                                         effect_set.compressed_size)
        if code_info.num_bunched_effects:
            bunched_arr_type = BunchedEffect * code_info.num_bunched_effects
            bunched = bunched_arr_type.from_address(addressof(block) +
                                                    code_info.offset_in_effect_set)
        else:
            bunched = ()
        if code_info.num_reg_effects:
            regs_arr_type = RegEffect * code_info.num_reg_effects
            regs = regs_arr_type.from_address(addressof(block) +
                                              code_info.offset_in_effect_set +
                                              code_info.num_bunched_effects * sizeof(BunchedEffect))
        else:
            regs = ()
        return bunched, regs
        
    
class ReadChron(object):
    def __init__(self):
        self.cr = None

    def showHeader(self, header=None):
        header = header or self.cr.header
        magic = header.magic.replace('\0', '.')
        pout('{k}Magic{n}: {v}%s {.24}{k}Version{n}: {v}%d', magic,
             header.version)
        pout('{k}Arch{n}: {v}%d {s}({n}%s{s}) {.24}{k}Little Endian{n}: {v}%d',
             header.architecture, header.architecture_name,
             header.is_little_endian)
        
    def showDirectory(self):
        for dir_entry in self.cr.dir_list:
            pout('{n}%s {.30}{v}%14x %14x', dir_entry.name,
                 dir_entry.offset, dir_entry.length)
    
    ADDR_MAP_FLAGS = (('is_mapped', 'm'), ('is_read', 'r'),
                      ('is_write', 'w'), ('is_execute', 'x'),
                      ('is_file', 'f'), ('contents_set_zero', 'z'))
    def showAddressMapEntry(self, addr_map):
        flags = ''
        for attr_name, flag_label in self.ADDR_MAP_FLAGS:
            val = getattr(addr_map, attr_name)
            if val:
                flags += flag_label
            else:
                flags += '-'
        
        pout('{n}%8d %16x %10x %s {.40}{fn}%s',
             addr_map.tstamp, addr_map.address, addr_map.length,
             flags,
             addr_map.filename)
    
    def showAddressMap(self):
        for addr_map in self.cr.readMapContents('ADDRESS_MAP_EVENTS'):
            self.showAddressMapEntry(addr_map)

    def showCodeInfoEntry(self, code_info):
        pout('{n}%10x %10x %8x %8x', code_info.effect_set,
             code_info.offset_in_effect_set, code_info.num_bunched_effects,
             code_info.num_reg_effects)

    def showBunchedEffect(self, bunched):
        atom_str_pieces = []
        for atom in bunched.atoms.atoms:
            if atom.length_increment:
                 atom_str_pieces.append('%d:%d' % (atom.instruction_index,
                                                   atom.length_increment))
        atoms =' '.join(atom_str_pieces)
        pout('{k}%18x %0s %d %d %d %04x %04x %04x %s',
             bunched.static_offset, MAP_TYPES.get(bunched.map, '?????????'),
             bunched.has_data, bunched.has_dynamic_offset,
             bunched.uses_dynamic_offset,
             bunched.first_instruction_index, bunched.last_instruction_index,
             bunched.length, atoms)
    
    def showRegEffect(self, reg):
        immed = reg.imm1 << 8 | reg.imm0
        pout('        {v}%04x %08s %03d %04s %06x',
             reg.instruction_index,
             EFFECT_MAP[reg.type],
             2 ** reg.bytes_pow2,
             self.cr.REG_MAP[reg.reg], immed)

    def showCodeInfo(self):
        pout('{k}Effect Set     Offset  Bunched      Reg')
        for code_info_entry in self.cr.readMapContents('CODE_INFO'):
            self.showCodeInfoEntry(code_info_entry)
            
            if self.options.show_code_info_details:
                bunched, regs = self.cr.getCodeInfoDetails(code_info_entry)
                
                for bunched_effect in bunched:
                    self.showBunchedEffect(bunched_effect)
                for reg_effect in regs:
                    self.showRegEffect(reg_effect)
    
    def showEffectSetEntry(self, effect_set):
        pout('{n}%18x %16x', effect_set.fileloc, effect_set.compressed_size)
    
    def showEffectSet(self):
        pout('{k}     File Location  Compressed Size')
        for effect_set_entry in self.cr.readMapContents('EFFECT_SET'):
            self.showEffectSetEntry(effect_set_entry)
    
    def grok(self, filename):
        self.cr = cr = ChronReader(filename)
        self.showHeader()
        pout.h()
        self.showDirectory()
        if self.options.show_all or self.options.show_address_map:
            pout.h()
            self.showAddressMap()
        if self.options.show_all or self.options.show_code_info:
            pout.h()
            self.showCodeInfo()
        if self.options.show_all or self.options.show_effect_set:
            pout.h()
            self.showEffectSet()
    
    def _make_optparser(self):
        oparser = optparse.OptionParser()
        
        oparser.add_option('-a',
                           action='store_true',
                           dest='show_all', default=False,
                           help='Show everything')
        
        oparser.add_option('-A',
                           action='store_true',
                           dest='show_address_map', default=False,
                           help='Show Address Map')
        oparser.add_option('-C',
                           action='store_true',
                           dest='show_code_info', default=False,
                           help='Show Code Info')
        oparser.add_option('-D',
                           action='store_true',
                           dest='show_code_info_details', default=False,
                           help='Show Code Info Details')
        oparser.add_option('-E',
                           action='store_true',
                           dest='show_effect_set', default=False,
                           help='Show Effect Set')
        
        
        return oparser
    
    def main(self):
        oparser = self._make_optparser()
        self.options, self.args = oparser.parse_args()
        self.grok(*self.args)

if __name__ == '__main__':
    rc = ReadChron()
    rc.main()