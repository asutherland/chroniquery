#!/usr/bin/env python
import optparse, os.path, struct, sys

from pyflam import pout

class DBHeader(object):
    def __init__(self, f):
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
        elif self.architecture == 1:
            self.architecture_name = 'amd64' 

class DBDirEntry(object):
    def __init__(self, f):
        data = f.read(20)
        
        (self.offset, self.length, self.name_offset) = struct.unpack('QQI',data)
        self.name = None

class DBEffectSetEntry(object):
    pass

class DBCodeInfoEntry(object):
    pass

class DBRegLogEntry(object):
    pass

class DBRegLogCunk(object):
    pass

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
        data = f.read(76)
        
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
         self.offset) = struct.unpack('QQQBBBBBBBBBBBBBBBBIQQQQ', data)
         
        if self.filename_len != 0:
            savepos = f.tell()
            
            f.seek(self.filename_fileloc)
            self.filename = f.read(self.filename_len)
            
            f.seek(savepos, 0)
        else:
            self.filename = None


class ChronReader(object):
    SECTION_TO_RECORD_TYPE = {
        'ADDRESS_MAP_EVENTS': DBAddrMapEntry
    }
    
    def __init__(self, filename):
        self.f = open(filename, 'rb')
        
        self.dir_list = []
        self.dir_map = {}
        
        # Only load the header and directory automatically.  Everything else
        #  gets done on demand, lest we explode. 
        self.readHeader()
        self.readDirectory()
    
    def readHeader(self):
        self.f.seek(0, 0)
        self.header = DBHeader(self.f)
    
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
    
    def readMapContents(self, map_name):
        dir_entry = self.dir_map[map_name]
        rec_class = self.SECTION_TO_RECORD_TYPE[map_name]
        
        self.f.seek(dir_entry.offset, 0)
        end_offset = dir_entry.offset + dir_entry.length
        while self.f.tell() < end_offset:
            rec = rec_class(self.f)
            yield rec
    
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
            pout('{n}%s {.30}{v}%x %x', dir_entry.name,
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
        
        pout('{n}%8d %10x %10x %s {.40}{fn}%s',
             addr_map.tstamp, addr_map.address, addr_map.length,
             flags,
             addr_map.filename)
    
    def showAddressMap(self):
        for addr_map in self.cr.readMapContents('ADDRESS_MAP_EVENTS'):
            self.showAddressMapEntry(addr_map)
    
    def grok(self, filename):
        self.cr = cr = ChronReader(filename)
        self.showHeader()
        pout.h()
        self.showDirectory()
        pout.h()
        self.showAddressMap()
        
    def main(self):
        self.grok(sys.argv[1])

if __name__ == '__main__':
    rc = ReadChron()
    rc.main()