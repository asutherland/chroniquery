# chroniquery, a chronicle-recorder python interface/abstraction library
#    Copyright (C) 2007 Andrew Sutherland (sombrero@alum.mit.edu)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


from chroniquery import ChroniQuery

import socket, linecache, os.path

class Chronifer(object):
    '''
    A highly fluxy higher level wrapper over ChroniQuery.  For now, it's 
    basically my __main__ test code re-purposed towards reuse.
    '''

    def __init__(self, exe_file, db_file=None):
	exe_file = os.path.abspath(exe_file)

        if db_file is None:
            db_file = exe_file + '.db'
        else:
            db_file = os.path.abspath(db_file)
        
        self.exe_file = exe_file
        self.db_file = db_file
        
        self.c = ChroniQuery(self.db_file)
        
        self._startupPrep()
        
        self._instrCache = {}
    
    def _startupPrep(self):
        c = self.c
        
        self._info = c.sss('info')
        self._startTStamp = 0
        self._endTStamp   = self._info['endTStamp']
        
        trash = c.getAsync()

        comp_units = self.c.ssa('lookupCompilationUnits',
                                do_name=self.exe_file,
                                cu_name='')
    
        ranges = []
        for comp_unit in comp_units:
            cuBegin = comp_unit.get('compilationUnitBegin')
            cuEnd   = comp_unit.get('compilationUnitEnd')
            if cuBegin and cuEnd:
                ranges.append({'start': cuBegin, 'length': cuEnd-cuBegin})

        self._ranges = ranges
    
    def getLocals(self, tstamp):
        c = self.c
        
        locals = {}
        for lokal in c.ssm('getLocals', TStamp=tstamp):
            if 'name' in lokal:
                lvalues = c.ssa('getLocation',
                                TStamp=tstamp,
                                valKey=lokal['valKey'],
                                typeKey=lokal['typeKey'],
                                )
                for lvalue in lvalues:
                    if 'valueBitStart' in lvalue:
                        if lvalue.get('register'):
                            kwds = {}
                            kwds[str(lvalue['register'])] = 32 # hack
                            value = c.sss('readReg',
                                          TStamp=tstamp,
                                          **kwds)
                        elif lvalue.get('address'):
                            dvalue = c.sss('readMem',
                                          TStamp=tstamp,
                                          ranges=[{'start':
                                                     lvalue['address'],
                                                   'length':
                                                     4 # hack
                                                     }])
                            val = socket.htonl(int(dvalue['bytes'], 16))

                        
                        locals[lokal['name']] = val
        
        return locals

    def getSourceLines(self, source_line):
        '''
        Return a list of a 4-tuples, where the tuple's contents are
        (the line number,
         text preceding the executed part of the line,
         the actual text for the part of the line being executed,
         text following the executed part of the line)
        '''
        filename, sl, el, sc, ec = source_line

        lines = []
        if ec > 1 or (sl == el):
            adjust = 1
        else:
            adjust = 0        
        for lineno in range(sl, el + adjust):
            line = linecache.getline(filename, lineno).rstrip()
            if lineno == sl:
                lines.append((lineno, line[:sc], line[sc:], ''))
            elif lineno == el:
                lines.append((lineno, '', line[:ec], line[ec:]))
            else:
                lines.append((lineno, '', line, ''))
        return lines
    
    def scanBySourceLine(self):
        '''
        Iterate over the program, yielding on each new source line reached.
        Return a tuple of: (start time stamp, end time stamp, source line info)
        
        Start time stamp is the first time stamp we were in the source line,
        end time stamp is the last line we were in the source line.  These
        can be used to retrieve locals via getLocals.
        
        Source line info is a tuple that can be used to retrieve the
        source lines via getSourceLines.
        '''
        c = self.c
        
        lastline = ('', 0, 0, 0, 0)
        
        tstamp = startStamp = lastStamp = None
        for instr in c.ssm('scan',
                           map='INSTR_EXEC',
                           beginTStamp=self._startTStamp,
                           endTStamp=self._endTStamp,
                           ranges=self._ranges,
                           ):

            if instr.get('type') == 'mmap':
                # flush instruction cache on mmaps
                self._instrCache.clear()
                
            # skip 'mmap' type, that's when the program gets mapped in...
            if 'TStamp' in instr and instr.get('type') == 'normal':
                lastStamp = tstamp
                tstamp  = instr['TStamp']
                address = instr['start']
                if address in self._instrCache:
                    curline = self._instrCache[address]
                    if curline is None:
                        continue
                    file, sl, el, sc, ec = curline
                else:
                    sinfo = c.sss('findSourceInfo',
                                  TStamp=tstamp,
                                  address=address)
                    
                    if not 'filename' in sinfo:
                        self._instrCache[address] = None
                        continue
                    else:
                        filename = sinfo['filename']
                        sl = sinfo['start_line']
                        el = sinfo['end_line']
                        sc = sinfo['start_column'] - 1
                        ec = sinfo['end_column']
                        
                        curline = (filename, sl, el, sc, ec)
                        self._instrCache[address] = curline
    

                if curline == lastline:
                    continue
                
                if lastStamp != None:
                    yield (startStamp, lastStamp, lastline)
            
                startStamp = tstamp
                
                lastline = curline
        
    def stop(self):
        self.c.stop()

