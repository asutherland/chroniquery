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

import socket, linecache, os.path, math, struct

class FuncInfo(object):
    def __init__(self, cf, name, entryPoint, typeKey,
                 beginTStamp, endTStamp,
                 ranges,
                 prologueEnd=None):
        self.cf = cf
        self.name = name
        self.entryPoint = entryPoint
        self.typeKey = typeKey
        self.beginTStamp = beginTStamp
        self.endTStamp = endTStamp
        self.ranges = ranges
        self.prologueEnd = prologueEnd

class Chronifer(object):
    '''
    A highly fluxy higher level wrapper over ChroniQuery.  For now, it's 
    basically my __main__ test code re-purposed towards reuse.
    '''

    def __init__(self, exe_file, db_file=None, querylog=False, extremeDebug=False):
        exe_file = os.path.abspath(exe_file)

        if db_file is None:
            db_file = exe_file + '.db'
        else:
            db_file = os.path.abspath(db_file)
        
        self.exe_file = exe_file
        self.db_file = db_file
        
        self.c = ChroniQuery(self.db_file,
                             querylog=querylog,
                             extremeDebug=extremeDebug)
        
        self._startupPrep()
        
        self._instrCache = {}
    
    def _startupPrep(self):
        c = self.c
        
        self._info = c.sss('info')
        self._beginTStamp = 0
        self._endTStamp   = self._info['endTStamp']
        self._arch   = self._info['arch']
        self._endian = self._info['endian']
        
        self._configureArch()
        
        trash = c.getAsync()
    
    def _configureArch(self):
        if self._arch == 'x86':
            self._sp_reg = 'esp'
            self._ptr_size = 4
            self._reg_bits = 32
            self._max_long = (2 << 32) - 1
        elif self._arch == 'amd64':
            self._sp_reg = 'rsp'
            self._ptr_size = 8
            self._reg_bits = 64
            self._max_long = (2 << 64) - 1
        
        self._pc_reg = 'pc'
        self._thread_reg = 'thread'
    
    def _decodePlatInt(self, sval):
        '''
        Turn a platform-specific int into a python integer, handling endian
        conversion.
        '''
        #return socket.htonl(int(sval, 16))
        return struct.unpack('>I', struct.pack('<I', int(sval, 16)))[0]
    
    def _decodeBigInt(self, sval):
        '''
        Turn a big-endian hex integer value into a nice python value.
        This doesn't require generalization, but code is prettier this way and
        less likely to experience typo-death.
        '''
        return int(sval, 16)
    
    def _fabFunction(self, finfo):
        if not 'entryPoint' in finfo:
            return None
        
        func = FuncInfo(self,
                        finfo['name'],
                        finfo['entryPoint'],
                        finfo.get('typeKey'),
                        finfo['beginTStamp'],
                        finfo['endTStamp'],
                        finfo.get('ranges'),
                        finfo.get('prologueEnd'))
        return func
    
    def lookupGlobalFunction(self, func_name):
        finfo = self.c.sss('lookupGlobalFunctions',
                           name=func_name)
        return self._fabFunction(finfo)
    
    def getRangesUsingExecutableCompilationUnits(self):
        comp_units = self.c.ssa('lookupCompilationUnits',
                                debugObjectName=self.exe_file,
                                compilationUnitName='')
    
        ranges = []
        for comp_unit in comp_units:
            cuBegin = comp_unit.get('compilationUnitBegin')
            cuEnd   = comp_unit.get('compilationUnitEnd')
            if cuBegin and cuEnd:
                ranges.append({'start': cuBegin, 'length': cuEnd-cuBegin})

        return ranges
    
    def getRegisters(self, tstamp, *registers):
        kwds = {}
        for register in registers:
            kwds[str(register)] = self._reg_bits
        values = {}
        for value in self.c.ssm('readReg',
                                TStamp=tstamp,
                                **kwds):
            values.update(value)

        return [self._decodeBigInt(values[register]) for register in registers]
        
    def getRegister(self, tstamp, register):
        return self.getRegisters(tstamp, register)[0]
    getReg = getRegister # alias

    def getSP(self, tstamp):
        return self.getRegisters(tstamp, self._sp_reg)[0]
    def getPC(self, tstamp):
        return self.getRegisters(tstamp, self._pc_reg)[0]

    def findStartOfCall(self, tstamp):
        '''
        Find the start of the function call that is being executed at timestamp
        tstamp.
        
        We get the party started by finding the current stack pointer (last /
        lowest occupied location).  We then find the start of the stack.
        Knowing this, we know that any stack location greater than our current
        location (we are x86/amd64, so stack grows towards 0) in a timestamp
        before our current timestamp could potentially be our entry.  We want the
        first one of these whose corresponding return timestamp is after our
        timestamp of interest.  (I don't currently understand how such a case would
        come to be, but the invariant certainly seems reasonable.)
        '''
        
        sp, thread = self.getRegisters(tstamp, self._sp_reg,
                                       self._thread_reg)
        stackEnd = self.findMemoryEnd(tstamp, sp)
        
        return self._findStartOfCallWithRegs(tstamp,
                                             sp, stackEnd, thread)
    
    def _findStartOfCallWithRegs(self, tstamp,
                                 stackBegin, stackEnd, thread):
        '''
        Helper to find the start of the function call at the given timestamp.
        You probably want to use findStartOfCall.
        
        Find the tstamp of the call/tail-call jump that entered 
        '''
        cinfo = self.c.sss('scan', map='ENTER_SP', termination='findLast',
                           beginTStamp=0,
                           endTStamp=tstamp,
                           ranges=[{'start': stackBegin,
                                    'length': stackEnd - stackBegin}])

        if cinfo.get('type') == 'normal':
            candidateEnterTStamp = cinfo['TStamp']
            candidateEnterSP = cinfo['start']
            candidatePreCallSP = candidateEnterSP + self._ptr_size 
            candidateEndTStamp = self._findEndOfCallWithRegs(candidateEnterTStamp,
                                                             candidatePreCallSP,
                                                             thread)
            if candidateEndTStamp > tstamp:
                return (candidateEnterTStamp,
                        candidateEndTStamp,
                        candidatePreCallSP, stackEnd,
                        thread)
            else:
                return self._findStartOfCallWithRegs(candidateEnterTStamp,
                                                     candidatePreCallSP,
                                                     stackEnd, thread)
                
        return None
    
    def scanCallsBetweenTimes(self, beginTStamp, endTStamp):
        sp, thread = self.getRegisters(beginTStamp, self._sp_reg,
                                       self._thread_reg)
        stackLimit = self.findMemoryBegin(beginTStamp, sp)
        stackEnd = self.findMemoryEnd(beginTStamp, sp)
        
        #print 'scanCalls: sp', hex(sp), 'stack limit', hex(stackLimit), 'stack end', hex(stackEnd)
        
        while True:
            cinfo = self.c.sss('scan', map='ENTER_SP', termination='findFirst',
                               beginTStamp=beginTStamp,
                               endTStamp=endTStamp,
                               ranges=[{'start': stackLimit,
                                        'length': sp - stackLimit - self._ptr_size}])
            
            if cinfo.get('type') == 'normal':
                subEnterTStamp = cinfo['TStamp']
                subEnterSP = cinfo['start']
                subPreCallSP = subEnterSP + self._ptr_size
                subEndTStamp = self._findEndOfCallWithRegs(subEnterTStamp + 1,
                                                           subEnterSP,
                                                           thread)
                
                pc = self.getPC(subEnterTStamp+1)
                func = self.findRunningFunction(subEnterTStamp+1, pc)
                
                if func and pc == func.entryPoint:
                    yield (subEnterTStamp + 1,
                           subEndTStamp,
                           subPreCallSP,
                           stackEnd, thread)

                    # the next possible call has to be after this one returned
                    # (this rules out sub-call following, we leave that to our caller!)
                    beginTStamp = subEndTStamp + 1

                else:
                    #print 'not entry point, skipping'
                    beginTStamp = subEndTStamp + 1
                
            else:
                break
                
    def findEndOfCall(self, tstamp):
        '''
        Given the tstamp of the first instruction of the given function, find the
        tstamp of the last instruction of the function.
        '''
        sp, thread = self.getRegisters(tstamp, self._sp_reg,
                                       self._thread_reg)
        return self._findEndOfCallWithRegs(tstamp, sp, thread)
    
    def _findEndOfCallWithRegs(self, tstamp, sp, thread):
        '''
        Given the tstamp of the first instruction of the given function, find the
        tstamp of the last instruction of the function.  We do this by finding the
        first time the stack pointer goes above the stack pointer's value upon entry
        to the function.
        '''
        cinfo = self.c.sss('findSPGreaterThan',
                           beginTStamp=tstamp,
                           endTStamp=self._endTStamp,
                           threshold=sp,
                           thread=thread)
        if cinfo.get('TStamp') is not None:
            # okay, the timestamp will be of our popping our stack frame off to
            #  the previous guy's stack frame.  Fantastic, but that's still part of
            #  our function.  The next 
            return cinfo['TStamp'] + 1
        else:
            return None
    
    def findRunningFunction(self, tstamp, pc=None):
        '''
        Find the function executing at time tstamp.
        '''
        if pc is None:
            pc, = self.getRegisters(tstamp, self._pc_reg)
        finfo = self.c.sss('findContainingFunction', TStamp=tstamp,
                           address=pc)
        return self._fabFunction(finfo)
    
    def findMemoryBegin(self, tstamp, addr, bump=0x10000):
        '''
        '''
        # chronomancer bumps memory by 0x10000, so we'll use that too...
        beginAddr = max(0, addr - bump)
        
        mappedBegin = addr
        for minfo in self.c.ssm('scan', map='MEM_MAP',
                                beginTStamp=0, endTStamp=tstamp,
                                ranges=[{'start': beginAddr,
                                         'length': addr - beginAddr}],
                                termination='findLastCover'):
            if minfo.get('mapped') and (minfo['start'] +
                                        minfo['length']) >= mappedBegin:
                mappedBegin = min(mappedBegin, minfo['start'])
        
        if mappedBegin <= beginAddr:
            if bump * 2 > 0 and bump * 2 < self._max_long:
                bump *= 2
            return self.findMemoryBegin(tstamp, mappedBegin, bump)
        
        return mappedBegin
    
    def findMemoryEnd(self, tstamp, addr, bump=0x10000):
        '''
        Determine the last byte of memory which is part of the active memory map
        containing addr at time tstamp.  Bump is a heuristic value that acts as
        a reasonable starting value for an exponentially increasing search space.
        If the bump is insufficient to find the end, we self-recurse with a
        doubled bump size starting from the furthest end value we found.
        (This is presumably to deal with wacky cases where additional allocations
        that are technically part of our continguous memory space but who start
        after our search range have get mapped in.  Dynamic code loading through
        page faults, or perhaps stack size increases?)
        '''
        # chronomancer bumps memory by 0x10000, so we'll use that too...
        endAddr = addr + bump
        if endAddr > self._max_long:
            endAddr = self._max_long
        
        mappedEnd = addr + 1
        for minfo in self.c.ssm('scan', map='MEM_MAP',
                                beginTStamp=0, endTStamp=tstamp,
                                ranges=[{'start': addr,
                                         'length': endAddr - addr}],
                                termination='findLastCover'):
            if minfo.get('mapped') and minfo['start'] <= mappedEnd:
                curMapEnd = minfo['start'] + minfo['length']
                mappedEnd = max(curMapEnd, mappedEnd)
        
        if mappedEnd >= endAddr:
            if bump * 2 > 0 and bump * 2 < self._max_long:
                bump *= 2
            return self.findMemoryEnd(tstamp, mappedEnd-1, bump)
        
        return mappedEnd
    
    def findContainingFunction(self, tstamp, addr):
        finfo = self.c.sss('findContainingFunction',
                           address=addr,
                           TStamp=tstamp)
        return self._fabFunction(finfo)
    
    def readMem(self, tstamp, address, length):
        #print 'REQ LENGTH', length
        dstr = '0' * length
        for dvalue in self.c.ssa('readMem',
                            TStamp=tstamp,
                            ranges=[{'start': address,
                                     'length': length
                                    }]):
            #print ':::', dvalue
            if 'bytes' in dvalue:
                offset = dvalue['start'] - address
                length = dvalue['length']
                #print 'offset', offset, 'length', length
                dstr = dstr[:offset] + dvalue['bytes']  + dstr[offset+length:]
        rstr = ''
        for idx in range(0, len(dstr), 2):
            rstr += chr(int(dstr[idx:idx+2], 16)&0xff)
        return rstr

    def readCString(self, tstamp, address, maxlength=256, probesize=1):
        #print 'READING FROM', hex(address)
        if maxlength and maxlength < probesize:
            probesize = maxlength
        
        rstr = ''
        
        while True:
            dstr = self.readMem(tstamp, address, probesize)
            idx_null = dstr.find('\0')
            if idx_null >= 0:
                rstr += dstr[:idx_null]
                return rstr
            elif maxlength and maxlength <= probesize:
                rstr += dstr[:maxlength]
                return rstr
            else:
                address += probesize
                rstr += dstr
                maxlength -= probesize

    def readInt(self, tstamp, address):
        dvalue = self.c.sss('readMem',
                            TStamp=tstamp,
                            ranges=[{'start': address,
                                     'length': self._ptr_size
                                    }])
        return self._decodePlatInt(dvalue['bytes'])

    
    def getValue(self, tstamp, valKey, typeKey):
        #print '---'

        # although the whole routine still needs a lot more work, this part is horrid.
        for tinfo in self.c.ssa('lookupType', typeKey=typeKey):
            kind = tinfo.get('kind')
            if kind == 'pointer':
                # okay, what are we pointing at...
                stinfo = tinfo
                subtype = 'unknown'
                while 'innerTypeKey' in stinfo:
                    for stinfo in self.c.ssa('lookupType', typeKey=stinfo['innerTypeKey']):
                        if 'kind' in stinfo:
                            if stinfo['kind'] == 'pointer':
                                subtype = 'pp'
                            else:
                                #print 'SUBINFO', stinfo
                                subtype = stinfo.get('name', 'unknown')
                            break
                break
            else:
                typeName = tinfo.get('name')
                #print 'TINFO', tinfo
                break
        
        val = 0
        
        lvalues = self.c.ssa('getLocation',
                             TStamp=tstamp,
                             valKey=valKey,
                             typeKey=typeKey,
                             )
        for lvalue in lvalues:
            #print 'LVALUE', lvalue
            if 'valueBitStart' in lvalue:
                if lvalue.get('register'):
                    val = self.getRegister(tstamp, lvalue['register'])
                elif lvalue.get('address'):
                    if tinfo.get('byteSize', 4) == 4:
                        val = self.readInt(tstamp, lvalue['address'])
                    else:
                        val = self.readMem(tstamp, lvalue['address'], tinfo['byteSize']) 
                break
            
        if kind == 'pointer':
            #print 'deref-ing pointer at 0x%x to 0x%x' % (lvalue['address'], val)
            if subtype == 'char':
                val = self.readCString(tstamp, val)
        elif kind == 'int' and typeName == 'bool':
            #print '***boolhex:', hex(ord(val[0])), 'from', lvalue['address']
            val = bool(ord(val[0]))
        
        return val
    
    def _getValueFromPacket(self, tstamp, pinfo):
        return self.getValue(tstamp, pinfo['valKey'], pinfo['typeKey'])
    
    def getParameters(self, tstamp):
        params = []
        for pinfo in self.c.ssm('getParameters', TStamp=tstamp):
            if 'name' in pinfo:
                params.append((pinfo['name'],
                               self._getValueFromPacket(tstamp, pinfo)))
        
        return params
    
    def getLocals(self, tstamp):
        c = self.c
        
        locals = {}
        for lokal in c.ssm('getLocals', TStamp=tstamp):
            if 'name' in lokal:
                locals[lokal['name']] = self._getValueFromPacket(tstamp, lokal)
                
        return locals

    def getReturnValue(self, tstamp, func=None):
        if func is None:
            func = self.findRunningFunction(tstamp)
        
        if func.typeKey is None:
            return None
        
        for tinfo in self.c.ssa('lookupType', typeKey=func.typeKey):
            kind = tinfo.get('kind')
            if kind == 'pointer':
                # okay, what are we pointing at...
                if 'innerTypeKey' in tinfo:
                    for stinfo in self.c.ssa('lookupType', typeKey=tinfo['innerTypeKey']):
                        if 'kind' in stinfo:
                            if stinfo['kind'] == 'pointer':
                                subtype = 'pp'
                            else:
                                #print 'SUBINFO', stinfo
                                subtype = stinfo.get('name', 'unknown')
                else:
                    subtype = 'unknown'  
                break
            else:
                typeName = tinfo.get('name')
                #print 'TINFO', tinfo
                break

        val = self.getRegister(tstamp, 'eax')
            
        if kind == 'pointer':
            #print 'deref-ing pointer'
            if subtype == 'char':
                val = self.readCString(tstamp, val)
        elif kind == 'int' and typeName == 'bool':
            val = bool(val)
        
        return val
        
        

    def getSourceLines(self, source_line):
        '''
        Return a list of a 4-tuples, where the tuple's contents are
        (filename,
         the line number,
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
                lines.append((filename, lineno, line[:sc], line[sc:], ''))
            elif lineno == el:
                lines.append((filename, lineno, '', line[:ec], line[ec:]))
            else:
                lines.append((filename, lineno, '', line, ''))
        return lines

    def scanEnterSP(self, beginTStamp, endTStamp):
        for instr in self.c.ssm('scan',
                                map='ENTER_SP',
                                beginTStamp=beginTStamp, endTStamp=endTStamp,
                                ranges=[{'start': 0, 'length': (2 << 32 - 1)}]):
            if 'TStamp' in instr and instr.get('type') == 'normal':
                tstamp = instr['TStamp']
                func = self.findRunningFunction(tstamp)
                if func:
                    print instr['TStamp'], hex(instr['start']), func.name
                else:
                    print '           ', instr['TStamp'], hex(instr['start'])
                    sline = self.getSourceLineInfo(tstamp)
                    if sline:
                        print self.getSourceLines(sline)

    def scanExecution(self, func):
        '''
        '''
        for instr in self.c.ssm('scan',
                           map='INSTR_EXEC',
                           beginTStamp=func.beginTStamp, endTStamp=func.endTStamp,
                           ranges=[{'start': func.entryPoint, 'length': 1}],
                           # no termination
                           ):
            if 'TStamp' in instr and instr['type'] == 'normal':
                yield (func, instr['TStamp'])

    def getSourceLineInfo(self, tstamp, address=None):
        '''
        cut-paste-modify of scanBySourceLine, fix me
        '''
        if address is None:
            address, = self.getRegisters(tstamp+1, self._pc_reg)
        
        if address in self._instrCache:
            curline = self._instrCache[address]
            
            return curline
        else:
            sinfo = self.c.sss('findSourceInfo',
                          TStamp=tstamp,
                          address=address)
            
            if not 'filename' in sinfo:
                self._instrCache[address] = None
                return None
            else:
                filename = sinfo['filename']
                sl = sinfo['startLine']
                el = sinfo.get('endLine', sl+1)
                sc = sinfo['startColumn'] - 1
                ec = sinfo.get('endColumn', 1)
                
                curline = (filename, sl, el, sc, ec)
                self._instrCache[address] = curline
                
                return curline

    def scanBySourceLine(self, ranges):
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
                           beginTStamp=self._beginTStamp,
                           endTStamp=self._endTStamp,
                           ranges=ranges,
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
                        sl = sinfo['startLine']
                        el = sinfo.get('endLine', sl+1)
                        sc = sinfo['startColumn'] - 1
                        ec = sinfo.get('endColumn', 1)
                        
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

