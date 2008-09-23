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

import socket, linecache, os.path, math, struct, ConfigParser

class FuncInfo(object):
    def __init__(self, cf, name, containerPrefix,
                 entryPoint, typeKey,
                 beginTStamp, endTStamp,
                 ranges,
                 prologueEnd=None,
                 compilationUnit=None, compilationUnitDir=None):
        self.cf = cf
        
        self.name = name
        self.containerPrefix = containerPrefix or ''
        self.fullName = self.containerPrefix + self.name
         
        self.entryPoint = entryPoint
        self.typeKey = typeKey
        
        self.beginTStamp = beginTStamp
        self.endTStamp = endTStamp
        self.ranges = ranges
        self.prologueEnd = prologueEnd
        
        # we should be passing relativeTo for one of these, probably
        self.compilationUnit = self.cf._evilNormalizePath(compilationUnit)
        self.compilationUnitDir = self.cf._evilNormalizePath(compilationUnitDir)
        
        # prefer the compilationUnitDir if present, because it actually knows
        #  where (some?) headers came from 
        self.interesting, self.depth, self.boring = self.cf._isComplexInteresting(
                            self.compilationUnitDir or self.compilationUnit,
                            self.containerPrefix, self.name)
        
        if '<' in self.fullName:
            #print 'Boring-izing template', self.fullName
            self.interesting = False
            self.depth = 0
            self.boring = True

        if not self.boring:
            print 'Function', self.fullName, 'idb', self.interesting, self.depth, self.boring
            print ' Compilation Unit', self.compilationUnit
            print ' Compilation Dir', self.compilationUnitDir


class TypeInfo(object):
    def loseTypedef(self):
        return self

class PointerTypeInfo(TypeInfo):
    def __init__(self, innerType, size):
        self.innerType = innerType
        self.size = size
    
    def __str__(self):
        return '*%s' % (self.innerType,)

class ArrayTypeInfo(TypeInfo):
    def __init__(self, innerType, length):
        self.innerType = innerType
        self.length = length
    
    def __str__(self):
        return '%s[%s]' % (self.innerType, self.length)

class TypedefTypeInfo(TypeInfo):
    def __init__(self, name, innerType):
        self.name = name
        self.innerType = innerType
    
    def getField(self, name):
        return self.innerType.getField(name)
    
    def loseTypedef(self):
        return self.innerType.loseTypedef()
    
    def __str__(self):
        return 'typedef:%s=%s' % (self.name, self.innerType)

class FieldTypeInfo(TypeInfo):
    def __init__(self, chronifer, parent, name, offset, size, fieldTypeKey):
        self.cf = chronifer
        self.parent = parent
        self.name = name
        self.offset = offset
        self._size = size
        self.typeKey = fieldTypeKey
        self.fieldType = None
    
    @property
    def size(self):
        if self._size:
            return self._size
        return self.realType.size
    
    @property
    def type(self):
        if self.fieldType is None:
            self.fieldType = self.cf.getTypeInfo(self.typeKey)
        return self.fieldType
    
    @property
    def realType(self):
        if self.fieldType is None:
            self.fieldType = self.cf.getTypeInfo(self.typeKey)
        return self.fieldType.loseTypedef()
    
    def __str__(self):
        # avoid recursion in display... don't show the type
        return '%s' % (self.name,)

class StructTypeInfo(TypeInfo):
    def __init__(self, name, kind):
        self.name = name
        self.kind = kind
        self.fields = []
        self.fieldsByName = {}
    
    def addField(self, field):
        self.fields.append(field)
        self.fieldsByName[field.name] = field
    
    def getField(self, name):
        return self.fieldsByName[name]
    
    def __str__(self):
        return '{%s %s %s}' % (self.kind, self.name,
                               ', '.join(map(str, self.fields)))

class AnnotationTypeInfo(TypeInfo):
    def __init__(self, annotation, innerType):
        self.annotation = annotation
        self.innerType = innerType

    # meh, annotations are stupid, lose them
    def loseTypedef(self):
        return self.innerType
    
    def __str__(self):
        return '%s %s' % (self.annotation, self.innerType)

class NativeTypeInfo(TypeInfo):
    def __init__(self, name, signed, size):
        self.name = name
        self.signed = signed
        self.size = size
    
    def __str__(self):
        return '%s%s%d' % ((self.signed is None) and ' ' or
                           (self.signed and 'signed' or 'unsigned'),
                           self.name, self.size)

VoidPointerType = PointerTypeInfo(NativeTypeInfo('void', None, 0), 0)

class Chronifer(object):
    '''
    A highly fluxy higher level wrapper over ChroniQuery.  For now, it's 
    basically my __main__ test code re-purposed towards reuse.
    '''

    def __init__(self, exe_file, db_file=None, querylog=False,
                 extremeDebug=False, debugQuery=False):
        exe_file = os.path.abspath(exe_file)

        if db_file is None:
            db_file = exe_file + '.db'
        else:
            db_file = os.path.abspath(db_file)
        
        self.exe_file = exe_file
        self.db_file = db_file

        self.config = ConfigParser.SafeConfigParser()
        self.config.read(os.path.expanduser('~/.chroniquery.cfg'))

        self._initInterestingLogic()
        
        self.c = ChroniQuery(self.db_file,
                             querylog=querylog,
                             extremeDebug=extremeDebug,
                             debugQuery=debugQuery)
        
                
        self._startupPrep()
        
        self._instrCache = {}
        self._funcCache = {}
        self._typeCache = {}

    def _initInterestingLogic(self):
        self._interestingPaths = {}
        self._interestingContainers = {}
        self._interestingFunctions = {}
        
        # it would be crazy for everybody to be interesting
        self._defaultInteresting = False
        self._defaultDepth = 0
        
        def get_values(sect):
            if self.config.has_option(sect, 'interesting'):
                interesting = self.config.getboolean(sect, "interesting")
            else:
                interesting = None
            
            if self.config.has_option(sect, 'depth'):
                depth = self.config.getint(sect, 'depth')
            else:
                depth = interesting and 1 or 0
            
            if self.config.has_option(sect, 'boring'):
                boring = self.config.getboolean(sect, 'boring')
            else:
                boring = None
            
            # boring implies not interesting, but not boring does not imply
            #  interesting.
            if boring:
                depth = 0
                interesting = False
                
            return (interesting, depth, boring)
            
        
        for section in self.config.sections():
            if section.startswith('dir@'):
                dirname = section[4:]
                if dirname.endswith('/'):
                    dirname = dirname[:-1]
                self._interestingPaths[dirname] = get_values(section)
                #print 'Set', dirname, 'to', self._interestingPaths[dirname]
                
            elif section.startswith('class@'):
                container_name = section[6:] + '::'
                self._interestingContainers[container_name] = get_values(section)
            elif section.startswith('func@'):
                func_name = section[5:]
                self._interestingFunctions[func_name] = get_values(section)
    
    def _isComplexInteresting(self, path, containerPrefix, funcName):
        interesting = self._defaultInteresting
        depth = self._defaultDepth
        boring = False
        
        # non-existent paths are inherently boring
        if path is None:
            return interesting, depth, boring
        
        # paths first
        cur_path = ''
        path = os.path.normpath(path)
        for path_part in path.split('/'): # nuts to windows
            cur_path = os.path.join(cur_path, path_part)
            if cur_path in self._interestingPaths:
                dirInteresting, dirDepth, dirBoring = self._interestingPaths[cur_path]
                if dirInteresting is not None:
                    interesting = dirInteresting
                if dirDepth is not None:
                    depth = dirDepth
                if dirBoring is not None:
                    boring = dirBoring
        
        # then containers
        if containerPrefix in self._interestingContainers:
            contInteresting, contDepth, contBoring = \
                    self._interestingContainers[containerPrefix]
            if contInteresting is not None:
                interesting = contInteresting
            if contDepth is not None:
                depth = contDepth
            if contBoring is not None:
                boring = contBoring
        
        # then function name
        if containerPrefix in self._interestingContainers:
            contInteresting, contDepth, contBoring = \
                    self._interestingContainers[containerPrefix]
            if contInteresting is not None:
                interesting = contInteresting
            if contDepth is not None:
                depth = contDepth
            if contBoring is not None:
                boring = contBoring
        
        if funcName in self._interestingFunctions:
            funcInteresting, funcDepth, funcBoring = \
                    self._interestingFunctions[funcName];
            if funcInteresting is not None:
                interesting = funcInteresting
            if funcDepth is not None:
                depth = funcDepth
            if funcBoring is not None:
                boring = funcBoring
                
        return interesting, depth, boring
    
    def _evilNormalizePath(self, path, relativeTo=None):
        '''
        I am evil because this logic has hard-coding in it.  Pragmatic, but
        evil.  Pragevil?  Sounds like some form of pill.
        '''
        if path is None:
            return path
        
        # absolute we can work with...
        if os.path.isabs(path):
            norm_path = os.path.normpath(path)
        elif relativeTo:
            norm_path = os.path.normpath(os.path.join(relativeTo, path))
            os.path.abspath(path)
        else: 
            # I'm sure there's a way to find the base directory, but I don't
            #  really care right now.
            # XXX find the base directory and use that as a relative basis
            # let's just strip off any preceding '../' stuff
            while path.startswith('../'):
                path = path[3:]
            norm_path = os.path.normpath(path)
        # this is really the evil part.
        if 'comm-central/' in norm_path:
            norm_path = norm_path[norm_path.rindex('comm-central/')+13:]
        elif 'mozilla-central/' in norm_path:
            norm_path = 'mozilla/' + norm_path[norm_path.rindex('mozilla-central/')+16:]
        # (this still counts as the evil part.  in fact, it's more evil.)
        if norm_path.startswith('obj-'):
            # strip the objdir off...
            norm_path = norm_path[norm_path.find('/')+1:]
        return norm_path
    
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
            self._bp_reg = 'ebp'
            self._retval_reg = 'eax'
            self._ptr_size = 4
            self._reg_bits = 32
            self._max_long = (2 << 32) - 1
            self._int_sizes = (4,)
        elif self._arch == 'amd64':
            self._sp_reg = 'rsp'
            self._bp_reg = 'rbp'
            self._retval_reg = 'rax'
            self._ptr_size = 8
            self._reg_bits = 64
            self._max_long = (2 << 64) - 1
            self._int_sizes = (4, 8)
        
        self._pc_reg = 'pc'
        self._thread_reg = 'thread'
    
    def _decodePlatInt(self, sval):
        '''
        Turn a platform-specific int into a python integer, handling endian
        conversion.
        '''
        #return socket.htonl(int(sval, 16))
        if len(sval) == 4:
            return struct.unpack('>H', struct.pack('<H', int(sval, 16)))[0]
        elif len(sval) == 8: # 8 hexadecimal string bytes though
            return struct.unpack('>I', struct.pack('<I', int(sval, 16)))[0]
        else:
            return struct.unpack('>Q', struct.pack('<Q', int(sval, 16)))[0]
    
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
                        finfo.get('containerPrefix'),
                        finfo['entryPoint'],
                        finfo.get('typeKey'),
                        finfo['beginTStamp'],
                        finfo['endTStamp'],
                        finfo.get('ranges'),
                        finfo.get('prologueEnd'),
                        finfo.get('compilationUnit'),
                        finfo.get('compilationUnitDir'),
                        )
        return func
    
    def _fabAnonFunction(self, pc):
        func = FuncInfo(self,
                        'Anon:%x' % pc, None,
                        pc,
                        None, None, None, None, None)
        return func
    
    def lookupGlobalFunction(self, func_name):
        finfo = self.c.sss('lookupGlobalFunctions',
                           name=func_name)
        if finfo:
            func = self._fabFunction(finfo)
            if func and func.entryPoint:
              self._funcCache[func.entryPoint] = func
            return func
        return None
    
    def lookupGlobalFunctions(self, func_pattern):
        for finfo in self.c.ssm('lookupGlobalFunctions',
                                name=func_pattern):
            if 'name' in finfo:
                func = self._fabFunction(finfo)
                if func and func.entryPoint:
                    self._funcCache[func.entryPoint] = func
                yield func
    
    def autocomplete(self, prefix, kind=None):
        extra = {}
        if kind:
            extra['kind'] = kind
        for ainfo in self.c.ssm('autocomplete',
                                prefix=prefix,
                                **extra):
            if 'name' in ainfo:
                yield ainfo['name'], ainfo['kind']
    
    def getRangesUsingExecutableCompilationUnits(self):
        # dubious ability to handle non-absolute paths for cases where the
        #  data file is local but the executable was on our path or such.
        exe_file = os.path.realpath(self.exe_file)
        if '/' in exe_file and os.path.exists(exe_file):
            # er, what if it's a script?
            f = open(exe_file, 'rb')
            first_two = f.read(2)
            f.close()
            # if it's a script, hope the script has the same name as the
            #  executable or is a prefix of it...
            if first_two == '#!':
                exe_query = ''
                exe_test = '/' + os.path.basename(exe_file)
            else:
                exe_query = exe_file
                exe_test = ''
        else:
            exe_query = ''
            exe_test = '/' + os.path.basename(exe_file)
        
        comp_units = self.c.ssa('lookupCompilationUnits',
                                debugObjectName=exe_query,
                                compilationUnitName='')
    
        ranges = []
        for comp_unit in comp_units:
            if not comp_unit.get('debugObject', '').endswith(exe_test):
                continue
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
    
    def findNextCall(self, beginTStamp, endTStamp):
        '''
        Basically a one-shot variant of scanCallsBetweenTimes.
        '''
        calls = list(self.scanCallsBetweenTimes(beginTStamp, endTStamp, True))
        return calls and calls[0] or None
    
    def scanCallsBetweenTimes(self, beginTStamp, endTStamp, oneShot=False):
        sp, thread = self.getRegisters(beginTStamp, self._sp_reg,
                                       self._thread_reg)
        # find where the stack can grow to (numerically smaller addresses)
        stackLimit = self.findMemoryBegin(beginTStamp, sp)
        # find where the stack comes from / starts
        stackEnd = self.findMemoryEnd(beginTStamp, sp)
        
        #print 'scanCalls: sp', hex(sp), 'stack limit', hex(stackLimit), 'stack end', hex(stackEnd), 'length', hex(sp - stackLimit)
        
        firstTime = True
        while not oneShot or firstTime:
            firstTime = False
            
            # okay, the idea here is to find the first ENTER_SP invocation that
            #  happens with a stack address numerically smaller than our current
            #  stack pointer (aka the stack grows and it's the result of
            #  something that resembles a call).
            # Because ranges start numerically low and get bigger, we want to
            #  start at the 'limit' of the stack (the furthest it can grow), and
            #  go all the way back up until the last byte before the current
            #  stack pointer.  (the stack pointer points at a byte that is part
            #  of the stack)  For arbitrary example, we have a stack that starts
            #  at 256 decimal (after alignment) and grows down to 4; sp is 128.
            #  that means we want our range to cover bytes 4-127 inclusive, so
            #  we do a start of 0 and a length of (sp - start) = 124.
            # NEW ODDNESS: previously, the first guy we saw was the guy we
            #  wanted; but now we tend to get like 2+ results, in reverse time
            #  order because we asked for findFirst.
            cinfs = self.c.ssa('scan', map='ENTER_SP', termination='findFirst',
                               beginTStamp=beginTStamp,
                               endTStamp=endTStamp,
                               ranges=[{'start': stackLimit,
                                        'length': sp - stackLimit}])
            #print '---'
            cinfo = {}
            for pcinfo in cinfs:
                #print pcinfo
                if pcinfo.get('type') == 'normal':
                    cinfo = pcinfo
            if cinfo.get('type') == 'normal':
                subEnterTStamp = cinfo['TStamp']
                subEnterSP = cinfo['start']
                subPreCallSP = subEnterSP + self._ptr_size
                subEndTStamp = self._findEndOfCallWithRegs(subEnterTStamp + 1,
                                                           subEnterSP,
                                                           thread)
                # we have the very real potential to be happening upon a
                #  trampoline.  I love trampolines as much as the next guy, but
                #  this vaguely screws up my analysis.  so, let's just see if
                #  the pc one time-stamp after our real point is someplace
                #  else that's crazy.  in such a case, let us use that pc.
                pc = self.getPC(subEnterTStamp+1)
                paranoia_pc = self.getPC(subEnterTStamp+2)
                if abs(paranoia_pc - pc) > 128:
                    subEnterTStamp += 1
                    pc = paranoia_pc
                func = self.findRunningFunction(subEnterTStamp+1, pc)
                
                if func and pc == func.entryPoint:
                    yield (func,
                           subEnterTStamp + 1,
                           subEndTStamp,
                           subPreCallSP,
                           stackEnd, thread)

                    # the next possible call has to be after this one returned
                    # (this rules out sub-call following, we leave that to our caller!)
                    beginTStamp = subEndTStamp + 1

                else:
                    # er, why not follow?
#                    yield (subEnterTStamp + 1,
#                           subEndTStamp,
#                           subPreCallSP,
#                           stackEnd, thread)
#
                    print 'Unable to locate function with address %x (%d-%d)' % (pc, subEnterTStamp, subEndTStamp) 
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
    
    def findRunningFunction(self, tstamp, pc=None, unknown_ok=True):
        '''
        Find the function executing at time tstamp.
        '''
        if pc is None:
            pc, = self.getRegisters(tstamp, self._pc_reg)
        func = self._funcCache.get(pc)
        if func is None:
            finfo = self.c.sss('findContainingFunction', TStamp=tstamp,
                               address=pc)
            if finfo is not None and 'entryPoint' in finfo:
                entryPoint = finfo['entryPoint']
                if entryPoint in self._funcCache:
                    func = self._funcCache[entryPoint]
                else:
                    func = self._fabFunction(finfo)
                    self._funcCache[func.entryPoint] = func
            else:
                func = self._fabAnonFunction(pc)
            self._funcCache[pc] = func
        return func
    
    def findMemoryWrites(self, beginTStamp, endTStamp, beginAddr, memSize=None):
        '''
        
        '''
        writes = []
        for minfo in self.c.ssm('scan', map='MEM_WRITE',
                                beginTStamp=beginTStamp, endTStamp=endTStamp,
                                ranges=[{'start': beginAddr,
                                         'length': memSize or self._ptr_size}],
                                # we want them all, specify no termination
                                ):
            if minfo.get('type') == 'normal' and 'TStamp' in minfo:
                 writes.append((minfo['TStamp'],
                                self._decodePlatInt(minfo['bytes'])))
        return writes
    
    def findMemoryBegin(self, tstamp, addr, bump=0x10000):
        '''
        '''
        # chronomancer bumps memory by 0x10000, so we'll use that too...
        beginAddr = max(0, addr - bump)

        # okay, so I'm not really sure how to make chronicle-query actually
        #  output the records in the order we want, and it's my bedtime real
        #  soon, and I just want this to work, so, hack it is.  we just stash
        #  things that don't help us, and then play things backwards under
        #  the assumption that they are really just ordered exactly wrong for
        #  what we want.  This seems like a bad assumption if stacks ever
        #  decide to grow dynamically, and the O(n^2) generalization of this
        #  hack is, well, O(n^2).  So, good until it breaks :)
        # TODO: do the right thing (or at least know the assumptions) for membegin
        rewind_list = []
        
        mappedBegin = addr
        for minfo in self.c.ssm('scan', map='MEM_MAP',
                                beginTStamp=0, endTStamp=tstamp,
                                ranges=[{'start': beginAddr,
                                         'length': addr - beginAddr}],
                                termination='findLastCover',
                                ):
            if minfo.get('mapped') and (minfo['start'] +
                                        minfo['length']) >= mappedBegin:
                mappedBegin = min(mappedBegin, minfo['start'])
            elif minfo.get('mapped'):
                rewind_list.append(minfo)

        rewind_list.reverse()
        for minfo in rewind_list:
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
    
    def findCallerPC(self, tstamp, pc=None):
        '''
        Given a call that begins at tstamp, find the last PC of the caller
        before control was transferred.  The potential 'gotcha' that this
        method attempts to address are trampolines.
        '''
        # for now, we are arguably very stupid and we just keep running the
        #  time-stamp backwards until we see a large jump that is not followed
        #  by another large jump
        # this should nicely handle tstamp being in the middle of a prolog too
        if pc is None:
            pc = self.getPC(tstamp)
        pc_delta = 0
        # keep going until we see the big jump 
        while pc_delta < 16:
            tstamp -= 1
            prev_pc = self.getPC(tstamp)
            pc_delta = abs(prev_pc - pc)
            pc = prev_pc
        # stop once we no longer see a big jump
        while pc_delta >= 16:
            pc = prev_pc
            tstamp -= 1
            prev_pc = self.getPC(tstamp)
            pc_delta = abs(prev_pc - pc)
        return (tstamp + 1, pc)
    
    def findContainingFunction(self, tstamp, addr):
        finfo = self.c.sss('findContainingFunction',
                           address=addr,
                           TStamp=tstamp)
        return self._fabFunction(finfo)
    
    def readMem(self, tstamp, address, length):
        dstr = '0' * length * 2
        for dvalue in self.c.ssa('readMem',
                            TStamp=tstamp,
                            ranges=[{'start': address,
                                     'length': length
                                    }]):
            if 'bytes' in dvalue:
                offset = (dvalue['start'] - address) * 2
                length = dvalue['length'] * 2
                dstr = dstr[:offset] + dvalue['bytes']  + dstr[offset+length:]
        rstr = ''
        for idx in range(0, len(dstr), 2):
            rstr += chr(int(dstr[idx:idx+2], 16)&0xff)
        return rstr

    def readCString(self, tstamp, address, maxlength=256, probesize=128):
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

    def readPascalUniString(self, tstamp, address, length):
        '''
        Read a unicode string of the given length from address.
        @param length The number of characters in the string.
        '''
        dstr = self.readMem(tstamp, address, 2 * length)
        try:
            return dstr.decode('utf_16_le')
        except:
            return 'corrupt-very-sad'

    def readInt(self, tstamp, address, byteSize):
        if byteSize is None:
            raise Exception('byteSize has to be a number!')
        dvalue = self.c.sss('readMem',
                            TStamp=tstamp,
                            ranges=[{'start': address,
                                     'length': byteSize,
                                    }])
        return self._decodePlatInt(dvalue['bytes'])

    
    def getValue(self, tstamp, valKey, typeKey):
        #print '---'

        # although the whole routine still needs a lot more work, this part is horrid.
        indirections = []
        for tinfo in self.c.ssa('lookupType', typeKey=typeKey):
            kind = tinfo.get('kind')
            if kind == 'pointer':
                # okay, what are we pointing at...
                stinfo = tinfo
                subtype = 'unknown'
                while 'innerTypeKey' in stinfo:
                    indirections.append(stinfo)
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
                    byteSize = tinfo.get('byteSize', self._ptr_size)
                    if byteSize in self._int_sizes:
                        val = self.readInt(tstamp, lvalue['address'], byteSize)
                    else:
                        val = self.readMem(tstamp, lvalue['address'], byteSize)
                break
        
        if kind == 'pointer':
            # if it's a type we know how to print, pop off the indirections...
            if subtype == 'char':
                # now pop off the indirections (this does not include the final
                #  type!), noting that we skip the first indirection, because
                #  it has already been 'pierced'
                for indirection in indirections[1:]:
                    if indirection['kind'] == 'pointer':
                        byteSize = indirection.get('byteSize', self._ptr_size)
                        val = self.readInt(tstamp, val, byteSize)
                
                val = self.readCString(tstamp, val)
        elif kind == 'int' and typeName == 'bool':
            #print '***boolhex:', hex(ord(val[0])), 'from', lvalue['address']
            val = bool(ord(val[0]))
        
        return val
    
    def _getValueFromPacket(self, tstamp, pinfo):
        return self.getValue(tstamp, pinfo['valKey'], pinfo['typeKey'])
    
    def getParameters(self, tstamp, func=None):
        if func is None:
            func = self.findRunningFunction(tstamp)

        # find the timestamp at which the prologue has been executed, it
        #  may be stashing parameters in locals (which may or may not be
        #  dumb)
        if func.prologueEnd:
            prologueEndTStamp = self.scanInstructionExecuted(tstamp, func.prologueEnd)
        else:
            # this is sad, but there's not a lot to do
            prologueEndTStamp = tstamp

        params = []
        for pinfo in self.c.ssm('getParameters', TStamp=prologueEndTStamp):
            if 'name' in pinfo:
                params.append((pinfo['name'],
                               self._getValueFromPacket(prologueEndTStamp, pinfo)))
        
        return params
    
    def getParametersAsDict(self, *args, **kwargs):
        return dict(self.getParameters(*args, **kwargs))
    
    def getLocals(self, tstamp):
        c = self.c
        
        locals = {}
        for lokal in c.ssm('getLocals', TStamp=tstamp):
            if 'name' in lokal:
                locals[lokal['name']] = self._getValueFromPacket(tstamp, lokal)
                
        return locals

    def lookupGlobalType(self, name):
        infos = self.c.ssa('lookupGlobalType', name=name)
        tinfo = infos[0]
        if 'typeKey' in tinfo:
            return self.getTypeInfo(tinfo['typeKey'])
        return None

    def getTypeInfo(self, typeKey):
        if typeKey in self._typeCache:
            return self._typeCache[typeKey]
        
        for tinfo in self.c.ssa('lookupType', typeKey=typeKey):
            if 'terminated' in tinfo:
                continue
            
            if 'partial' in tinfo:
                tinfo = self.c.sss('lookupGlobalType', name=tinfo['name'],
                                   typeKey=typeKey)
            
            kind = tinfo.get('kind')
            if kind == 'annotation':
                ti = AnnotationTypeInfo(tinfo['annotation'],
                                        self.getTypeInfo(tinfo['innerTypeKey']))
            elif kind == 'pointer':
                if 'innerTypeKey' in tinfo:
                    ti = PointerTypeInfo(self.getTypeInfo(tinfo['innerTypeKey']),
                                         tinfo.get('byteSize'))
                else:
                    ti = VoidPointerType
            elif kind == 'typedef':
                ti = TypedefTypeInfo(tinfo['name'],
                                     self.getTypeInfo(tinfo['innerTypeKey']))
            elif kind == 'struct':
                ti = StructTypeInfo(tinfo.get('name'), tinfo['structKind'])
                # cache structs immediately since they can be self-recursive
                self._typeCache[typeKey] = ti
                for finfo in tinfo.get('fields'):
                    fi = FieldTypeInfo(self, ti, finfo.get('name'),
                                       finfo.get('byteOffset'),
                                       finfo.get('byteSize'),
                                       finfo['typeKey'])
                    ti.addField(fi)
            elif kind == 'array':
                ti = ArrayTypeInfo(self.getTypeInfo(tinfo['innerTypeKey']),
                                   tinfo.get('length'))
            elif kind == 'function':
                print 'Ignoring function type.'
                ti = None
            elif kind in ('int', 'float'):
                ti = NativeTypeInfo(kind, tinfo.get('signed'),
                                    tinfo['byteSize'])
            elif kind == 'enum':
                ti = None
            elif kind is None and 'progress' in tinfo:
                # ignore things that are just about progress
                ti = None
                continue
            else:
                ti = None
                print 'UNKNOWN!', tinfo
                typeName = tinfo.get('name')
                #print 'TINFO', tinfo
        
        self._typeCache[typeKey] = ti
        return ti

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
                                subtype = stinfo.get('name', 'unknown')
                else:
                    subtype = 'unknown'
                break
            else:
                typeName = tinfo.get('name')
                #print 'TINFO', tinfo
                break

        val = self.getRegister(tstamp, self._retval_reg)
            
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

    def scanMemMap(self, beginTStamp, endTStamp):
        # scan all of memory!
        for mmap in self.c.ssm('scan',
                                map='MEM_MAP',
                                beginTStamp=beginTStamp, endTStamp=endTStamp,
                                ranges=[{'start': 0, 'length': self._max_long}]
                                ):
            yield mmap
        

    def scanEnterSP(self, beginTStamp, endTStamp):
        for instr in self.c.ssm('scan',
                                map='ENTER_SP',
                                beginTStamp=beginTStamp, endTStamp=endTStamp,
                                ranges=[{'start': 0, 'length': self._max_long}]):
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

    def scanInstructionExecuted(self, timestamp, address, endTStamp=None):
        if endTStamp is None:
            endTStamp = self._endTStamp
        # even though we only want one, iterate in case an mmap gets in there
        #  to mess us up.  use ssa because we won't finish consuming the iter
        for instr in self.c.ssa('scan',
                           map='INSTR_EXEC',
                           beginTStamp=timestamp, endTStamp=endTStamp,
                           ranges=[{'start': address, 'length': 1}],
                           termination='findFirst'):
            if 'TStamp' in instr and instr['type'] == 'normal':
                return instr['TStamp']
        return None

    def findExecution(self, func_or_pc, beginTStamp=None, endTStamp=None):
        if isinstance(func_or_pc, FuncInfo):
            pc = func_or_pc.entryPoint
        else:
            pc = func_or_pc
        
        for instr in self.c.ssa('scan', map='INSTR_EXEC',
                           # let's avoid the mmap event entirely
                           beginTStamp=beginTStamp or func_or_pc.beginTStamp+1,
                           endTStamp=endTStamp or func_or_pc.endTStamp,
                           ranges=[{'start': pc, 'length': 1}],
                           termination='findFirst',
                           ):
            if instr and 'TStamp' in instr and instr['type'] == 'normal':
                return instr['TStamp']
        return None

    def scanExecution(self, func):
        '''
        '''
        for instr in self.c.ssm('scan',
                           map='INSTR_EXEC',
                           beginTStamp=func.beginTStamp,
                           endTStamp=func.endTStamp,
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

    def scanBySourceLine(self, ranges, beginTStamp=None, endTStamp=None):
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
        beginTStamp = beginTStamp or self._beginTStamp
        endTStamp = endTStamp or self._endTStamp
        
        lastline = ('', 0, 0, 0, 0)
        
        if len(ranges) == 0:
            # do not wildcard, or our line cache logic will kill us
            ranges = None
        
        tstamp = startStamp = lastStamp = None
        for instr in c.ssm('scan',
                           map='INSTR_EXEC',
                           beginTStamp=beginTStamp,
                           endTStamp=endTStamp,
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

