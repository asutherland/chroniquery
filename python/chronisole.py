#!/usr/bin/env python
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


from chronifer import Chronifer
import chrondis

import optparse, os.path

from pyflam import pout

try:
    from pyflam import pout
except:
    class pout(object):
        def __init__(self):
            import re
            self.pat = re.compile('{[^}]+}')
        def __call__(self, msg, *args, **kwargs):
            print self.pat.sub('', msg) % args
        def pnullfunc(self, arg, **kwargs):
            print str(arg)
        def nullfunc(self, *args, **kwargs):
            pass
        def __getattr__(self, key):
            if key.startswith('p'):
                return self.pnullfunc
            return self.nullfunc
    pout = pout()

# this will need to move elsewhere, of course
class JSScriptInfo(object):
    def __init__(self, name, line):
        self.name = name
        self.line = line

class XPCInterfaceInfo(object):
    def __init__(self, name, ptr):
        self.name = name
        self.ptr = ptr

class XPCMemberInfo(object):
    def __init__(self, name, ptr, iface):
        self.name = name
        self.ptr = ptr
        self.iface = iface

class Chronisole(object):
    '''
    A console, command line, or at least batch processing interface to
    Chronifer.
    '''
    def __init__(self, soleargs, action,
                 *args, **kwargs):
        self.action = action
        self.cf = Chronifer(*args, **kwargs)
        
        self.watches_every = []
        self.watches_by_func = {}
        
        self.functions = soleargs.get('functions', [])
        self.libraries = soleargs.get('libraries', [])
        self.values = soleargs.get('values', [])
        self.excluded_functions = soleargs.get('excluded_functions', [])
        self.max_depth = soleargs.get('depth', 0)
        self.flag_dis = soleargs.get('disassemble', False)
        self.dis_instructions = soleargs.get('instructions', 3)
        self.show_locals = soleargs.get('show_locals', True)
        self.process_watch_defs(soleargs.get('watch_defs', ()))
        self.call_details = soleargs.get('call_details', False)
        self.file_per_func_invoc = soleargs.get('file_per_func_invoc', False)
        
        self.dis = chrondis.ChronDis(self.cf._reg_bits)
    
    def run(self):
        if self.action == 'show':
            self.show()
        elif self.action == 'trace':
            self.trace(self.functions)
        elif self.action == 'jstrace':
            self.init_xpc()
            self.init_jstrace()
            self.jstrace()
        elif self.action == 'mmap':
            self.show_mmap()
        elif self.action == 'findret':
            self.find_calls_with_return_value()
    
    # all this watch stuff is prototyping; generalization/prettification needs
    #  to follow
    def process_watch_defs(self, watch_defs):
        for watch_def in watch_defs:
            cmd = watch_def[0]
            args = watch_def[1:].split(':')
            
            # before, after function
            if cmd in ('-', '+', '@'):
                if cmd == '-':
                    wfunc = self.watch_before
                elif cmd == '+':
                    wfunc = self.watch_after
                elif cmd =='@':
                    wfunc = self.watch_range
                
                function_name = args[0]
                action = args[1]
                args = args[2:]
                
                watches = self.watches_by_func.setdefault(function_name, [])
                watches.append((wfunc, action, args))
            else:
                raise Exception("Unknown watch command '%s' for '%s'" % 
                                (cmd, watch_def))
                
    def watch_common_point(self, tstamp, action, args, **kwargs):
        expr = args[0]
        if len(args) > 1:
            expr_len = args[1]
        else:
            expr_len = self.cf._ptr_size
        
        if expr.startswith('0x'):
            expr_len = int(expr_len)
            if expr_len in (4, 8):
                val = hex(self.cf.readInt(tstamp, int(expr, 16), expr_len))
            else:
                val = self.cf.readMem(tstamp, int(expr, 16), int(expr_len))
            pout('{k}%s{n}: {v}%s', expr, val)
        elif expr.startswith('*'):
            # dereference an argument's value...
            search_varname = expr[1:]
            ptr_val = None
            for varname, value, indirectionStr in kwargs['parameters']:
                if varname == search_varname:
                    ptr_val = value
                    break
            if ptr_val is None:
                print 'unable to find value for %s', search_varname
                return
            expr_len = int(expr_len)
            if expr_len in (4, 8):
                val = hex(self.cf.readInt(tstamp, ptr_val, expr_len))
            else:
                val = self.cf.readMem(tstamp, ptr_val, int(expr_len))
            pout('{k}%s{n}: {v}%s', expr, val)
    
    def watch_before(self, beginTStamp, endTStamp, action, args, **kwargs):
        self.watch_common_point(beginTStamp, action, args, **kwargs)
    
    def watch_after(self, beginTStamp, endTStamp, action, args, **kwargs):
        self.watch_common_point(endTStamp, action, args, **kwargs)
    
    def watch_range(self, beginTStamp, endTStamp, action, args, **kwargs):
        if action == 'show':
            self.show(beginTStamp, endTStamp)
    
    def show(self, beginTStamp=None, endTStamp=None, **kwargs):
        '''
        Old-school command good for extremely small programs that you want a
        source-line-by-source-line execution trace for.
        '''
        ranges = self.cf.getRangesUsingExecutableCompilationUnits()
        
        last_locals = locals = {}
        for startStamp, endStamp, sline in self.cf.scanBySourceLine(ranges,
                                                                    beginTStamp,
                                                                    endTStamp):
            lines = self.cf.getSourceLines(sline)
            
            if self.show_locals:
                locals = self.cf.getLocals(endStamp+1)
                
                locals_sorted = list(locals.keys())
                locals_sorted.sort()
                ldisplay = []
                for lname in locals_sorted:
                    lval = locals[lname]
                    if type(lval) in (int, long):
                        str_lval = hex(lval)
                    else:
                        str_lval = str(lval)
                    if lname not in last_locals or last_locals[lname] != locals[lname]:
                        ldisplay.append('{n}%s:{w}%s' % (lname, str_lval))
                    else:
                        ldisplay.append('{s}%s:%s' % (lname, str_lval))
                ldisplay = ' '.join(ldisplay)
            else:
                ldisplay = ''

            #callinfo = self.cf.findStartOfCall(startStamp)
            #print callinfo

            for line in lines:
                fmt = '{s}%-10.10s %4d: %s{n}%s{s}%s {.60}' + ldisplay
                pout(fmt, os.path.basename(line[0]), *line[1:])
                
                ldisplay = ''
                
            last_locals = locals
    
    def trace(self, function_names):
        '''
        For each function in function names, trace the execution of the
        function, which mainly means tracking functions it in turn calls.
        No attempt is made at timeline integration of the multiple function
        names provided.
        '''
        for func_name in function_names:
            func = self.cf.lookupGlobalFunction(func_name)
            if func is None:
                pout('{e}No such function {n}%s{e}! {s}(skipping)', func_name)
                for aname, akind in self.cf.autocomplete(func_name):
                    pout('   {n}Alternative: {ex}%s {s}(%s)', aname, akind)
            else:
                self.trace_function(func)
            
    def show_mmap(self):
        '''
        Show all of the memory mapping events that happen in the program, ever.
        Debugging functionality, mainly, which readchron.py can also sorta do.
        '''
        for mmap in self.cf.scanMemMap(self.cf._beginTStamp,
                                       self.cf._endTStamp):
            pout.pp(mmap)
    
    def _formatValue(self, value):
        if type(value) in (int, long):
            v = hex(value)
        elif isinstance(value, basestring):
            v = repr(value)
        else:
            v = str(value)
        return v
    
    def _formatParameters(self, parameters):
        str_parts = []
        for label, value, indirectionStr in parameters:
            v = self._formatValue(value)
            try:
                str_parts.append('%s%s: %s' % (indirectionStr, label, v))
            except:
                str_parts.append('%s%s: glitch' % (indirectionStr, label))
    
        return ', '.join(str_parts)
    
    def trace_function(self, func, beginTStamp=None, endTStamp=None):
        '''
        The legwork for the trace() command; given a function and an optional
        constraining timestamp region, finds all invocation of the functions in
        the region and (potentially) traces into calls made by the function.

        Whether functions are recursed into depends on the chroniquery config
        file that marks folders/files/classes/functions/etc. as interesting or
        boring and what not.
        '''
        def helpy(beginTStamp, endTStamp, depth=2, max_depth=None):
            # iterate over the calls found between the given start/end
            #  timestamps, which have been bounded to be inside our parent
            #  function...
            for (subfunc, subBeginTStamp, subEndTStamp, subPreCallSP,
                 subStackEnd, thread) in self.cf.scanCallsBetweenTimes(beginTStamp,
                                                                       endTStamp):
                if subfunc.name in self.excluded_functions:
                    continue
                    
                pc = self.cf.getPC(subBeginTStamp)
                if self.flag_dis:
                    self._diss(subBeginTStamp-3, None, self.dis_instructions, showRelTime=True)
                    self._diss(subBeginTStamp, None, self.dis_instructions, showRelTime=True)
                #self._showMem(subBeginTStamp, self.cf.getSP(subBeginTStamp) -32, 64)
                #pout('{fn}%s {.20}{w}%s {.30}{n}%s', subfunc.name,
                #     self._formatValue(self.cf.getReturnValue(subEndTStamp, subfunc)),
                #     self._formatParameters(self.cf.getParameters(subBeginTStamp, subfunc)),
                #     )
                if subfunc.boring:
                    continue
                
                if self.call_details:
                    pout('{s}cpp {cn}%s{fn}%s {.20}{w}%s {.30}{n}%s',
                         subfunc.containerPrefix, subfunc.name,
                         # it's possible the call never returned due to abort-death. (sad!)
                         subEndTStamp and
                             self._formatValue(self.cf.getReturnValue(subEndTStamp, subfunc)) or
                             "n/a",
                         self._formatParameters(self.cf.getParameters(subBeginTStamp, subfunc,
                                                                      subEndTStamp)),
                         )
                else:
                    pout('{s}cpp {cn}%s{fn}%s', subfunc.containerPrefix, subfunc.name)
                pout.i(2)
                
                # do any dumping!
                if subfunc.dumpInfo:
                    for paramName, paramType, paramVal in self.cf.getRawParameters(
                            subBeginTStamp, subfunc):
                        if subfunc.dumpInfo.get(paramName):
                            # and we're assuming a structure, otherwise what's the
                            #  point.  (but we realy should not assume this)
                            structType = paramType.loseTypedef().innerType
                            sdict = self.cf.getStructValue(subBeginTStamp, paramVal,
                                                           structType)
                            dumpParam = subfunc.dumpInfo[paramName]
                            if dumpParam is True:
                                odict = sdict
                            else:
                                odict = {}
                                for fieldName in dumpParam.split(','):
                                    fieldName = fieldName.strip()
                                    odict[fieldName] = sdict.get(fieldName)
                            pout.pp(odict)

                rel_max_depth = max(max_depth, depth + subfunc.depth)
                if (subfunc.interesting or depth < rel_max_depth):
                    helpy(subBeginTStamp, subEndTStamp, depth + 1, rel_max_depth)
                #sline = self.cf.getSourceLineInfo(subBeginTStamp)
                #if sline:
                #    pout('{s}%s', self.cf.getSourceLines(sline))
                pout.i(-2)
        
        if beginTStamp:
            if func.boring:
                return
            if self.call_details:
                pout('{s}cpp {cn}%s{fn}%s {.20}{w}%s {.30}{n}%s',
                     func.containerPrefix, func.name,
                     # it's possible the call never returned due to abort-death. (sad!)
                     endTStamp and
                         self._formatValue(self.cf.getReturnValue(endTStamp, func)) or
                         "n/a",
                     self._formatParameters(self.cf.getParameters(beginTStamp, func,
                                                                  endTStamp)),
                     )
            else:
                pout('{s}cpp {cn}%s{fn}%s', func.containerPrefix, func.name)
            if func.interesting:
                pout.i(2)
                helpy(beginTStamp, endTStamp)
                pout.i(-2)
            return
        
        # find all the times the function in question was executed
        for func, beginTStamp in self.cf.scanExecution(func):
            #callInfo = self.cf.findStartOfCall(beginTStamp+1)
            endTStamp = self.cf.findEndOfCall(beginTStamp) or func.endTStamp
            if self.flag_dis:
                self._diss(beginTStamp, None, self.dis_instructions, showRelTime=True)
            
            parameters = self.cf.getParameters(beginTStamp, func, endTStamp)
            if self.file_per_func_invoc:
                pout.linkToPermutation(beginTStamp)
            pout('{fn}%s {.20}{w}%s {.30}{n}%s',
                 func.name,
                 self._formatValue(self.cf.getReturnValue(endTStamp, func)),
                 self._formatParameters(parameters),
                 )
            if self.file_per_func_invoc:
                pout.closeLink()
            pout.i(2)
            self.show_watches(beginTStamp, endTStamp, function=func,
                              parameters=parameters)

            if self.file_per_func_invoc:
                pout.pushFilePermutation(beginTStamp)
            if self.max_depth != 1:
                helpy(beginTStamp, endTStamp, self.max_depth)
            if self.file_per_func_invoc:
                pout.popFilePermutation()

            pout.i(-2)
    
    def jstrace(self):
        '''
        SpiderMonkey JS-engine and XPConnect aware tracing support.  Because we
        have the type information available, our offsets are generally reliable,
        but we are still strongly dependent on the spidermonkey JS
        implementation.
        '''
        contexts = {}
        self._jsFuncCache = {}
        
        func = self.cf.lookupGlobalFunction('JS_NewContext')
        contextPointerType = self.cf.getTypeInfo(func.typeKey)
        pout('{g}Context Type Pointer Size{n}: %s', contextPointerType.size)
        contextType = contextPointerType.innerType
        pout('{g}Context Type: {n}%s', contextType)
        # note: free typedef piercing.
        fpField = contextType.getField('fp')
        fpOffset = fpField.offset
        fpSize = fpField.size
        
        pout('{g}fp {n}offset: %d size: %d', fpOffset, fpSize)

        jsFrameType = fpField.type.innerType.loseTypedef()
        # -- get fun info
        jsFunField = jsFrameType.getField('fun')
        self.jsFrameFunOffset = jsFunField.offset
        self.jsFrameFunSize = jsFunField.size
        # - get fun atom
        # the field is of course, a pointer
        jsFunType = jsFunField.type.innerType.loseTypedef()
        jsFunAtom = jsFunType.getField('atom')
        self.jsFunAtomOffset = jsFunAtom.offset
        self.jsFunAtomSize = jsFunAtom.size
        
        # -- get script info
        # - script field
        jsScriptField = jsFrameType.getField('script')
        self.jsFrameScriptOffset = jsScriptField.offset
        self.jsFrameScriptSize = jsScriptField.size
        jsScriptType = jsScriptField.type.innerType.loseTypedef()
        # - script filename
        jsScriptFilename = jsScriptType.getField('filename')
        self.jsScriptFilenameOffset = jsScriptFilename.offset
        self.jsScriptFilenameSize = jsScriptFilename.size
        # - script line
        self.jsScriptLine = jsScriptType.getField('lineno')
        
        # -- get down frame info
        jsDownField = jsFrameType.getField('down')
        
        for func, beginTStamp in self.cf.scanExecution(func):
            endTStamp = self.cf.findEndOfCall(beginTStamp)
            context = self.cf.getReturnValue(endTStamp, func)
            contexts[context] = [endTStamp, None]
            
        func = self.cf.lookupGlobalFunction('js_DestroyContext')
        for func, beginTStamp in self.cf.scanExecution(func):
            endTStamp = self.cf.findEndOfCall(beginTStamp)
            params = self.cf.getParameters(beginTStamp, func, endTStamp)
            context = params[0][1]
            contexts[context][1] = endTStamp
            pout('Context: %x: %d-%d', context, contexts[context][0],
                 contexts[context][1])
            
            contextStart, contextEnd = contexts[context]
            mem_writes = self.cf.findMemoryWrites(contextStart, contextEnd,
                                                  context + fpOffset,
                                                  fpSize)
            
            stack = []
            for writeStamp, writeValue in mem_writes:
                # figure out what point we're at
                func = self.cf.findRunningFunction(writeStamp)

                
                if writeValue == 0:
                    pout('{n}Null write. Resetting stack. From {w}%s{n}',
                         func.name)
                    pout.i(-2 * len(stack))
                    stack = []
                    continue
                
                # figure out if we're pushing or popping...
                if writeValue in stack:
                    idx = stack.index(writeValue)
                    delta = len(stack) - idx - 1
                    del stack[idx+1:]
                    pout.i(-2 * delta)
                    #pout('{s}Pop! by {w}%s {s}Now at: {n}%s',
                    #     func.name, map(hex, stack))
                else:
                    # it could be some form of replacement or something.
                    # check fp->down for more info
                    fpDown = self.cf.readInt(writeStamp,
                                             writeValue+jsDownField.offset,
                                             jsDownField.size)
                    
                    if fpDown in stack:
                        # delete everything _above_ our down friend
                        idx = stack.index(fpDown)
                        delta = len(stack) - idx - 1
                        del stack[idx+1:]
                        pout.i(-2 * delta)
                        
                    stack.append(writeValue)
                    if writeValue == 0:
                        print 'Null push, somewhat ignoring...'
                    else:
                        # js_Invoke:
                        #  top of the func, initial frame.
                        #  (calls js_Interpret)
                        #  bottom of the func, pops the frame
                        # js_Execute:
                        #  top of the func, initial frame
                        #  (calls js_Interpret)
                        #  bottom of the func, pops the frame
                        # js_Interpret:
                        #  inline return, pop frame
                        #  inline call (FUN_INTERP;JSOP_CALL/JSOP_EVAL), push
                        # --- weird places
                        # MaybeSetupFrame (jsparse.cpp) called by js_ParseScript
                        # JS_RestoreFrameChain (jsapi.cpp)
                        
                        script = self.js_script_from_frame(writeStamp, writeValue)
                            
                        if script is None and func.name == 'js_Invoke':
                            (subfunc, subBeginTStamp, subEndTStamp, subPreCallSP,
                             subStackEnd, thread) = self.cf.findNextCall(
                                writeStamp, endTStamp)
                            if subfunc == self.xpcCallMethod:
                                # fast-forward to just before the call to
                                #  SetCallInfo, as the locals will have the info
                                #  we want just sitting there!
                                tsPreSetCallInfo = self.cf.findExecution(
                                    self.xpcCallMethodPreSetCallInfoPC,
                                    subBeginTStamp, subEndTStamp)
                                locals = self.cf.getLocals(tsPreSetCallInfo)
                                pInterface = locals['iface']
                                xpcInterface = self.xpc_get_interface(
                                    tsPreSetCallInfo, pInterface)
                                pMember = locals['member']
                                xpcMember = self.xpc_get_member(
                                    tsPreSetCallInfo, pMember, xpcInterface)
                                
                                pout('{s}xpc {in}%s{s}::{fn}%s{s}()',
                                     xpcInterface.name, xpcMember.name)
                                pout.i(2)

                                # this means a dispatch is going to happen.
                                # we know the pc that will happen before then...
                                tsPreDispatch = self.cf.findExecution(
                                    self.invokePreDispatchPC, subBeginTStamp,
                                    subEndTStamp)
                                # now that dispatch is the next call!
                                if tsPreDispatch:
                                    nextCall = self.cf.findNextCall(tsPreDispatch,
                                                                    subEndTStamp)
                                    if nextCall:
                                        self.trace_function(*nextCall[0:3])
                                # QueryInterface gets its own magic path, so
                                #  there will neverbe a 'thing'
                                elif (xpcInterface.name != 'nsISupports' and
                                      xpcMember.name != 'QueryInterface'):
                                    pout('{e}Unable to find thing.{n}')
                            elif subfunc == self.xpcGetterSetter:
                                tsPreSaarp = self.cf.findExecution(
                                    self.xpcGetterSetterPreSaarpPC,
                                    subBeginTStamp, subEndTStamp)
                                locals = self.cf.getLocals(tsPreSaarp)
                                pInterface = locals['iface']
                                xpcInterface = self.xpc_get_interface(
                                    tsPreSaarp, pInterface)
                                pMember = locals['member']
                                xpcMember = self.xpc_get_member(
                                    tsPreSaarp, pMember, xpcInterface)
                                
                                params = self.cf.getParametersAsDict(tsPreSaarp,
                                                        self.xpcGetterSetter)
                                
                                pout('{s}xpc %s {in}%s{s}::{fn}%s{n}',
                                     params['argc'] and 'set' or 'get',
                                     xpcInterface.name, xpcMember.name)
                                pout.i(2)

                                # - er, this still results in a dispatch!
                                # this means a dispatch is going to happen.
                                # we know the pc that will happen before then...
                                tsPreDispatch = self.cf.findExecution(
                                    self.invokePreDispatchPC, subBeginTStamp,
                                    subEndTStamp)
                                # now that dispatch is the next call!
                                if tsPreDispatch:
                                    nextCall = self.cf.findNextCall(tsPreDispatch,
                                                                    subEndTStamp)
                                    if nextCall:
                                        self.trace_function(*nextCall[0:3])
                                # QueryInterface gets its own magic path, so
                                #  there will neverbe a 'thing'
                                elif (xpcInterface.name != 'nsISupports' and
                                      xpcMember.name != 'QueryInterface'):
                                    pout('{e}Unable to find thing.{n}')
                            else:
                                pout('{s}nat {cn}%s{fn}%s',
                                     subfunc.containerPrefix, subfunc.name)
                                pout.i(2)
                        elif func.name == 'js_Invoke': # script is not None
                            jsFuncName = self.js_function_name_from_frame(
                                             writeStamp, writeValue)
                            pout('{s}js! {jfn}%s {sn}%s{s}:{ln}%d', jsFuncName,
                                 script.name, script.line)
                            pout.i(2)
                        elif func.name == 'js_Interpret':
                            jsFuncName = self.js_function_name_from_frame(
                                             writeStamp, writeValue)
                            pout('{s}js  {jfn}%s {sn}%s{s}:{ln}%d', jsFuncName,
                                 script.name, script.line)
                            pout.i(2)
                        elif func.name == 'js_Execute':
                            if script:
                                pout('{s}js exec {sn}%s{s}:{ln}%d',
                                     script.name, script.line)
                            else:
                                pout('{e}js exec with no script')
                            pout.i(2)
                        else:
                            pout('{s}??? {w}%s', func.fullName)
                            pout.i(2)
    
    def init_jstrace(self):
        self._jsScriptCache = {}
        
        # -- JSString support
        self.jsStringType = self.cf.lookupGlobalType('JSString')
        self.jsStringLengthOffset = self.jsStringType.getField('length').offset
        self.jsStringLengthSize = self.jsStringType.getField('length').size
        uUnionField = self.jsStringType.getField('u')
        charsPtrField = uUnionField.realType.getField('chars')
        self.jsStringPointerOffset = uUnionField.offset
        self.jsStringPointerSize = charsPtrField.size
        
        # -- XPConnect Support
        self.nsInvokeByIndex = self.cf.lookupGlobalFunction('NS_InvokeByIndex')
        self.nsInvokeByIndexP = self.cf.lookupGlobalFunction('NS_InvokeByIndex_P')
        
        # to be clever, we want to locate within NS_InvokeByIndex_P the point
        #  after the call to invoke_copy_to_stack which is where the actual
        #  dispatch happens.  this will allow us to just follow the next call
        #  to wherever it leads.
        invokeCopyToStack = self.cf.lookupGlobalFunction('invoke_copy_to_stack')
        # find the call to invokeCopyToStack
        tsCopyToStackStart = self.cf.findExecution(invokeCopyToStack)
        tsCopyToStackEnd = self.cf.findEndOfCall(tsCopyToStackStart)
        # find the next call following that guy
        nextCall = self.cf.findNextCall(tsCopyToStackEnd,
                                        # end ts is arbitrary but sufficient
                                        invokeCopyToStack.endTStamp)
        tsPreDispatch, pcPreDispatch = self.cf.findCallerPC(nextCall[1])
        self.invokePreDispatchPC = pcPreDispatch
        pout('{e}Pre-Dispatch PC: {n}%x', self.invokePreDispatchPC)
        
        self.xpcCallMethod = self.cf.lookupGlobalFunction('XPC_WN_CallMethod')
        self.xpcGetterSetter = self.cf.lookupGlobalFunction('XPC_WN_GetterSetter')

        # find out the PC of the point just before we jump into SetCallInfo
        #  in XPC_WN_CallMethod
        tsCallMethodStart = self.cf.findExecution(self.xpcCallMethod)
        setCallInfo = self.cf.lookupGlobalFunction('XPCCallContext::SetCallInfo')
        tsSetCallInfoStart = self.cf.findExecution(setCallInfo,
                                                   tsCallMethodStart,
                                                   setCallInfo.endTStamp)
        tsPreDispatch, pcPreDispatch = self.cf.findCallerPC(tsSetCallInfoStart)
        self.xpcCallMethodPreSetCallInfoPC = pcPreDispatch
        
        # for XPC_WN_GetterSetter we need to use SetArgsAndResultPtr because
        #  it has two calls to SetCallInfo inside of it and some branching,
        #  whereas SAARP happens before the branching (and after the failure
        #  handling for GetCallInfo)
        tsGetterSetterStart = self.cf.findExecution(self.xpcGetterSetter)
        SAARP = self.cf.lookupGlobalFunction(
                                        'XPCCallContext::SetArgsAndResultPtr')
        tsSAARP = self.cf.findExecution(SAARP, tsGetterSetterStart,
                                        SAARP.endTStamp)
        tsPreDispatch, pcPreDispatch = self.cf.findCallerPC(tsSAARP)
        self.xpcGetterSetterPreSaarpPC = pcPreDispatch
        
    
    def js_gcthing(self, ptr):
        return ptr & ~7
    
    def js_script_from_frame(self, tstamp, pframe):
        pscript = self.cf.readInt(tstamp, pframe + self.jsFrameScriptOffset,
                                  self.jsFrameScriptSize)
        if pscript == 0:
            return None
        if pscript in self._jsScriptCache:
            return self._jsScriptCache[pscript]
        
        pfilename = self.cf.readInt(tstamp,
                                    pscript + self.jsScriptFilenameOffset,
                                    self.jsScriptFilenameSize)
        if pfilename == 0:
            return ''
        script_name = self.cf.readCString(tstamp, pfilename, 1024, 32)
        script_name = self.cf._evilNormalizePath(script_name)
        
        script_line = self.cf.readInt(tstamp,
                                      pscript + self.jsScriptLine.offset,
                                      self.jsScriptLine.size)
        
        script = JSScriptInfo(script_name, script_line)
        self._jsScriptCache[pscript] = script
        return script
    
    def js_function_name_from_frame(self, tstamp, pframe):
        #print 'pframe %x' % (pframe,)
        #print 'frame offset %x size %d' % (self.jsFrameFunOffset,
        #                                   self.jsFrameFunSize)
        pfun = self.cf.readInt(tstamp, pframe + self.jsFrameFunOffset,
                               self.jsFrameFunSize)
        if pfun == 0:
            return u'no-fun'
        
        # tagged atom
        tatom = self.cf.readInt(tstamp, pfun + self.jsFunAtomOffset,
                                self.jsFunAtomSize)
        # real atom pointer become string
        patom = self.js_gcthing(tatom)
        if (patom != 0):
            return self.js_string_read(tstamp, patom)
        return u'no-fun-atom'
    
    def js_string_read(self, tstamp, strAddr):
        lenFlags = self.cf.readInt(tstamp, strAddr + self.jsStringLengthOffset,
                                   self.jsStringLengthSize)
        JS_BITS_PER_WORD = 64
        JSSTRING_LENGTH_BITS = JS_BITS_PER_WORD - 3
        JSSTRING_LENGTH_MASK = (1 << JSSTRING_LENGTH_BITS) - 1
        
        JSSTRDEP_LENGTH_BITS = JSSTRING_LENGTH_BITS // 2
        JSSTRDEP_LENGTH_MASK = (1 << JSSTRDEP_LENGTH_BITS) - 1
        
        
        
        isDep = lenFlags & (1 << (JS_BITS_PER_WORD-1))
        isPrefix = isMutable = lenFlags & (1 << (JS_BITS_PER_WORD-2))
        isAtomized = lenFlags & (1 << (JS_BITS_PER_WORD-3))
        
        if isDep:
            raise Exception("This dependent string stuff is crazy. Nuts to you.")
            if isPrefix:
                length = lenFlags & JSSTRING_LENGTH_MASK
            else:
                length = lenFlags & JSSTRDEP_LENGTH_MASK
        else:
            length = lenFlags & JSSTRING_LENGTH_MASK
        
        if length:
            pdata = self.cf.readInt(tstamp, strAddr + self.jsStringPointerOffset,
                                    self.jsStringPointerSize)
            return self.cf.readPascalUniString(tstamp, pdata, length)
        else:
            return u'no-atom-string'
    
    def init_xpc(self):
        self._xpcInterfaceCache = {}
        self._xpcMemberCache = {}
        
        xpcInterfaceType = self.cf.lookupGlobalType('XPCNativeInterface')
        xpcInterfaceType = xpcInterfaceType.loseTypedef()
        self.xpcInterfaceNameField = xpcInterfaceType.getField('mName')
        
        xpcMemberType = self.cf.lookupGlobalType('XPCNativeMember')
        xpcMemberType = xpcMemberType.loseTypedef()
        self.xpcMemberNameField = xpcMemberType.getField('mName')
    
    def xpc_get_interface(self, tstamp, pNativeInterface):
        if pNativeInterface in self._xpcInterfaceCache:
            return self._xpcInterfaceCache[pNativeInterface]
        
        pInterfaceName = self.cf.readInt(tstamp,
            pNativeInterface + self.xpcInterfaceNameField.offset,
            self.xpcInterfaceNameField.size)
        interfaceName = self.js_string_read(tstamp,
            self.js_gcthing(pInterfaceName))
        
        xpcInterface = XPCInterfaceInfo(interfaceName, pNativeInterface)
        self._xpcInterfaceCache[pNativeInterface] = xpcInterface
        return xpcInterface

    def xpc_get_member(self, tstamp, pNativeMember, xpcIface):
        if pNativeMember in self._xpcMemberCache:
            return self._xpcMemberCache[pNativeMember]
        
        pMemberName = self.cf.readInt(tstamp,
            pNativeMember + self.xpcMemberNameField.offset,
            self.xpcMemberNameField.size)
        memberName = self.js_string_read(tstamp,
            self.js_gcthing(pMemberName))
        
        xpcMember = XPCMemberInfo(memberName, pNativeMember, xpcIface)
        self._xpcMemberCache[pNativeMember] = xpcMember
        return xpcMember

    
    def show_watches(self, beginTStamp, endTStamp, function=None, **kwargs):
        if function and function.name in self.watches_by_func:
            watches = self.watches_by_func[function.name]
            for wfunc, action, args in watches:
                wfunc(beginTStamp, endTStamp, action, args, **kwargs)
    
    def _diss(self, timestamp, address=None, instructions=1, showRelTime=False):
        '''
        Disassemble the code that was executed at a timestamp, optionally
        listing subsequent opcodes and labeling them with the relative first
        timestamps at which they will be executed in the future.

        @param timestamp The execution timestamp you want a disassembly of.
        @param address Optional address of first instruction to disassemble.  If
            left unspecified (or None), the PC at timestamp is used.  Don't just
            randomly guess an address; x86 opcodes are variable length and don't
            like that.  In general, you would only pass a value here if you have
            already retrieved the PC and want to save a redundant fetch.
        @param instructions Number of instructions to disassemble.
        @param showRelTime If True, provides relative timestamp information as
            well as the stack pointer and frame pointer at that time.
        '''
        if address is None:
            address = self.cf.getPC(timestamp)
        # technically, I think 16 is the right number, but that seems rare.
        MAX_INSTR_SIZE = 8
        code = self.cf.readMem(timestamp, address, instructions*MAX_INSTR_SIZE)
        opcodes = self.dis.dis(address, code)
        for op_addr, op_len, op_dis, op_hex in opcodes[:instructions]:
            op_reltime = ''
            if showRelTime:
                execStamp = self.cf.scanInstructionExecuted(timestamp, op_addr)
                if execStamp:
                    op_reltime = '%d' % (execStamp - timestamp)
                    execSP = self.cf.getSP(execStamp)
                    op_reltime += ' %x' % execSP
                    execBP = self.cf.getReg(execStamp, self.cf._bp_reg)
                    op_reltime += ' %x' % execBP
            pout('{s}%x %d {n}%s (%s) {.78}{g}%s',
                 op_addr, op_len, op_dis, op_hex,
                 op_reltime)
    
    def _showMem(self, timestamp, address, size, block_size=16):
        '''
        Do a hex dump of a memory block (at a given time) (at a given block).
        '''
        after_byte = address + size
        mem = self.cf.readMem(timestamp, address, size)
        for base in range(address - (address % block_size), after_byte, block_size):
            if base < address:
                skip = address % block_size
                dbytes = ['  '] * skip
                offset = 0
            else:
                skip = 0
                dbytes = []
                offset = base - address

            bytes_this_row = min(block_size - skip, after_byte - base)
            dbytes += ['%02x' % ord(x) for x in mem[offset:offset+bytes_this_row]]
            
            pout('{s}%x {n}%s', base, ' '.join(dbytes))
        
        
    
    def dump_stack(self, tstamp, pre=8, post=8, time_window=8):
        '''
        Dump the memory around the stack pointer at a given time-stamp,
        annotating each memory address with the relative time stamps in the time
        window when the stack pointer had that value.

        This was a debugging tool to help dealing with twiddly constants and
        understanding what chronicle-recorder's model is.

        @param tstamp The timestamp at which you care about the stack pointer.
        @param pre The number of pointer sizes prior to the stack pointer to
            display.
        @param post The number of pointer sizes after the stack pointer to
            display.
        @param time_window The number of timestamps before and after the
            provided timestamp to check for their stack pointer value for
            display annotation purposes.
        '''
        mappy = {}
        for delta in range(-time_window, time_window):
            rsp = self.cf.getSP(tstamp + delta)
            mappy.setdefault(rsp, []).append(delta)
        
        sp = self.cf.getSP(tstamp)
        for address in range(sp - pre*self.cf._ptr_size, sp + (post+1)*self.cf._ptr_size, self.cf._ptr_size):
            val = self.cf.readInt(tstamp, address)
            if address == sp:
                pout('{g}%x %x {.20}%s', address, val, mappy.get(address))
            else:
                pout('{n}%x %x {.20}%s', address, val, mappy.get(address))

    def showBackTrace(self, tstamp, depth=0):
        '''
        Perform a back trace at the given time stamp.

        @param tstamp The timestamp at which to run the backtrace.
        @param depth Not for you!  This function is recursive and passes the
            depth to itself for labeling purposes.
        '''
        call = self.cf.findStartOfCall(tstamp)
        if call is None:
            return
        
        beginTStamp, endTStamp, preCallSP, stackEnd, thread = call
        
        # we no longer need to pierce the call
        enterTStamp = beginTStamp
        
        if not depth:
            pout('Backtrace:')

        if self.flag_dis:
            self._diss(enterTStamp, None, self.dis_instructions, showRelTime=True)
            self._diss(endTStamp, None, self.dis_instructions, showRelTime=True)
        
        func = self.cf.findRunningFunction(enterTStamp)
        parameters = self.cf.getParameters(enterTStamp, func, endTStamp)
        pout('%d {fn}%s {.20}{w}%s {.30}{n}%s',
             depth, func.name,
             self._formatValue(self.cf.getReturnValue(endTStamp, func)),
             self._formatParameters(parameters),
             )
        
        # since beginTStamp is no longer pointing at the call, we need to
        #  adjust
        self.showBackTrace(beginTStamp-1, depth+1)
        

    def find_calls_with_return_value(self):
        '''
        Command that tries to find invocations of user-specified functions or
        code in libraries that have user-specified interesting values.

        This works out okay as long as you know generally who is the set of
        functions that may be betraying you.
        '''
        interesting_values = set(self.values)
        
        ranges = []
        
        for func_name in self.functions:
            func = self.cf.lookupGlobalFunction(func_name)
            if func is None:
                pout('{e}No such function {n}%s{e}! {s}(skipping)', func_name)
                for aname, akind in self.cf.autocomplete(func_name):
                    pout('   {n}Alternative: {ex}%s {s}(%s)', aname, akind)
                continue
            self.cf.rangeAdd(ranges, func)
        
        for library_name in self.libraries:
            debugObjectInfo = self.cf.getDebugObjectInfo(library_name)
            ranges.extend(debugObjectInfo['func_entry_ranges'])
        
        if not ranges:
            pout('{e}No ranges found using the given functions/libraries')
            return
        
        for func, beginTStamp in self.cf.scanExecution(ranges):
            endTStamp = self.cf.findEndOfCall(beginTStamp)
            if endTStamp is None:
                continue
            
            retval = self.cf.getReturnValue(endTStamp, func)
            if retval in interesting_values:
                pout('{g}Interesting! {n}%x {s}from {fn}%s', retval,
                     func.name)
                pout.i(2)
                if self.flag_dis:
                    self._diss(beginTStamp, None, self.dis_instructions, showRelTime=True)
                    self._diss(endTStamp, None, self.dis_instructions, showRelTime=True)
                self.showBackTrace(beginTStamp)
                pout.i(-2)
            
    def stop(self):
        try:
            self.cf.stop()
        except:
            pass

def main(args=None, soleclass=Chronisole):
    oparser = optparse.OptionParser()

    oparser.add_option('-H', '--html',
                       dest='html_filename',
                       help='Enable HTML output and output to the given file.')
    oparser.add_option('--nostyle',
                       action='store_false', dest='style',
                       default=True)
    
    oparser.add_option('-f', '--func',
                       dest='functions', action='append', type='str',
                       help='Add list to list of functions to process.',
                       default=[]
                       )
    oparser.add_option('-c', '--call-details',
                       action='store_true', dest='call_details',
                       default=False,
                       help='Show details for all trace sub-calls')
    oparser.add_option('-l', '--library',
                       dest='libraries', action='append', type='str',
                       help='Add library to the list or regions to use.',
                       default=[]
                       )    
    oparser.add_option('-v', '--value',
                       dest='values', action='append', type='int',
                       help='Add list to list of values to process.',
                       default=[]
                       )
    oparser.add_option('-x', '--exclude-func',
                       dest='excluded_functions', action='append', type='str',
                       default=[],
                       help='Exclude functions from processing')
    oparser.add_option('-d', '--depth',
                       dest='depth', type='int',
                       default=0)

    oparser.add_option('-D', '--disassemble',
                       action='store_true', dest='disassemble',
                       default=False,
                       help='Show disassembly of first -I instructions at entry.')
    oparser.add_option('-I', '--instruction-count',
                       dest='instructions', type='int',
                       default=3,
                       help='Number of instructions to disassemble when disassembling.')
    
    oparser.add_option('--no-locals',
                       action='store_false', dest='show_locals',
                       default=True)
    
    oparser.add_option('-w', '--watch',
                       action='append', dest='watches',
                       default=[])

    oparser.add_option('--file-per-func-invoc',
                       action='store_true', dest='file_per_func_invoc',
                       default=False,
                       help="Should each 'trace' function invocation get its own HTML file")

    oparser.add_option('--log',
                       action='store_true', dest='log', default=False,
                       help='Tell chronicle-query to log /tmp')
    oparser.add_option('-X', '--extreme-debug',
                       action='store_true', dest='extremeDebug', default=False,
                       help='like --log, but on the console and perhaps cooler')
    oparser.add_option('-Y', '--query-debug',
                       action='store_true', dest='debugQuery', default=False,
                       help='Run chronicle against chronicle-query')

    
    opts, args = oparser.parse_args(args)

    htmlfile = None
    if opts.html_filename:
        global pout
        import pyflam
        pout = pyflam.FlamHTML(opts.html_filename, style=opts.style,
                               title='Chronisole Output')
    
    cs = soleclass({'functions': opts.functions,
                     'libraries': opts.libraries,
                     'values': opts.values,
                     'excluded_functions': opts.excluded_functions,
                     'depth': opts.depth,
                     'disassemble': opts.disassemble,
                     'instructions': opts.instructions,
                     'show_locals': opts.show_locals,
                     'watch_defs': opts.watches,
                     'call_details': opts.call_details,
                     'file_per_func_invoc': opts.file_per_func_invoc,
                     },
                    querylog=opts.log,
                    extremeDebug=opts.extremeDebug,
                    debugQuery=opts.debugQuery,
                    *args)
    cs.run()

    if opts.html_filename:
        pout.close()
    
    cs.stop()

if __name__ == '__main__':
    main()
