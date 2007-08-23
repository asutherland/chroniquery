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

class Chronisole(object):
    '''
    A console, command line, or at least batch processing interface to
    Chronifer.
    '''
    def __init__(self, soleargs, action,
                 *args, **kwargs):
        self.action = action
        self.cf = Chronifer(*args, **kwargs)
        
        self.functions = soleargs.get('functions', [])
        self.excluded_functions = soleargs.get('excluded_functions', [])
        self.max_depth = soleargs.get('depth', 0)
    
    def run(self):
        if self.action == 'show':
            self.show()
        elif self.action == 'trace':
            self.trace(self.functions)
    
    def show(self, locals=True):
        ranges = self.cf.getRangesUsingExecutableCompilationUnits()
        
        last_locals = {}
        for startStamp, endStamp, sline in self.cf.scanBySourceLine(ranges):
            lines = self.cf.getSourceLines(sline)
            
            locals = self.cf.getLocals(endStamp+1)
            
            locals_sorted = list(locals.keys())
            locals_sorted.sort()
            ldisplay = []
            for lname in locals_sorted:
                if lname not in last_locals or last_locals[lname] != locals[lname]:
                    ldisplay.append('{n}%s:{w}%s' % (lname, str(locals[lname])))
                else:
                    ldisplay.append('{s}%s:%s' % (lname, str(locals[lname])))
            ldisplay = ' '.join(ldisplay)

            callinfo = self.cf.findStartOfCall(startStamp)
            print callinfo

            for line in lines:
                fmt = '{s}%-10.10s %4d: %s{n}%s{s}%s {.60}' + ldisplay
                pout(fmt, os.path.basename(line[0]), *line[1:])
                
                ldisplay = ''
                
            last_locals = locals
    
    def trace(self, function_names):
        func_name_to_addr = {}
        for func_name in function_names:
            func = self.cf.lookupGlobalFunction(func_name)
            self.trace_function(func)
            #self.cf.scanEnterSP(1388067, #func.beginTStamp,
            #                    func.endTStamp)
    
    def _formatValue(self, value):
        if type(value) == int:
            v = hex(value)
        elif isinstance(value, basestring):
            v = "'%s'" % value
        else:
            v = str(value)
        return v        
    
    def _formatParameters(self, parameters):
        str_parts = []
        for label, value in parameters:
            v = self._formatValue(value)
            str_parts.append('%s: %s' % (label, v))
    
        return ', '.join(str_parts)
    
    def trace_function(self, func):
        def helpy(beginTStamp, endTStamp, depth=1):
            # iterate over the calls found between the given start/end
            #  timestamps, which have been bounded to be inside our parent
            #  function...
            for (subBeginTStamp, subEndTStamp, subPreCallSP,
                 subStackEnd, thread) in self.cf.scanCallsBetweenTimes(beginTStamp,
                                                                       endTStamp):
                subfunc = self.cf.findRunningFunction(subBeginTStamp)
                if subfunc:
                    if subfunc.name in self.excluded_functions:
                        continue
                    
                    pc = self.cf.getPC(subBeginTStamp)
                    pout('{fn}%s {.20}{w}%s {.30}{n}%s', subfunc.name,
                         self._formatValue(self.cf.getReturnValue(subEndTStamp, subfunc)),
                         self._formatParameters(self.cf.getParameters(subBeginTStamp)),
                         )
                    pout.i(2)
                    if (not self.max_depth) or depth < self.max_depth:
                        helpy(subBeginTStamp, subEndTStamp, depth + 1)
                    #sline = self.cf.getSourceLineInfo(subBeginTStamp)
                    #if sline:
                    #    pout('{s}%s', self.cf.getSourceLines(sline))
                    pout.i(-2)
        
        # find all the times the function in question was executed
        for func, beginTStamp in self.cf.scanExecution(func):
            callInfo = self.cf.findStartOfCall(beginTStamp+1)
            endTStamp = self.cf.findEndOfCall(beginTStamp)
            #print 'BEGIN', beginTStamp, 'BOB', callInfo[0], 'END', endTStamp, 'BOB', callInfo[1]
            if callInfo:
                beginTStamp, endTStamp = callInfo[0:2]
            else:
                beginTStamp += 1
            #self.dump_stack(beginTStamp)
            pout('{fn}%s {.20}{w}%s {.30}{n}%s', func.name,
                 self._formatValue(self.cf.getReturnValue(endTStamp, func)),
                 self._formatParameters(self.cf.getParameters(beginTStamp)),
                 )
            pout.i(2)
            if self.max_depth != 1:
                helpy(beginTStamp, endTStamp)
            pout.i(-2)
            
    def dump_stack(self, tstamp, pre=8, post=8):
        mappy = {}
        for delta in range(-8, 8):
            rsp = self.cf.getSP(tstamp + delta)
            mappy.setdefault(rsp, []).append(delta)
        
        sp = self.cf.getSP(tstamp)
        for address in range(sp - pre*self.cf._ptr_size, sp + (pre+1)*self.cf._ptr_size, self.cf._ptr_size):
            val = self.cf.readInt(tstamp, address)
            if address == sp:
                pout('{g}%x %x {.20}%s', address, val, mappy.get(address))
            else:
                pout('{n}%x %x {.20}%s', address, val, mappy.get(address))
        
                
            
    def stop(self):
        self.cf.stop()

def main(args=None):
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
                       )
    oparser.add_option('-x', '--exclude-func',
                       dest='excluded_functions', action='append', type='str',
                       default=[],
                       help='Exclude functions from processing')
    oparser.add_option('-d', '--depth',
                       dest='depth', type='int',
                       default=0)
    
    oparser.add_option('--log',
                       action='store_true', dest='log', default=False,
                       help='Tell chronicle-query to log /tmp')
    oparser.add_option('-X', '--extreme-debug',
                       action='store_true', dest='extremeDebug', default=False,
                       help='like --log, but on the console and perhaps cooler')
    
    opts, args = oparser.parse_args(args)

    htmlfile = None
    if opts.html_filename:
        global pout
        import pyflam
        htmlfile = open(opts.html_filename, 'w')
        pout = pyflam.FlamHTML(htmlfile, style=opts.style)
        pout.write_html_intro('Chronisole Output')
    
    cs = Chronisole({'functions': opts.functions,
                     'excluded_functions': opts.excluded_functions,
                     'depth': opts.depth},
                    querylog=opts.log,
                    extremeDebug=opts.extremeDebug,
                    *args)
    cs.run()

    if htmlfile:
        pout.write_html_outro()
        htmlfile.close()
    
    cs.stop()

if __name__ == '__main__':
    main()
