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

import optparse

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
    def __init__(self, *args, **kwargs):
        self.cf = Chronifer(*args, **kwargs)
    
    def show(self, locals=True):
        last_locals = {}
        for startStamp, endStamp, sline in self.cf.scanBySourceLine():
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

            for line in lines:
                fmt = '{s}%4d: %s{n}%s{s}%s {.60}' + ldisplay
                pout(fmt, *line)
                
                ldisplay = ''
                
            last_locals = locals
            
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
    
    opts, args = oparser.parse_args(args)

    htmlfile = None
    if opts.html_filename:
        global pout
        import pyflam
        htmlfile = open(opts.html_filename, 'w')
        pout = pyflam.FlamHTML(htmlfile, style=opts.style)
        pout.write_html_intro('Chronisole Output')

    cs = Chronisole(*args)
    cs.show()

    if htmlfile:
        pout.write_html_outro()
        htmlfile.close()
    
    cs.stop()

if __name__ == '__main__':
    main()