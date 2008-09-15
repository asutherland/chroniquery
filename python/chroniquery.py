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

# chronicle-recorder python interface

import subprocess, pprint, threading
import simplejson, sys, socket, os.path, os

class ChroniQuery(threading.Thread):
    NOTICE_COMPLETE  = 0
    NOTICE_STREAMING = 1
    
    def __init__(self, dbname, querylog=False, extremeDebug=False,
                 debugQuery=False):
        '''
        @param querylog: If provided, the name of a file to tell chronicle-query
            to log to.
        @param debugQuery: Instructs us to run 'chronicle' against
            chronicle-query.
        '''
        threading.Thread.__init__(self)
        
        self.setDaemon(True)
        
        self._spawn(dbname, querylog=querylog, debugQuery=debugQuery)
        
        # lock for everything before the next blank line
        self._reqmap_lock = threading.Lock()
        # request id one-up counter
        self._id = 0
        # maps requests to notification type (deprecated), notifier, results
        self._reqmap = {}
        
        self._async_lock = threading.Lock()
        self._async = []
        
        self._extremeDebug = extremeDebug
        
        self.start()
    
    def _pathfind(self, exename):
        if os.path.isabs(exename):
            return exename
        
        for part in os.environ['PATH'].split(':'):
            candidate = os.path.join(part, exename)
            if os.path.exists(candidate):
                return candidate
        
        raise Exception('Unable to locate "%s" on the path' % exename)
    
    def _spawn(self, dbname, querylog=False, debugQuery=False):
        # okay, we need to find chronicle-query on the path, and shell=True
        #  screws us for some reason...
        # broke-ass fallback...
        exename = self._pathfind('chronicle-query')
        args = [exename,
                '--db',
                dbname]
        
        if debugQuery:
            # user better have a chronicle script on their path
            args.insert(0, self._pathfind('chronicle'))
        
        if querylog:
            args.append('--log')
        self.child = subprocess.Popen(args,
                                      shell=False,
                                      stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE,
                                      stderr=sys.stderr,
                                      )
    
    def stop(self):
        self.child.stdin.close()
    
    def run(self):
        while self.child.poll() is None:
            line = self.child.stdout.readline()
            if self._extremeDebug:
                print 'LINE:', line,
            if line is None or len(line) == 0:
                return
            obj = simplejson.loads(line)
            
            # Is this something we asked for?
            if 'id' in obj: # Yes, it is.
                oid =  obj['id']
                terminated = 'terminated' in obj
                
                try:
                    self._reqmap_lock.acquire()
                    if oid in self._reqmap:
                        notice_type, cond, rlist = self._reqmap[oid]
                    else:
                        continue
                    
                    cond.acquire()
                    
                    rlist.append(obj)
                    if terminated:
                        rlist.append(None)
                    
                    cond.notify()
                    cond.release()
                finally:
                    self._reqmap_lock.release()
            # Asynchronous, unsolicited.
            else:
                try:
                    self._async_lock.acquire()
                    self._async.append(obj)
                finally:
                    self._async_lock.release()
    
    def getAsync(self):
        async = None
        try:
            self._async_lock.acquire()
            async = self._async
            self._async = []
            
            return async
        finally:
            self._async_lock.release()
        
        return []

    def _sendCommand(self, command_name, _stream=False, **kwargs):
        if self.child.returncode is not None:
            print 'uh-oh, child is angry!'
        
        cid, cond, rlist = None, None, []
        # not thread safe, clearly
        try:
            self._reqmap_lock.acquire()
            
            cid = self._id
            self._id += 1
            
            if _stream:
                notice_type = self.NOTICE_STREAMING
            else:
                notice_type = self.NOTICE_COMPLETE
            
            cond = threading.Condition()
            self._reqmap[cid] = (notice_type, cond, rlist)
        finally:
            self._reqmap_lock.release()

        # get any unicode out of our system...
        unsafe_args = kwargs
        kwargs = {}
        for key, val in unsafe_args.items():
            if type(key) == unicode:
                key = str(key)
            elif type(val) == unicode:
                val = str(val)
            kwargs[key] = val
        
        kwargs['id'] = cid
        kwargs['cmd'] = command_name
        
        
        json_data = simplejson.dumps(kwargs)
        if self._extremeDebug:
            print 'JSON:', json_data
        self.child.stdin.write(json_data + '\n')
        
        return cid, cond, rlist
    asc = _sendCommand
    
    def syncSendSingle(self, command_name, **kwargs):
        cid, cond, rlist = self._sendCommand(command_name, **kwargs)
        
        cond.acquire()
        while len(rlist) == 0 or rlist[-1] != None:
            cond.wait()
        cond.release()
        
        try:
            self._reqmap_lock.acquire()
            del self._reqmap[cid]
            return rlist[0]
        finally:
            self._reqmap_lock.release()
    sss = syncSendSingle
    
    def syncSendMulti(self, command_name, **kwargs):
        cid, cond, rlist = self._sendCommand(command_name, _stream=True,
                                             **kwargs)
        
        cond.acquire()
        while True:
            if not len(rlist):
                cond.wait()
            while len(rlist):
                val = rlist.pop(0)
                cond.release()
                if val is None:
                    self._reqmap_lock.acquire()
                    del self._reqmap[cid]
                    self._reqmap_lock.release()
                    return
                yield val
                cond.acquire()
    ssm = syncSendMulti
    
    def syncSendAll(self, command_name, **kwargs):
        return list(self.syncSendMulti(command_name, **kwargs))
    ssa = syncSendAll
