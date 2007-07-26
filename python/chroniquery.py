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
    
    def __init__(self, dbname):
        threading.Thread.__init__(self)
        
        self._spawn(dbname)
        
        # lock for everything before the next blank line
        self._reqmap_lock = threading.Lock()
        # request id one-up counter
        self._id = 0
        # maps requests to conditions for notification
        self._reqmap = {}
        # maps requests to result objects
        self._resmap = {}
        
        self._async_lock = threading.Lock()
        self._async = []
        
        self._extremeDebug = False
        
        self.start()
    
    def _spawn(self, dbname):
        # okay, we need to find chronicle-query on the path, and shell=True
        #  screws us for some reason...
        # broke-ass fallback...
        exename = 'chronicle-query'
        for part in os.environ['PATH'].split(':'):
            candidate = os.path.join(part, 'chronicle-query')
            if os.path.exists(candidate):
                exename = candidate
                break
        args = [exename,
                '--db',
                dbname]
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
                        notice_type, cond = self._reqmap[oid]
                    else:
                        continue
                    
                    if oid in self._resmap or not terminated:
                        # implies multi
                        cond.acquire()
                        
                        rlist = self._resmap.get(oid)
                        if rlist is None:
                            rlist = []
                            self._resmap[oid] = rlist
                        
                        rlist.append(obj)
                    
                        if notice_type == self.NOTICE_STREAMING:
                            if terminated:
                                rlist.append(None)
                            cond.notify()
                        elif terminated:
                            cond.notify()
                        cond.release()
                        
                    else:
                        # one-shot, but everybody loves a list...
                        self._resmap[oid] = [obj]
                        
                        cond.acquire()
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
        
        cid, cond = None, None
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
            self._reqmap[cid] = (notice_type, cond)
        finally:
            self._reqmap_lock.release()
        
        kwargs['id'] = cid
        kwargs['cmd'] = command_name
        
        json_data = simplejson.dumps(kwargs)
        if self._extremeDebug:
            print 'JSON:', json_data
        self.child.stdin.write(json_data + '\n')
        
        return cid, cond
    asc = _sendCommand
    
    def syncSendSingle(self, command_name, **kwargs):
        cid, cond = self._sendCommand(command_name, **kwargs)
        
        cond.acquire()
        cond.wait()
        cond.release()
        
        try:
            self._reqmap_lock.acquire()
            
            obj = self._resmap[cid]
            del self._resmap[cid]
            
            return obj[0]
        finally:
            self._reqmap_lock.release()
    sss = syncSendSingle
    
    def syncSendMulti(self, command_name, **kwargs):
        cid, cond = self._sendCommand(command_name, _stream=True, **kwargs)
        
        rlist = None
        cond.acquire()
        while True:
            cond.wait()
            if rlist is None:
                self._reqmap_lock.acquire()
                rlist = self._resmap[cid]
                self._reqmap_lock.release()
            
            while len(rlist):
                val = rlist[0]
                del rlist[0]
                cond.release()
                if val is None:
                    self._reqmap_lock.acquire()
                    del self._resmap[cid]
                    self._reqmap_lock.release()
                    return
                yield val
                cond.acquire()
    ssm = syncSendMulti
    
    def syncSendAll(self, command_name, **kwargs):
        return list(self.syncSendMulti(command_name, **kwargs))
    ssa = syncSendAll
