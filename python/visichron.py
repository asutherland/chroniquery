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

import chronisole as csole
pout = csole.pout

class VFunc(object):
    def __init__(self, func):
        self.func = func
        self.name = func.name
        # invocations lists the times we were invoked.  for each invocation we have:
        #  
        #  start tick - the start time of our invocation
        #  end tick - the end time of our invocation (when we returned)
        #  call depth - how deep was the stack when we were called? (0 = we were the 'main')
        #  cflow - what is the summary value of our control flow graph traversal in that function
        #  cfuncs - sub invocations performed
        self.invocations = []
        self.ever_called = set()
    
    def invoke(self, stick, etick, call_depth, cflow=0):
        invocation = [self, stick, etick, call_depth, cflow, []]
        self.invocations.append(invocation)
        return invocation
    
    def update_invoc_cflow(self, invoc, cflow):
        invoc[4] = cflow
    
    def invoc_called(self, invoc, sinvoc):
        invoc[5].append(sinvoc)
        self.ever_called.add(sinvoc[0])
        
    def __str__(self):
        return ('function %s' % (self.name)) + (
                #'\n'.join(['   %03d-%03d (%02d) %s' % inv[1:5] for inv in self.invocations]))
                '\n'.join([' '.join(map(str,inv[1:5])) for inv in self.invocations])) 

class Visichron(csole.Chronisole):
    def __init__(self, *args, **kwargs):
        super(Visichron, self).__init__(*args, **kwargs)
        
        self._vfunc_map = {}
        self._cflows_seen = []
    
    def _get_vfunc(self, func):
        vfunc = self._vfunc_map.get(func.name)
        if vfunc is None:
            vfunc = VFunc(func)
            self._vfunc_map[func.name] = vfunc
        return vfunc
    
    def _determine_control_flow_id(self, func, beginTStamp, endTStamp, excl_ranges):
        '''
        The idea is to attempt to determine a unique identifier for the
        control flow path taken by this invocation of a function.  The proper
        way to do this is likely to defer to chronicle's query engine since
        it should know more about things happening at a basic block level.
        
        As a quick brittle hack/general proof-of-concept, we will just compute
        the instruction coverage of the execution path by cramming the
        instructions in a set and then providing id's based on equivalence.
        
        This should really exist on chronifer, but we'll delay the move
        until we have something less hideous.
        '''
        #return 1
    
        coverage = set()

        def scanit(bts, ets):
            for instr in self.cf.c.ssm('scan',
                               map='INSTR_EXEC',
                               beginTStamp=bts, endTStamp=ets,
                               ranges=func.ranges,
                               # no termination
                               ):
                if instr.get('type') == 'normal' and 'start' in instr:
                    coverage.add(instr['start'])
        
        nextStart = beginTStamp
        for excl_start, excl_stop in excl_ranges:
            scanit(nextStart, excl_start)
            nextStart = excl_stop
        if nextStart != endTStamp:
            scanit(nextStart, endTStamp)
        
        # okay, the coverage set now has the coverage, hooray.
        if coverage in self._cflows_seen:
            return self._cflows_seen.index(coverage)
        else:
            self._cflows_seen.append(coverage)
            return len(self._cflows_seen) - 1        

    
    def trace_function(self, func):
        def helpy(vfunc, invoc, beginTStamp, endTStamp, depth=1):
            sub_invoc_ranges = []
            
            # iterate over the calls found between the given start/end
            #  timestamps, which have been bounded to be inside our parent
            #  function...
            for (subBeginTStamp, subEndTStamp, subPreCallSP,
                 subStackEnd, thread) in self.cf.scanCallsBetweenTimes(beginTStamp,
                                                                       endTStamp):
                sub_invoc_ranges.append((subBeginTStamp, subEndTStamp))
                subfunc = self.cf.findRunningFunction(subBeginTStamp)
                if subfunc:
                    if subfunc.name in self.excluded_functions:
                        continue
                    
                    subvfunc = self._get_vfunc(subfunc)
                    
                    subinvoc = subvfunc.invoke(subBeginTStamp,
                                               subEndTStamp, depth)
                    
                    vfunc.invoc_called(invoc, subinvoc)
                    
                    ss_ranges = []
                    if (not self.max_depth) or depth < self.max_depth:
                        ss_ranges.extend(helpy(subvfunc, subinvoc,
                                               subBeginTStamp, subEndTStamp, depth + 1))
                    
                    cflow = self._determine_control_flow_id(subfunc,
                                                            subBeginTStamp,
                                                            subEndTStamp,
                                                            ss_ranges)
                    subvfunc.update_invoc_cflow(subinvoc, cflow)
            
            return sub_invoc_ranges
        
        vfunc = self._get_vfunc(func)
        # find all the times the function in question was executed
        for func, beginTStamp in self.cf.scanExecution(func):
            endTStamp = self.cf.findEndOfCall(beginTStamp)
            
            invoc = vfunc.invoke(beginTStamp, endTStamp, 0)
            
            sub_invoc_ranges = []
            if self.max_depth != 1:
                sub_invoc_ranges.extend(helpy(vfunc, invoc, beginTStamp, endTStamp))
            cflow = self._determine_control_flow_id(func,
                                                    beginTStamp, endTStamp,
                                                    sub_invoc_ranges)
            vfunc.update_invoc_cflow(invoc, cflow)
    
        self._vis_funcs(self._vfunc_map.values())

    def _vis_funcs(self, funcs):
        import visophyte.kora as kr
        import math

        layout = kr.map.Graphviz(nodeId=None,
                                 nodeEdges=kr.map.expr('ever_called'),
                                 #nodeEdges=kr.map.expr('invocations'),
                                 #edgeNode=kr.map.expr('0')
                                 )
        
        BLACK = kr.raw.color('black')
        
        circ = kr.vis.Circle(fill=kr.map.distinct_color(kr.map.expr('name'),
                                                        s=0.2),
                             stroke=BLACK, strokeWidth=1,
                             radius=24,
                             label=kr.map.expr('name'),
                             )
        
        map_time_angle = kr.map.linear(None,
                                       output_low=-math.pi/2,
                                       output_high=math.pi*3/2) 
        
        rings = kr.vis.Rings(circ,
                             data=kr.map.expr('invocations'),
                             radius=36,
                             thickness=kr.map.linear(kr.map.expr('3'),
                                                     output_low=16,
                                                     output_high=4),
                             startAng=map_time_angle(kr.map.expr('1')),
                             endAng=map_time_angle(kr.map.expr('2')),
                             fill=kr.map.distinct_color(kr.map.expr('4'),
                                                        s=0.6, v=0.9),
                             #stroke=BLACK,
                             stroke=kr.map.distinct_color(kr.map.expr('4'),
                                                        s=0.9, v=0.6),
                             )
        
        func_vis = rings
        
        graph_vis = kr.vis.Graphito(
                              nodes=kr.map.expr('@'),
                              y=layout.y,
                              x=layout.x,
                              nodeVis=func_vis,
                              lineColor=kr.map.distinct_color(kr.map.expr('name')),
                              #lineColor=kr.raw.color('black'),
                              nodeId=None,
                              nodeEdges=kr.map.expr('ever_called'),
                              #nodeEdges=kr.map.expr('invocations'),
                              #edgeNode=kr.map.expr('0')
                              )
        
        vis = kr.vis.Pad(graph_vis,
                         padLeft=15, padTop=15, padRight=15, padBottom=15)
        
        context = kr.feed.native(funcs).make_context()
        kr.render.contextualize(context, kr.themes.default)
        
        WIDTH, HEIGHT = 320, 320 # 640, 640
        model = vis.topRender(context,
                          width=WIDTH, height=HEIGHT,
                          )
        
        #print model
        
        kr.render.displayModel(model, width=WIDTH, height=HEIGHT)



if __name__ == '__main__':
    csole.main(None, Visichron)
