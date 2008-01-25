'''
Disassembly helper.
'''


class ChronDisNop(object):
    def __init__(self, bits):
        pass
    def dis(self, *args, **kwargs):
        return None

class ChronDisDistorm(object):
    def __init__(self, bits):
        if bits == 32:
            self._bitflag = distorm.Decode32Bits
        elif bits == 64:
            self._bitflag = distorm.Decode64Bits
    
    def dis(self, address, code):
         return distorm.Decode(address, code, self._bitflag)

try:
    import distorm
    ChronDis = ChronDisDistorm
except:
    ChronDis = ChronDisNop
