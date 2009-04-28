#
# pretty printers...
#

import chronifer
import re

class BasePrettier(object):
    basetype = None
    typepattern = None
    def __init__(self, cf):
        self.cf = cf

    def is_exceptional(self, val):
        return False

class nsCOMPtrPrettier(BasePrettier):
    typename = None
    basetype = 'nsCOMPtr'
    typepattern = re.compile('nsCOMPtr<[^>]+>')

    def to_better_rep(self, tstamp, val):
        return val['mRawPtr']

class nsStringPrettier(BasePrettier):
    typename = 'nsString'

    def to_better_rep(self, tstamp, val):
        if val['mData'] == 0:
            return None
        if val['mLength'] == 0:
            return "''"
        return self.cf.readPascalUniString(tstamp,
                                           val['mData'],
                                           val['mLength'])

class nsCStringPrettier(BasePrettier):
    typename = 'nsCString'

    def to_better_rep(self, tstamp, val):
        if val['mData'] == 0:
            return None
        if val['mLength'] == 0:
            return "''"
        return self.cf.readPascalUtf8String(tstamp,
                                            val['mData'],
                                            val['mLength'])

class nsresultPrettier(BasePrettier):
    typename = 'nsresult'

    # this is more a proof of concept than anything...
    ERROR_MAP = {
        0xC1F30000L: 'NS_ERROR_BASE',
        0xC1F30001L: 'NS_ERROR_NOT_INITIALIZED',
        0xC1F30002L: 'NS_ERROR_ALREADY_INITIALIZED',
        0x80004001L: 'NS_ERROR_NOT_IMPLEMENTED',
        0x80004002L: 'NS_ERROR_NO_INTERFACE',
        0x80004003L: 'NS_ERROR_INVALID_POINTER',
        0x80004004L: 'NS_ERROR_ABORT',
        0x80004005L: 'NS_ERROR_FAILURE',
        0x8000ffffL: 'NS_ERROR_UNEXPECTED',
        0x8007000eL: 'NS_ERROR_OUT_OF_MEMORY',
        0x80070057L: 'NS_ERROR_ILLEGAL_VALUE',
        0x80040110L: 'NS_ERROR_NO_AGGREGATION',
        0x80040111L: 'NS_ERROR_NOT_AVAILABLE',
        }

    def to_better_rep(self, tstamp, val):
        if val in self.ERROR_MAP:
            return self.ERROR_MAP[val]
        return val

    def is_exceptional(self, val):
        return val & 0x80000000L

chronifer.PrettierRegistry.register_prettiers('mozilla',
    [nsCOMPtrPrettier,
     nsStringPrettier, nsCStringPrettier,
     nsresultPrettier])
