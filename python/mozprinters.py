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
        # MAILNEWS module
        0x80550005L: 'NS_MSG_ERROR_FOLDER_SUMMARY_OUT_OF_DATE',
        0x80550006L: 'NS_MSG_ERROR_FOLDER_SUMMARY_MISSING',
        0x80550007L: 'NS_MSG_ERROR_FOLDER_MISSING',
        0x80550008L: 'NS_MSG_MESSAGE_NOT_FOUND',
        0x80550009L: 'NS_MSG_NOT_A_MAIL_FOLDER',
        0x8055000aL: 'NS_MSG_FOLDER_BUSY',
        0x8055000bL: 'NS_MSG_COULD_NOT_CREATE_DIRECTORY',
        0x8055000cL: 'NS_MSG_CANT_CREATE_FOLDER',
        0x8055000dL: 'NS_MSG_FILTER_PARSE_ERROR',
        0x8055000eL: 'NS_MSG_FOLDER_UNREADABLE',
        0x8055000fL: 'NS_MSG_ERROR_WRITING_MAIL_FOLDER',
        0x80550010L: 'NS_MSG_ERROR_NO_SEARCH_VALUES',
        0x80550011L: 'NS_MSG_ERROR_INVALID_SEARCH_SCOPE',
        0x80550012L: 'NS_MSG_ERROR_INVALID_SEARCH_TERM',
        0x80550013L: 'NS_MSG_FOLDER_EXISTS',
        0x80550014L: 'NS_MSG_ERROR_OFFLINE',
        0x80550015L: 'NS_MSG_POP_FILTER_TARGET_ERROR',
        0x80550016L: 'NS_MSG_INVALID_OR_MISSING_SERVER',
        0x80550017L: 'NS_MSG_SERVER_USERNAME_MISSING',
        0x80550018L: 'NS_MSG_INVALID_DBVIEW_INDEX',
        0x80550019L: 'NS_MSG_NEWS_ARTICLE_NOT_FOUND',
        0x8055001aL: 'NS_MSG_ERROR_COPY_FOLDER_ABORTED',
        0x8055001bL: 'NS_MSG_ERROR_URL_ABORTED',
        0x8055001cL: 'NS_MSG_CUSTOM_HEADERS_OVERFLOW',
        0x8055001dL: 'NS_MSG_INVALID_CUSTOM_HEADER',
        0x8055001eL: 'NS_MSG_USER_NOT_AUTHENTICATED',
        0x8055001fL: 'NS_MSG_ERROR_COPYING_FROM_TMP_DOWNLOAD',
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
