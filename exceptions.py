class IpFormatError(Exception):
    pass

class SheetNameNotFoundError(Exception):
    pass

class MaskFormatError(Exception):
    pass

class MaskValueError(Exception):
    pass

class NoExceptionError(Exception):
    pass

class NoCommentError(Exception):
    pass

class NoBoundaryError(Exception):
    pass

class NoCIDRError(Exception):
    pass

class NoActionError(Exception):
    pass

class NoIpBaseError(Exception):
    pass

class NoIpTopError(Exception):
    pass

class NotNetworkAdressError(Exception):
    pass

class WrongGroupDeleteError(Exception):
    pass

class WrongGroupConflictError(Exception):
    pass

class NoSALCodeError(Exception):
    pass

class CountryCodeError(Exception):
    pass