import logging
from .base import HandlerBase

from argument_resolver.formatters.log_formatter import make_logger


class StaticHandlers(HandlerBase):
    """
    Hanlders for functions that should return static values for our purposes:
        uname
    """

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_uname(self, state: "ReachingDefinitionsState", stored_func: "StoredFunction"):
        """
        Process the impact of the function's execution on register and memory definitions and uses.
        .. sourcecode:: c
            char *strcpy (char * dst, const char * src);
        """
        self.log.debug("RDA: %s(), ins_addr=%#x", stored_func.name, stored_func.code_loc.ins_addr)
        return False, state, None