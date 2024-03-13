from .nvram import libnvram_decls
from .win32 import winreg_decls
from .custom import custom_decls

CUSTOM_DECLS = {**libnvram_decls, **winreg_decls, **custom_decls}
