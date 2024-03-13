import logging

import claripy
#
from angr.calling_conventions import SimRegArg, SimStackArg
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.code_location import ExternalCodeLocation

from argument_resolver.formatters.log_formatter import make_logger
from argument_resolver.handlers.base import HandlerBase
from argument_resolver.utils.calling_convention import cc_to_rd
from argument_resolver.utils.utils import Utils
from argument_resolver.utils.stored_function import StoredFunction
from argument_resolver.utils.transitive_closure import get_constant_data

from archinfo import Endness


class NVRAMHandlers(HandlerBase):
    """
    Handlers for NVRAM functions
        nvram_set, acosNvramConfig_set, nvram_get, nvram_safe_get, acosNvramConfig_get,
    """

    def _handle_nvram_set(
        self,
        state: "ReachingDefinitionsState",
        stored_func: StoredFunction,
    ):
        """
        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                      Code location of the call
        :param str handler_name:                     Name of the handler
        """
        self.log.debug("RDA: %s(), ins_addr=%#x", stored_func.name, stored_func.code_loc.ins_addr)
        # TODO
        return False, state, None

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_nvram_set(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            int nvram_set(const char *name, const char *value);

        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                      Code location of the call
        """
        return self._handle_nvram_set(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_SetValue(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            int nvram_set(const char *name, const char *value);

        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                      Code location of the call
        """
        return self._handle_nvram_set(state, stored_func)


    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_nvram_safe_set(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            int nvram_set(const char *name, const char *value);

        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                      Code location of the call
        """
        return self._handle_nvram_set(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_acosNvramConfig_set(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            int acosNvramConfig_set(const char *name, const char *value);

        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                       Code location of the call
        """
        return self._handle_nvram_set(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_wlcsm_nvram_set(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            int acosNvramConfig_set(const char *name, const char *value);

        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                       Code location of the call
        """
        return self._handle_nvram_set(
            state, stored_func
        )

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_envram_set(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            int acosNvramConfig_set(const char *name, const char *value);

        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                       Code location of the call
        """
        return self._handle_nvram_set(state, stored_func)


    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_bcm_nvram_set(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            int acosNvramConfig_set(const char *name, const char *value);

        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                       Code location of the call
        """
        return self._handle_nvram_set(state, stored_func)


    def _handle_nvram_get(
        self,
        state: "ReachingDefinitionsState",
        stored_func: StoredFunction,
    ):
        """
        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                       Code location of the call
        :param str handler_name:                      Name of the handler
        """
        self.log.debug("RDA: %s(), ins_addr=%#x", stored_func.name, stored_func.code_loc.ins_addr)

        default = False
        set_key = None
        cc = self._calling_convention_resolver.get_cc(stored_func.name)
        key_arg = cc.get_next_arg()
        key_ptr = Utils.get_values_from_cc_arg(key_arg, state, state.arch)
        key_ptr_definitions = LiveDefinitions.extract_defs_from_mv(key_ptr)
        keys = []
        default_values = {
            "ifname": b"wlan0",
            "netmask": b"0.0.0.0",
            "ipaddr": b"1.1.1.1",
            "last_auto_ip": b"2.2.2.2",
            "gateway": b"3.3.3.3",
            "PHYSDEVDRIVER": b"PHYSDEVDRIVER"
        }

        # Mark parameter as used.
        for def_ in key_ptr_definitions:
            state.add_use_by_def(def_, stored_func.code_loc)
            resolved_keys = get_constant_data(def_, key_ptr, state)
            if resolved_keys is None:
                resolved_keys = ["TOP"]
            keys.extend(Utils.bytes_from_int(x).decode() if isinstance(x, claripy.ast.Base) else "TOP" for x in resolved_keys)
        keys = [x[:-1] if x.endswith("\x00") else x for x in keys]

        if self.env_dict is None:
            default = True

        if "get" in stored_func.name:
            set_key = stored_func.name.replace("get", "set").replace("Get", "Set")
        elif "read" in stored_func.name:
            set_key = stored_func.name.replace("read", "write")

        out_mv = MultiValues()
        values = []
        found = False
        for key in keys:
            default_value = f"{stored_func.name}(\"{key}\")@{hex(stored_func.code_loc.ins_addr)}"
            for df, df_val in default_values.items():
                if df in key:
                    values.append(df_val)
                    found = True
                    break
            if not default and key in self.env_dict:
                if found:
                    continue
                if set_key in self.env_dict[key]:
                    key_vals = [y["value"] for x in self.env_dict[key][set_key].values() for y in x["values"] if y["pos"] == "1"]
                    for val in key_vals:
                        if val != "TOP":
                            values.append(val.encode())
                        else:
                            values.append(default_value)
                else:
                    values.append(default_value)
            else:
                values.append(default_value)

        if len(values) == 0:
            default_value = f"{stored_func.name}(\"TOP\")@{hex(stored_func.code_loc.ins_addr)}"
            values.append(default_value)

        for v in values:
            if isinstance(v, str):
                new_val = claripy.BVS(v, self.MAX_READ_SIZE*8, explicit_name=True)
                new_val.variables = frozenset(set(new_val.variables) | {"TOP"})
                out_mv.add_value(0, new_val)
                self.env_access.add(new_val)
            else:
                out_mv.add_value(0, claripy.BVV(v + b"\x00"))

        size = Utils.get_size_from_multivalue(out_mv)
        if stored_func.name in {"acosNvramConfig_read", "GetValue"}:
            arg_dst = cc.get_next_arg()
            dst_ptrs = Utils.get_values_from_cc_arg(arg_dst, state, state.arch)
            dst_valid_ptrs = [x for x in Utils.get_values_from_multivalues(dst_ptrs) if not state.is_top(x)]
            for dst_ptr in dst_valid_ptrs:
                sources = stored_func.atoms - {cc_to_rd(arg_dst, state.arch, state)}
                memloc = MemoryLocation(dst_ptr, size, endness=Endness.BE)
                stored_func.depends(memloc, *sources, value=out_mv)
            return True, state, None
        else:
            heap_addr = state.heap_allocator.allocate(size)
            memloc = MemoryLocation(heap_addr, size, endness=Endness.BE)
            stored_func.depends(memloc, value=out_mv, apply_at_callsite=True)
            heap_mv = MultiValues(Utils.gen_heap_address(heap_addr.value, state.arch))

            return True, state, heap_mv

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_nvram_get(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            char *nvram_get(const char *name);

        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                       Code location of the call
        """
        return self._handle_nvram_get(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_GetValue(
            self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            char *nvram_get(const char *name);

        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                       Code location of the call
        """
        return self._handle_nvram_get(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_nvram_safe_get(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            char *nvram_safe_get(const char *name);

        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                       Code location of the call
        """
        return self._handle_nvram_get(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_acosNvramConfig_get(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            char *acosNvramConfig_get(const char *name);

        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                       Code location of the call
        """
        return self._handle_nvram_get(state, stored_func)


    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_acosNvramConfig_read(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            char *acosNvramConfig_get(const char *name);

        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                       Code location of the call
        """
        return self._handle_nvram_get(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_bcm_nvram_get(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            char *acosNvramConfig_get(const char *name);

        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                       Code location of the call
        """
        return self._handle_nvram_get(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_envram_get(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            char *acosNvramConfig_get(const char *name);

        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                       Code location of the call
        """
        return self._handle_nvram_get(state, stored_func)

    @HandlerBase.returns
    @HandlerBase.tag_parameter_definitions
    def handle_wlcsm_nvram_get(
        self, state: "ReachingDefinitionsState", stored_func: StoredFunction
    ):
        """
        Process the impact of the function's execution on register and memory definitions and uses.

        .. sourcecode:: c

            char *acosNvramConfig_get(const char *name);

        :param ReachingDefinitionsState state:       Register and memory definitions and uses
        :param Codeloc codeloc:                       Code location of the call
        """
        return self._handle_nvram_get(state, stored_func)
