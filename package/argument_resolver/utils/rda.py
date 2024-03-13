import claripy
import logging
from pathlib import Path

from typing import Iterable

import pyvex

from angr.analyses.reaching_definitions.reaching_definitions import (
    ReachingDefinitionsAnalysis,
    ReachingDefinitionsState,
)
from angr.analyses.reaching_definitions.engine_vex import SimEngineRDVEX
from angr.knowledge_plugins.key_definitions.atoms import (
    Register,
    MemoryLocation,
    SpOffset,
)
from angr.calling_conventions import SimRegArg
from angr.code_location import CodeLocation
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

l = logging.getLogger(name=__name__)

from argument_resolver.utils.utils import Utils


class CustomRDA(ReachingDefinitionsAnalysis):
    timeout_set = False

    def __init__(
        self,
        *args,
        is_reanalysis=False,
        start_time=None,
        rda_timeout=None,
        prev_observed=None,
        **kwargs,
    ):
        self.prev_observed = prev_observed
        self.is_reanalysis = is_reanalysis
        self.start_time = start_time
        self.rda_timeout = rda_timeout
        super().__init__(*args, **kwargs)

    def _run_on_node(self, node, state: ReachingDefinitionsState):
        """

        :param node:    The current node.
        :param state:   The analysis state.
        :return:        A tuple: (reached fix-point, successor state)
        """
        if not isinstance(self._engine_vex, CustomVexEngine):
            # This is the first instance of the analysis
            self._engine_vex = CustomVexEngine(
                self.project,
                functions=self.kb.functions,
                function_handler=self._function_handler,
            )
            self.model.func_addr = (
                self.project.kb.cfgs.get_most_accurate()
                .get_any_node(node.addr)
                .function_address
            )

            if self.prev_observed:
                self.model.observed_results = self.prev_observed

            if node.addr in self.project.kb.functions and not self.is_reanalysis:
                if self._function_handler.current_parent is None:
                    if (
                        "main" in self.project.kb.functions
                        and node.addr == self.project.kb.functions["main"].addr
                    ):
                        state = self.taint_main_args(state)
                    state.codeloc = CodeLocation(block_addr=node.addr, stmt_idx=None)
                    self._engine_vex.state = state
                    self._engine_vex._handle_function(
                        MultiValues(claripy.BVV(node.addr, state.arch.bits))
                    )

                    stored_func = self._function_handler.call_trace[-1]
                    self._function_handler.analyzed_list = [stored_func]

                stored_func = self._function_handler.call_trace[-1]
                self._function_handler.call_stack.append(stored_func)
                self._function_handler.current_parent = stored_func
        res = super()._run_on_node(node, state)
        return res

    def taint_main_args(self, state):
        argc = claripy.BVS("ARGC", state.arch.bits, explicit_name=True)
        argv = claripy.BVS("ARGV", state.arch.bits, explicit_name=True)
        envp = claripy.BVS("ENVP", state.arch.bits, explicit_name=True)
        taints = [argc, argv, envp]
        main = self.project.kb.functions["main"]

        for idx, taint in enumerate(taints):
            if idx >= len(main.arguments):
                return state
            if not isinstance(main.arguments[idx], SimRegArg):
                raise ValueError("Expected Register Argument")
            reg_tup = state.arch.registers[main.arguments[idx].reg_name]
            if "ARGV" in taint.variables:
                argv_loc = 0xDEADC0DE
                arg_size = 0x100
                state.registers.store(
                    reg_tup[0],
                    state.stack_address(argv_loc),
                    endness=state.arch.memory_endness,
                )
                for loc in range(10):
                    arg_pointer = state.stack_address(argv_loc) + loc * state.arch.bytes
                    pointer_dst = state.stack_address(argv_loc) + (1 + loc) * arg_size
                    state.stack.store(
                        state.get_stack_address(arg_pointer),
                        pointer_dst,
                        endness=state.arch.memory_endness,
                    )
                    if loc == 0:
                        name = Path(self.project.filename).name.encode() + b"\x00"
                        memloc = MemoryLocation(
                            SpOffset(state.arch.bits, argv_loc + (1 + loc) * arg_size),
                            len(name),
                        )
                        state.kill_and_add_definition(
                            memloc, MultiValues(claripy.BVV(name, len(name) * 8))
                        )
                    else:
                        arg_str = f"ARGV_{loc}"
                        argv_val = claripy.BVS(
                            arg_str, state.arch.bits, explicit_name=True
                        )
                        argv_val.variables = frozenset(
                            set(argv_val.variables) | {"TOP"}
                        )
                        memloc = MemoryLocation(
                            SpOffset(state.arch.bits, argv_loc + (1 + loc) * arg_size),
                            argv_val.size() // 8,
                        )
                        state.kill_and_add_definition(memloc, MultiValues(argv_val))
            else:
                old_val = state.registers.load(*reg_tup)
                new_mv = MultiValues()
                for offset, val_set in old_val.items():
                    for val in val_set:
                        if taint.variables <= val.variables:
                            new_mv.add_value(offset, val)
                        else:
                            new_mv.add_value(offset, val + taint)
                state.registers.store(
                    reg_tup[0], new_mv, endness=state.arch.memory_endness
                )
        return state


class CustomVexEngine(SimEngineRDVEX):

    # Having a context for Codelocations makes the hash difficult to resolve for our purposes
    @property
    def _context(self) -> None:
        return None

    # Normal Guarded Load also loads the alt value, we don't care
    def _handle_LoadG(self, stmt):
        guard = self._expr(stmt.guard)
        guard_v = guard.one_value()

        if claripy.is_true(guard_v):
            # FIXME: full conversion support
            if stmt.cvt.find("Ident") < 0:
                l.warning("Unsupported conversion %s in LoadG.", stmt.cvt)
            load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)
            wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, load_expr)
            self._handle_WrTmp(wr_tmp_stmt)
        elif claripy.is_false(guard_v):
            wr_tmp_stmt = pyvex.stmt.WrTmp(stmt.dst, stmt.alt)
            self._handle_WrTmp(wr_tmp_stmt)
        else:
            if stmt.cvt.find("Ident") < 0:
                l.warning("Unsupported conversion %s in LoadG.", stmt.cvt)
            load_expr = pyvex.expr.Load(stmt.end, stmt.cvt_types[1], stmt.addr)

            load_expr_v = self._expr(load_expr)
            # alt_v = self._expr(stmt.alt)

            # data = load_expr_v.merge(alt_v)
            self._handle_WrTmpData(stmt.dst, load_expr_v)

    # Normal Guarded Store also stores the alt value
    # this sometimes messes up if alt-values are not intended for use so just ignore it to be safe.
    def _handle_StoreG(self, stmt: pyvex.IRStmt.StoreG):
        guard = self._expr(stmt.guard)
        guard_v = guard.one_value()

        if claripy.is_false(guard_v):
            return

        else:
            addr = self._expr(stmt.addr)
            if addr.count() == 1:
                addrs = next(iter(addr.values()))
                size = stmt.data.result_size(self.tyenv) // 8
                data = self._expr(stmt.data)
                self._store_core(addrs, size, data)

    # Merging these values often causes conflicting issues down the line so always take the true if unresolvable
    def _handle_ITE(self, expr: pyvex.IRExpr.ITE):
        cond = self._expr(expr.cond)
        cond_v = cond.one_value()
        iftrue = self._expr(expr.iftrue)
        iffalse = self._expr(expr.iffalse)

        if claripy.is_true(cond_v):
            return iftrue
        elif claripy.is_false(cond_v):
            return iffalse
        else:
            data = iftrue
            return data

    def _handle_Put(self, stmt):
        reg_offset: int = stmt.offset
        size: int = stmt.data.result_size(self.tyenv) // 8
        reg = Register(reg_offset, size, self.arch)
        data = self._expr(stmt.data)

        if self.arch.sp_offset == reg_offset and any(
            self.state.is_top(x) for x in next(iter(data.values()))
        ):
            old_sp = self.state.registers.load(self.arch.sp_offset, self.arch.bytes)
            if old_sp.one_value() is None:
                stripped_values_set = {
                    v._apply_to_annotations(lambda alist: None)
                    for v in next(iter(old_sp.values()))
                }

                annotations = []
                for v in stripped_values_set:
                    annotations += list(v.annotations)

                if len(stripped_values_set) > 1:
                    new_sp = next(iter(stripped_values_set))
                    if annotations:
                        new_sp = new_sp.annotate(*annotations)
                    data = MultiValues(new_sp)

                else:
                    offsets = {}
                    new_data = MultiValues()
                    for value in next(iter(data.values())):
                        stack_offset = self.state.get_stack_offset(value)
                        if stack_offset not in offsets:
                            offsets[stack_offset] = value - 0x30
                        else:
                            offsets[stack_offset].annotate(
                                *(
                                    list(offsets[stack_offset].annotations)
                                    + list(value.annotations)
                                )
                            )

                    for val in offsets.values():
                        new_data.add_value(0, val)
                    data = new_data
            else:
                data = MultiValues(old_sp.one_value() - 0x30)

        # special handling for references to heap or stack variables
        if data.count() == 1:
            for d in next(iter(data.values())):
                if self.state.is_heap_address(d):
                    heap_offset = self.state.get_heap_offset(d)
                    if heap_offset is not None:
                        self.state.add_heap_use(heap_offset, 1, "Iend_BE")
                elif self.state.is_stack_address(d):
                    stack_offset = self.state.get_stack_offset(d)
                    if stack_offset is not None:
                        self.state.add_stack_use(stack_offset, 1, "Iend_BE")

        if self.state.exit_observed and reg_offset == self.arch.sp_offset:
            return
        self.state.kill_and_add_definition(reg, data)

    # This is an attempt to preserve ARGV and ENVP context for readability
    def _load_core(
        self, addrs: Iterable[claripy.ast.Base], size: int, endness: str
    ) -> MultiValues:
        argv_list = []
        addrs = list(addrs)
        for addr in addrs:
            if "ARGV" in addr.variables or "ENVP" in addr.variables:
                argv_list.append(addr)
            if self.state.is_heap_address(addr):
                pass
        result = super()._load_core(addrs, size, endness)
        if argv_list:
            new_mv = MultiValues()
            for offset, values in result.items():
                for value in values:
                    if "TOP" in value.variables and argv_list:
                        new_mv.add_value(offset, argv_list.pop())
                    else:
                        new_mv.add_value(offset, value)
            return new_mv
        else:
            return result
