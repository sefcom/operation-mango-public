import shlex

from angr import Project, PointerWrapper
from angr.knowledge_plugins.functions import Function
from angr.knowledge_plugins.key_definitions.atoms import SimStackArg


class ConcreteRunner:

    def __init__(self, project: Project, function: Function, vuln_pos: int, func_args):
        self.shell_string = b";;;; `echo 'Hello World!'`"
        pointer = PointerWrapper(self.shell_string, buffer=True)
        func_args[vuln_pos] = pointer
        vuln_reg = function.arguments[vuln_pos]

        self.function = function
        self.ret_addr = 0xffffffff
        self.init_state = project.factory.call_state(self.function.addr, *func_args, ret_addr=self.ret_addr, add_options={"ZERO_FILL_UNCONSTRAINED_MEMORY", "ZERO_FILL_UNCONSTRAINED_REGISTERS"})
        self.string_memloc = vuln_reg.get_value(self.init_state)
        self.sm = project.factory.simulation_manager(self.init_state)

    def check_if_escaped(self) -> bool:
        self.sm.explore(find=self.ret_addr)
        for state in self.sm.found:
            shell_string = state.memory.concrete_load(self.string_memloc, 800).tobytes().strip(b"\x00")
            if shell_string != self.shell_string and self.is_escaped(shell_string):
                return True

            reg_val = state.solver.eval(getattr(state.regs, self.function.calling_convention.RETURN_VAL.reg_name))
            shell_string = state.memory.concrete_load(reg_val, 800).tobytes().strip(b"\x00")
            if len(shell_string) >= len(self.shell_string) and shell_string != self.shell_string and self.is_escaped(shell_string):
                return True
        return False

    @staticmethod
    def is_escaped(string: bytes):
        lexed = list(shlex.shlex(string.decode()))
        if 'echo' not in lexed:
            # Probably format changed somehow
            return False
        elif ';' in lexed or '`' in lexed:
            return False
        return True
