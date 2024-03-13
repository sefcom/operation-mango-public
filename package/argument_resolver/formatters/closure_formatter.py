import string
from argument_resolver.external_function.sink.sink_lists import (
    GETTER_SINKS,
    SETTER_SINKS,
)

from typing import List

from angr.knowledge_plugins.key_definitions.atoms import Atom, Register, SpOffset
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.live_definitions import (
    LiveDefinitions,
    DerefSize,
)

import claripy
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

from argument_resolver.formatters.log_formatter import CustomFormatter
from argument_resolver.utils.stored_function import StoredFunction
from argument_resolver.utils.utils import Utils
from argument_resolver.utils.call_trace import traces_to_sink
import re


class ClosureFormatter:
    def __init__(self, project, cc_resolver):
        self.project = project
        self.calling_convention_resolver = cc_resolver
        self.depth_colors = [
            CustomFormatter.grey,
            CustomFormatter.green,
            CustomFormatter.blue,
            CustomFormatter.yellow,
        ]
        self.func = None

    def log_function(
        self,
        stored_func: StoredFunction,
        target_atom: Atom = None,
        target_defn: Definition = None,
    ):
        reg_strs = []
        all_resolved = True
        depth = stored_func.depth

        function = stored_func.function
        call_insn = stored_func.code_loc.ins_addr or stored_func.code_loc.block_addr

        start = function.name + "("
        spacing = len(start)
        strs, resolved = self.args_to_str(
            stored_func, spacing, target_atom=target_atom, target_defn=target_defn
        )
        all_resolved &= resolved
        reg_strs.extend(strs)
        log_output = [start]
        for idx, reg_str in enumerate(reg_strs):
            log_output.append(
                reg_str + "," if idx != len(reg_str) - 1 or len(reg_strs) > 1 else ""
            )

        ret_str, _ = self.get_ret_str(stored_func)
        out_str = " " * spacing + f") @ {hex(call_insn)}"
        out_str += f" -> {ret_str}" if ret_str else ""
        log_output.append(out_str)
        depth_str = ""
        for i in range(depth - 1):
            depth_str += f"{self.depth_colors[i%len(self.depth_colors)]}|"
        if depth_str != "":
            depth_str += CustomFormatter.reset

        log_output = [depth_str + CustomFormatter.grey + x for x in log_output]
        return log_output, all_resolved

    def sort_args(self, arg):
        if isinstance(arg, Register):
            if self.func is not None:
                cc = self.func.function.calling_convention
                if cc is not None:
                    int_args = [
                        self.func.state.arch.registers[x.reg_name][0]
                        for x in cc.int_args
                    ]
                    return int_args.index(arg.reg_offset)

            return arg.reg_offset
        else:
            if isinstance(arg.addr, SpOffset):
                val = arg.addr.offset * -1
            else:
                val = arg.addr
            return 0x1000 + val

    def args_to_str(
        self, stored_func: StoredFunction, spacing: int, target_atom, target_defn
    ):
        reg_strs = []
        all_resolved = True
        self.func = stored_func
        for atom in sorted(stored_func.atoms, key=self.sort_args):
            if isinstance(atom, Register):
                if target_atom == atom:
                    reg_str = f"{CustomFormatter.reset}{CustomFormatter.blue}{stored_func.state.arch.register_names[atom.reg_offset]}{CustomFormatter.reset}: "
                else:
                    reg_str = (
                        f"{stored_func.state.arch.register_names[atom.reg_offset]}: "
                    )
            else:
                reg_str = f"{atom}: "

            if (
                target_defn is not None
                and isinstance(target_atom, Register)
                and target_atom != atom
            ):
                vals, resolved = self.format_multivalue_output(stored_func, atom)
            else:
                vals, resolved = self.format_multivalue_output(
                    stored_func, atom, target_defn=target_defn
                )
            if not resolved:
                all_resolved = False
            reg_str += " | ".join(
                val if isinstance(val, str) else val.decode("latin-1") for val in vals
            )
            reg_str = " " * spacing + reg_str
            reg_strs.append(reg_str)
        return reg_strs, all_resolved

    def get_ret_str(self, stored_func: StoredFunction):
        if (
            stored_func.function.prototype is None
            or stored_func.function.prototype.returnty is None
            or stored_func.ret_val is None
        ):
            return "", 0

        values = Utils.get_values_from_multivalues(stored_func.ret_val)
        ret_val = list(values) if len(values) > 1 else values[0]
        ret_str = f"{CustomFormatter.yellow}{ret_val}{CustomFormatter.reset}"
        length = len(str(ret_val))
        return ret_str, length

    @staticmethod
    def format_multivalue_output(stored_func, atom, target_defn=None):
        return_vals = []
        resolved = True
        mv = stored_func.arg_vals[atom]
        defns = list(LiveDefinitions.extract_defs_from_mv(mv))
        if len(defns) == 0:
            resolved = False
            return [str(x) for x in Utils.get_values_from_multivalues(mv)], resolved

        for defn in defns:
            new_mv = MultiValues()
            for offset, vals in mv.items():
                for val in vals:
                    val_defns = set(LiveDefinitions.extract_defs(val))
                    if defn not in val_defns:
                        continue
                    new_mv.add_value(offset, val)
            if atom not in stored_func.constant_data:
                constant_data = None
            else:
                constant_data = stored_func.constant_data[atom]

            if (
                0 in new_mv
                and constant_data is not None
                and all(x is not None for x in constant_data)
            ):
                pointer = new_mv.one_value()
                is_pointer = True
                try:
                    sp = Utils.get_sp(stored_func.state)
                except AssertionError:
                    sp = stored_func.state.arch.initial_sp
                if pointer is not None and not Utils.is_pointer(
                    pointer, sp, stored_func.state.analysis.project
                ):
                    is_pointer = False

                for value in constant_data:
                    str_bytes = Utils.bytes_from_int(value)
                    if all(
                        x in bytes(string.printable, "ascii") or x == 0
                        for x in str_bytes
                    ) and not all(x == 0 for x in str_bytes):
                        if is_pointer and pointer is not None:
                            output_str = str(pointer) + f' -> {CustomFormatter.green}"'
                        else:
                            output_str = '"'
                        output_str += (
                            str_bytes.decode("latin-1")
                            .replace("\n", "\\n")
                            .replace("\r", "\\r")
                        )
                        output_str += f'"{CustomFormatter.grey}'
                        return_vals.append(output_str)
                    else:
                        if is_pointer:
                            output_str = f"{pointer} -> {CustomFormatter.green}{value}{CustomFormatter.reset}{CustomFormatter.grey}"
                        else:
                            output_str = f"{pointer}"
                        return_vals.append(output_str)
            else:
                resolved = False

                for val in Utils.get_values_from_multivalues(mv):
                    if defn in {x for x in LiveDefinitions.extract_defs(val)}:
                        arg_str = str(val)
                        if stored_func.state.is_stack_address(val):
                            offset = stored_func.state.get_stack_offset(val)
                            if offset is None:
                                if hex(0xDEADC0DE) in str(val):
                                    arg_str = f"{CustomFormatter.light_blue}ARGV{CustomFormatter.reset}[?]"

                            elif offset < 0:
                                offset += 2**stored_func.state.arch.bits

                            if (
                                offset is not None
                                and 0xDEADC0DE < offset < 0xDEADC0DE + 0x100 * 11
                            ):
                                idx = (offset - 0xDEADC0DE) // 0x100
                                change = offset - (0xDEADC0DE + 0x100 * idx)
                                if change == 0:
                                    arg_str = f"{CustomFormatter.light_blue}ARGV{CustomFormatter.reset}[{idx - 1}]"
                                else:
                                    arg_str = f"{CustomFormatter.light_blue}ARGV{CustomFormatter.reset}[{idx - 1}] + {hex(change)}"

                                return_vals.append(arg_str)

                        if Utils.is_pointer(
                            val,
                            sp=stored_func.state.arch.initial_sp,
                            project=stored_func.state.analysis.project,
                        ):
                            symbolic_vals = Utils.get_strings_from_pointer(
                                val, stored_func.state, stored_func.code_loc
                            )

                            str_list = []
                            if symbolic_vals.count() > 5:
                                arg_str = str(symbolic_vals)
                            else:
                                for v in Utils.get_values_from_multivalues(
                                    symbolic_vals, pretty=True
                                ):
                                    if v.symbolic:
                                        if len(v.args) > 1:
                                            arg_list = ""
                                            if all(
                                                isinstance(arg, claripy.ast.Base)
                                                for arg in v.args
                                            ):
                                                for arg in v.args:
                                                    if arg.concrete:
                                                        arg_list += (
                                                            Utils.bytes_from_int(
                                                                arg
                                                            ).decode("latin-1")
                                                        )
                                                    else:
                                                        arg_list += str(arg)

                                            else:
                                                arg_list = str(v)
                                            str_list.append(arg_list)
                                        else:
                                            str_list.append(str(v))
                                    else:
                                        str_list.append(
                                            Utils.bytes_from_int(v).decode("latin-1")
                                        )

                            if str_list:
                                arg_str += (
                                    f" -> {CustomFormatter.blue}"
                                    + " | ".join('"' + x + '"' for x in str_list)
                                    + CustomFormatter.reset
                                )
                        elif not isinstance(val.args[0], str):
                            arg_str = (
                                '"'
                                + "".join(
                                    [
                                        Utils.bytes_from_int(x).decode("latin-1")
                                        if isinstance(x, claripy.ast.BV) and x.concrete
                                        else str(x)
                                        for x in val.args
                                    ]
                                )
                                + '"'
                            )

                        return_vals.append(arg_str)
        return set(return_vals), resolved

    @staticmethod
    def filter_trace(closure: "Closure") -> List[StoredFunction]:
        sink_closure_defns = {
            defn
            for atom in closure.handler._sink_atoms
            for defn in closure.sink_trace.closures[atom]
        }
        caller_addrs = {
            x.caller_func_addr for x in closure.rda.subject.content.callsites
        }
        trace_list = []
        for stored_func in closure.handler.analyzed_list[::-1]:
            if stored_func.function.addr in caller_addrs:
                trace_list.append(stored_func)
            elif any(
                defn in sink_closure_defns
                for defn in stored_func.definitions | stored_func.return_definitions
            ):
                trace_list.append(stored_func)
                sink_closure_defns |= {
                    defn for defns in stored_func.closures.values() for defn in defns
                }

        return trace_list[::-1]

    @staticmethod
    def strip_non_letters_from_ends(s):
        return re.sub(r"^[^a-zA-Z]+|[^a-zA-Z]+$", "", s)

    @staticmethod
    def get_value_from_env(key, func_name, env_dict, keyword_dict):
        func_name = (
            func_name.replace("get", "set")
            .replace("read", "write")
            .replace("Get", "Set")
        )
        sources = []
        if key == "ARGV":
            return sources
        elif key == "stdin":
            return sources

        bad_key = False
        if not env_dict or key not in env_dict or func_name not in env_dict[key]:
            bad_key = True
            if keyword_dict and key in keyword_dict:
                bad_key = False

        if bad_key:
            return ["Keywords: None", "UNKNOWN"]

        keywords = []
        values = []
        if (
            key in env_dict
            and func_name in env_dict[key]
            and func_name != "frontend_param"
        ):
            for bin_name, value_dict in env_dict[key][func_name].items():
                key_vals = [
                    f"{bin_name} - {func_name}({key})@{', '.join(val['locations'])}"
                    for val in value_dict["values"]
                    if val["value"] == "TOP"
                ]
                if key_vals:
                    keywords = list(set(keywords) | set(value_dict["keywords"]))
                    values.extend(key_vals)
        else:
            sources += [f"Keyword Source: {key} - {keyword_dict[key]}"]

        for keyword in keywords:
            if keyword in keyword_dict:
                sources += [f"Keyword Source: {keyword} - {keyword_dict[keyword]}"]
        # sources += [f"Keywords: {', '.join(keywords) if keywords else 'None'}"]
        sources.extend(values)
        return sources

    def get_source_from_env_dict(self, stored_func, env_dict, keyword_dict):
        sources = []
        key = set()

        if not env_dict:
            return sources, key

        setter_name = (
            stored_func.function.name.replace("get", "set")
            .replace("read", "write")
            .replace("Get", "Set")
        )
        if all(x.name != setter_name for x in SETTER_SINKS):
            return sources, key

        for atom, values in stored_func.constant_data.items():
            if values is None:
                continue
            for val in values:
                if val is None:
                    continue
                try:
                    val_string = Utils.bytes_from_int(val).decode()
                except UnicodeDecodeError:
                    continue

                key.add(val_string)
                sources.extend(
                    self.get_value_from_env(
                        val_string, setter_name, env_dict, keyword_dict
                    )
                )

        return sources, key

    def format_unresolved_closures(
        self,
        bin_name,
        closure,
        c_dict,
        defn,
        excluded_functions,
        input_sources,
        env_dict,
        keyword_dict,
        limit_output=False,
    ):
        output_list = []
        analyzed_list = c_dict["analyzed_list"]
        trace_output = []
        for stored_func in analyzed_list:
            if stored_func != closure.sink_trace:
                if limit_output:
                    continue
                output, all_resolved = self.log_function(stored_func)
                sources, key = self.get_source_from_env_dict(
                    stored_func, env_dict, keyword_dict
                )
                if sources:
                    pre_str = output[0][: output[0].index(stored_func.function.name)]
                    for source in sources[1:]:
                        output.insert(
                            0,
                            pre_str
                            + ClosureFormatter.set_line_color(
                                source, CustomFormatter.blue, 0
                            ),
                        )

                    output.insert(
                        0,
                        pre_str
                        + ClosureFormatter.set_line_color(
                            f"SOURCES: {key}", CustomFormatter.blue, 0
                        ),
                    )

            else:  # Found the sink
                output, all_resolved = self.log_function(stored_func, target_defn=defn)
                offset = output[0].find(stored_func.function.name)
                output = [
                    ClosureFormatter.set_line_color(
                        line, CustomFormatter.bold_red, offset
                    )
                    for line in output
                ]
                trace_output.append(output)
                break

            trace_output.append(output)

        trace_output.append(["", f"BINARY: {bin_name}", "INPUT SOURCES:"])
        likely_sources = input_sources["sources"]["likely"]
        possibly_sources = input_sources["sources"]["possibly"]
        if likely_sources or possibly_sources:
            input_strings = []
            input_strings.append("[bold purple]Likely:")
            if likely_sources:
                for key, group in likely_sources.items():
                    keys = key.strip('"').split(" | ")
                    func = group[-1].split("(")[0]
                    input_strings.append("[bold purple]" + "-" * 10)
                    input_strings.append("[bold purple]" + f'KEY: "{", ".join(keys)}"')
                    for sub_key in keys:
                        for idx, source in enumerate(
                            self.get_value_from_env(
                                sub_key, func, env_dict, keyword_dict
                            )
                        ):
                            if source.startswith("Key"):
                                input_strings.append(
                                    f"[bold purple]{source}"
                                    )
                            else:
                                input_strings.append(
                                    f"[bold purple]Binary Source: {source}"
                                )
                    input_strings.extend(
                        "[bold purple]" + f"Sink: {x}" for x in group
                    )
                    input_strings.append("[bold purple]" + "-" * 10)
            else:
                input_strings.append("[bold purple]" + "NONE")

            if not limit_output:
                input_strings.append("[bold #808080]Possibly:")
                if possibly_sources:
                    for key, group in possibly_sources.items():
                        keys = key.strip('"').split(" | ")
                        func = group[-1].split("(")[0]
                        input_strings.append("[bold #808080]" + "-" * 10)
                        input_strings.append(
                            "[bold #808080]" + f'KEY: "{", ".join(keys)}"'
                        )
                        for sub_key in keys:
                            for idx, source in enumerate(
                                self.get_value_from_env(
                                    sub_key, func, env_dict, keyword_dict
                                )
                            ):
                                if idx == 0:
                                    input_strings.append(f"[bold #808080]{source}")
                                else:
                                    input_strings.append(
                                        "[bold #808080]" + f"Binary Source - {source}"
                                    )
                        input_strings.extend("[bold #808080]" + x for x in group)
                        input_strings.append("[bold #808080]" + "-" * 10)
                else:
                    input_strings.append("[bold #808080]NONE")

            input_strings.append(
                CustomFormatter.yellow + f"RANK: {input_sources['rank']:.3f}"
            )
        else:
            input_strings = [CustomFormatter.bold_blue + "UNKNOWN"]
        trace_output.append(input_strings)
        output_list.append([y for x in trace_output for y in x])
        project = closure.rda.project
        if (
            "main" in project.kb.functions
            and closure.handler.analyzed_list[0].function.addr
            != project.kb.functions["main"].addr
        ):
            traces = traces_to_sink(
                closure.sink_trace.function,
                project.kb.functions.callgraph,
                max_depth=12,
                excluded_functions=excluded_functions,
            )
            traces = {
                t
                for t in traces
                if all(x in t.callsites for x in closure.rda.subject.content.callsites)
            }
            output_list[-1].insert(0, "^" * 50)
            for trace in traces:
                output_list[-1].insert(
                    0,
                    f"TRACE: {'->'.join(project.kb.functions[x.caller_func_addr].name for x in reversed(trace.callsites))}->{closure.sink_trace.function.name}",
                )

        return output_list

    @staticmethod
    def set_line_color(line: str, color, offset):
        if offset == 0:
            return color + line + CustomFormatter.reset
        else:
            reset = ""
            max_val = ""
            max_idx = 0
            for fmt_color in CustomFormatter.__dict__.values():
                if not isinstance(fmt_color, str):
                    continue
                color_idx = line.rfind(fmt_color, 0, offset)
                if color_idx > max_idx:
                    max_val = fmt_color
                    max_idx = color_idx
            if max_val != CustomFormatter.reset:
                reset = CustomFormatter.reset
            return line[:offset] + reset + color + line[offset:] + CustomFormatter.reset

    @staticmethod
    def log_closures_for_sink(output_list: List[List[str]], sink, logger):
        if output_list:
            logger.critical(CustomFormatter.bold_red + "*" * 50)
            logger.critical(
                "%sUNRESOLVED CLOSURES to %s: ", CustomFormatter.bold_red, sink.name
            )
        for output in output_list:
            logger.critical(CustomFormatter.bold_red + "-" * 50)
            for line in output:
                logger.critical(line)
