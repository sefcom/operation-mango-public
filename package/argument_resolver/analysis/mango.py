import subprocess

import time
import json

from pathlib import Path
from typing import Dict, Tuple, List

import networkx

from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions

from angr.analyses.reaching_definitions.reaching_definitions import (
    ReachingDefinitionsAnalysis,
)
from angr.code_location import ExternalCodeLocation
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag, ParameterTag
from angr.knowledge_plugins.key_definitions.atoms import Register

from argument_resolver.handlers.base import HandlerBase
from argument_resolver.handlers.local_handler import LocalHandler

from argument_resolver.utils.closure import Closure
from argument_resolver.utils.utils import Utils
from argument_resolver.utils.rank import get_rank

from argument_resolver.formatters.results_formatter import save_closure
from argument_resolver.analysis.base import ScriptBase, default_parser
from argument_resolver.external_function import (
    is_an_external_input_function,
)
from argument_resolver.external_function.sink import VULN_TYPES
from argument_resolver.external_function import KEY_BEACONS
from argument_resolver.utils.closure import SkeletonClosure


class MangoAnalysis(ScriptBase):
    def __init__(self, *args, **kwargs):
        self.concise = kwargs.pop("concise")
        super().__init__(*args, **kwargs)
        self.all_unresolved_closures = {}
        self.execv_dict = {}

    def save_results(self, check_if_sanitized=False):
        for sink, defn_dict in self.all_unresolved_closures.items():
            output = []
            for closures in defn_dict.values():
                for closure in closures.values():
                    output.extend(closure["output"])
            self.result_formatter.log_closures_for_sink(output, sink, self.log)
        self.save_results_to_file(None, None)

    @staticmethod
    def similar_closure(closure_1, closure_2) -> bool:
        if isinstance(closure_1, SkeletonClosure):
            code_loc_1 = closure_1.code_loc
        else:
            code_loc_1 = closure_1.sink_trace.code_loc

        if isinstance(closure_2, SkeletonClosure):
            code_loc_2 = closure_2.code_loc
        else:
            code_loc_2 = closure_2.sink_trace.code_loc

        return code_loc_1.ins_addr == code_loc_2.ins_addr

    @staticmethod
    def get_sources_from_closure(closure) -> Dict:
        sources = {"likely": {}, "possibly": {}, "tags": {}, "valid_funcs": set()}
        used_sources = {"likely": set(), "possibly": set()}
        for atom in closure.handler._sink_atoms:
            sink_str = Utils.get_strings_from_pointers(
                closure.sink_trace.arg_vals[atom],
                closure.sink_trace.state,
                closure.sink_trace.code_loc,
            )
            if "ARGV" in str(sink_str):
                sources["likely"]["ARGV"] = ['"ARGV"']
                used_sources["likely"].add("ARGV")

            for env_var in closure.handler.env_access | set(
                closure.handler.keyword_access
            ):
                name = env_var._encoded_name.decode("latin-1")
                key = name[name.find('"') + 1 : name.rfind('"')]
                if not key:
                    continue

                loc = name.rfind("@")
                if loc != -1:
                    under = name.find("_", loc)
                    if under != -1:
                        name = name[:under]
                if name in used_sources:
                    continue

                if key in str(sink_str) and key != "TOP":
                    if loc != -1:
                        addr = int(name[loc + 1 :].split("_")[0], 16)
                        sources["valid_funcs"].add(addr)
                    if key in sources["likely"]:
                        sources["likely"][key].append(name)
                    else:
                        sources["likely"][key] = [name]
                    used_sources["likely"].add(name)
                else:
                    if key in sources["possibly"]:
                        sources["possibly"][key].append(name)
                    else:
                        sources["possibly"][key] = [name]
                    used_sources["possibly"].add(name)

            # for keyword_var, keywords in closure.handler.keyword_access.items():

            for func, instances in closure.handler.fd_tracker.items():
                if isinstance(func, int):
                    continue
                for fd_dict in instances:
                    local_sources = []
                    input_name = fd_dict["val"]._encoded_name.decode("latin-1")
                    if '"' in input_name:
                        input_key = input_name[
                            input_name.find('"') + 1 : input_name.rfind('"')
                        ]
                        input_key = input_key.split(",")[0].strip().strip('"')
                    else:
                        l_paren = input_name.rfind("(")
                        l_paren = input_name[:l_paren].rfind("(")
                        r_paren = input_name.find(")")
                        r_paren += input_name[r_paren + 1 :].find(")")
                        input_key = input_name[l_paren + 1 : r_paren]

                    if input_key == input_name[:-1]:
                        input_key = input_name[
                            input_name.find("(") + 1 : input_name.rfind(")")
                        ]
                    loc = input_name.rfind("@")
                    if loc != -1:
                        under = input_name.find("_", loc)
                        if under != -1:
                            input_name = input_name[:under]

                    if input_name in used_sources:
                        continue
                    parents = fd_dict["parent"]
                    local_sources.append(str(input_name))
                    while parents is not None and len(parents) > 0:
                        parent = parents.pop()
                        if parent in closure.handler.fd_tracker:
                            name = closure.handler.fd_tracker[parent][
                                "val"
                            ]._encoded_name.decode("latin-1")
                            local_sources.insert(0, name)
                            if closure.handler.fd_tracker[parent]["parent"] is not None:
                                parents = (
                                    closure.handler.fd_tracker[parent]["parent"]
                                    + parents
                                )
                    if input_key in str(sink_str) and input_key != "<BV32 TOP>":
                        for f in local_sources:
                            loc = f.rfind("@")
                            if loc != -1:
                                addr = int(f[loc + 1 :].split("_")[0], 16)
                                sources["valid_funcs"].add(addr)
                        if input_key in sources["likely"]:
                            sources["likely"][input_key].append(local_sources[-1])
                        else:
                            sources["likely"][input_key] = local_sources
                        used_sources["likely"].add(input_name)
                    else:
                        if input_key in sources["possibly"]:
                            sources["possibly"][input_key].append(local_sources[-1])
                        else:
                            sources["possibly"][input_key] = local_sources
                        used_sources["possibly"].add(input_name)
        sources["tags"] = used_sources
        return sources

    def save_closure(self, sink, defn, closure):
        has_sinks = len(self.get_sink_callsites(self.sinks)) != 0
        if not has_sinks:
            self.log.critical("NO SINKS FOUND")

        analyzed_list = closure.handler.analyzed_list
        is_sanitized = False

        sources = self.get_sources_from_closure(closure)

        k = "likely" if sources["likely"] else "possibly"
        if sink in self.all_unresolved_closures:
            for defn, closures_dict in self.all_unresolved_closures[sink].items():
                for c, c_dict in [
                    (k, v)
                    for k, v in closures_dict.items()
                    if self.similar_closure(closure, k)
                ]:
                    input_keys = set(c_dict["external_input"]["sources"][k].keys())
                    input_keys.discard("ARGV")
                    if input_keys and input_keys <= set(sources[k]):
                        self.log.warning(
                            "Not Saving Closure, %s matches %s",
                            set(sources[k]),
                            input_keys,
                        )
                        return None

        possible_ranks = get_rank(sources["tags"]["possibly"])
        likely_ranks = get_rank(sources["tags"]["likely"])

        dict_keys = self.env_dict | self.keyword_dict

        for keyword in [s for s in sources["likely"] if s in dict_keys]:
            hit = False
            for rank in [r for r in likely_ranks if keyword in r]:
                hit = True
                likely_ranks[rank] *= 10
            if hit:
                break

        for beacon in [x for x in KEY_BEACONS if x in sources["likely"]]:
            hit = False
            for rank in [r for r in likely_ranks if beacon in r]:
                hit = True
                likely_ranks[rank] *= 10
            if hit:
                break

        rank = max(likely_ranks.values() or [0]) + max(possible_ranks.values() or [0])

        # if any("frontend_param" in y for x in sources["likely"].values() for y in x):
        #    rank = 7

        all_sources = {"sources": sources, "rank": rank}

        valid_closure = {
            "analyzed_list": analyzed_list,
            "sanitized": is_sanitized,
            "call_locs": closure.get_call_locations(),
            "external_input": all_sources,
            "sink_loc": closure.sink_trace.code_loc.ins_addr,
        }

        if (
            sink in self.all_unresolved_closures
            and defn in self.all_unresolved_closures[sink]
        ):
            for o_closure in self.all_unresolved_closures[sink][defn].values():
                if (
                    valid_closure["call_locs"] == o_closure["call_locs"]
                    and valid_closure["sink_loc"] == o_closure["sink_loc"]
                ):
                    return None

        output = self.result_formatter.format_unresolved_closures(
            Path(self.project.filename).name,
            closure,
            valid_closure,
            defn,
            self.find_default_excluded_functions(),
            all_sources,
            env_dict=self.env_dict,
            keyword_dict=self.keyword_dict,
            limit_output=self.concise,
        )
        self.result_formatter.log_closures_for_sink(output, sink, self.log)
        valid_closure["output"] = output
        del valid_closure["analyzed_list"]

        if sink not in self.all_unresolved_closures:
            self.all_unresolved_closures[sink] = {}

        if defn not in self.all_unresolved_closures[sink]:
            self.all_unresolved_closures[sink][defn] = {}

        self.all_unresolved_closures[sink][defn][
            SkeletonClosure(closure)
        ] = valid_closure

        self.analysis_time = time.time() - self.analysis_start_time
        self.save_results_to_file(closure, valid_closure)
        return all_sources

    def save_results_to_file(self, closure, closure_info):
        has_sinks = len(self.get_sink_callsites(self.sinks)) != 0
        if self.result_path is not None:
            self.result_path.mkdir(parents=True, exist_ok=True)

            save_closure(
                project=self.project,
                cfg_time=self.cfg_time,
                vra_time=self.vra_time,
                mango_time=self.analysis_time,
                closure=closure,
                closure_info=closure_info,
                execv_dict=self.execv_dict,
                result_path=self.result_path,
                time_data=self.time_data,
                total_sinks=self.sinks_found,
                has_sinks=has_sinks,
                category=self.category,
                sink_time=self.sink_time,
            )

    def post_analysis(
        self, dep: ReachingDefinitionsAnalysis, handler: HandlerBase
    ) -> bool:
        if dep is None:
            self.log.error("RDA Failed Due to Timeout")
            return False
        sink_function = self.project.kb.functions[handler._sink_function_addr]

        self.log.debug("Finding vulnerable sinks.")
        potential_sinks = self.vulnerable_sinks_from_call_trace(handler)
        self.log.info("Found %d potential sinks.", len(potential_sinks))

        unresolved_closures = self.trim_resolved_values(
            sink_function, dep, potential_sinks, handler
        )
        self.log.info(
            "Found %d unresolved vulnerable definitions.", len(unresolved_closures)
        )

        all_closures = set()
        input_locations = set()
        for defn, closures in unresolved_closures.items():
            for closure in closures:
                self.log.debug("Saving Closure: %s", closure)
                sources = self.save_closure(sink_function, defn, closure)
                if sources:
                    input_locations |= sources["sources"]["valid_funcs"]
                if sources is not None:
                    all_closures.add(closure)

        if input_locations:
            callsites = {x.caller_func_addr for x in dep.subject.content.callsites}
            remove_addrs = set()
            for addr in input_locations:
                if addr in callsites:
                    remove_addrs.add(addr)
                else:
                    depth = 2
                    prev_parent = None
                    while depth > 1:
                        idx, func = next(
                            iter(
                                (idx, x)
                                for idx, x in enumerate(handler.analyzed_list)
                                if x.code_loc.ins_addr == addr
                            )
                        )
                        parent_idx, parent = next(
                            iter(
                                (new_idx, x)
                                for new_idx, x in enumerate(
                                    reversed(handler.analyzed_list[:idx])
                                )
                                if x.depth < func.depth
                            )
                        )
                        depth = parent.depth
                        if prev_parent is not None and prev_parent.name == parent.name:
                            remove_addrs = callsites
                            break

                        prev_parent = parent
                        if parent.function.addr in callsites:
                            remove_addrs.add(parent.function.addr)
                            break
            if len(callsites - remove_addrs) > 0:
                final_callsite = None
                subj_callsites = dep.subject.content.callsites
                for rev_idx, callsite in enumerate(reversed(subj_callsites)):
                    if callsite.caller_func_addr not in remove_addrs:
                        final_callsite = tuple(
                            [
                                x.caller_func_addr
                                for x in reversed(subj_callsites[: rev_idx + 1])
                            ]
                            + [subj_callsites[0].callee_func_addr]
                        )
                    else:
                        break
                if (
                    sink_function in self.trace_dict
                    and final_callsite in self.trace_dict[sink_function]
                ):
                    self.log.warning(
                        "Found Unused Callsites: %s",
                        [hex(x) for x in callsites - remove_addrs],
                    )
                    self.log.warning("Setting parent to final")
                    if len(final_callsite) > 2:
                        final_callsite = final_callsite[1:]
                    self.trace_dict[sink_function][final_callsite]["final"] = True

        resolved = not self.contains_external(dep, unresolved_closures)

        for closure in all_closures:
            del closure.handler.analyzed_list[1:]
            closure.handler.call_trace.clear()
            closure.handler.call_stack.clear()

            closure.rda._function_handler = None
        return resolved

    @staticmethod
    def contains_external_input(closure: Closure):
        contains_external, valid_funcs, _ = MangoAnalysis.search_for_external_input(
            closure, closure.sink_trace
        )
        if (
            contains_external
            and valid_funcs
            and closure.handler.analyzed_list[0] not in valid_funcs
        ):
            caller_addrs = {
                x.caller_func_addr for x in closure.rda.subject.content.callsites
            }
            valid_funcs |= {
                x
                for x in closure.handler.analyzed_list
                if x.function.addr in caller_addrs
            }
            valid_funcs.add(closure.sink_trace)
            new_analyzed_list = [
                x for x in closure.handler.analyzed_list if x in valid_funcs
            ]
            return True, new_analyzed_list
        return False, closure.handler.analyzed_list

    def value_from_pointer_atoms(
        self, atoms: List["Atom"], state, code_loc
    ) -> Tuple[List[str], bool]:
        values = []
        contains_unresolved = False
        for atom in atoms:
            bv = Utils.get_bv_from_atom(atom, state.arch)
            strings = Utils.get_strings_from_pointer(bv, state, code_loc)
            for s in Utils.get_values_from_multivalues(strings):
                if s.concrete:
                    values.append(Utils.bytes_from_int(s).decode("latin-1"))
                else:
                    values.append(str(s))
                    contains_unresolved = True

        return values, contains_unresolved

    def handle_exec(self, closure: Closure):
        vals = closure.sink_trace.arg_vals[next(iter(closure.sink_trace.args_atoms[1]))]
        for pointer in Utils.get_values_from_multivalues(vals):
            try:
                sp = closure.sink_trace.state.get_sp()
            except AssertionError:
                sp = None
            if not Utils.is_pointer(pointer, sp, self.project):
                continue
            base_atom = closure.sink_trace.state.deref(
                pointer,
                closure.sink_trace.state.arch.bytes,
                endness=closure.sink_trace.state.arch.memory_endness,
            )
            args = {}
            vulnerable_args = []
            if closure.sink_trace.name.startswith("execv"):
                count = 0
                while count < 10:
                    pointer = closure.sink_trace.state.deref(
                        base_atom, closure.sink_trace.state.arch.bytes
                    )

                    if len(pointer) == 1 and next(iter(pointer)).addr == 0:
                        break

                    arg_strings, vulnerable = self.value_from_pointer_atoms(
                        pointer, closure.sink_trace.state, closure.sink_trace.code_loc
                    )
                    args[count] = arg_strings
                    if vulnerable:
                        vulnerable_args.append(count)
                    base_atom.addr.offset += closure.sink_trace.state.arch.bytes
                    count += 1
            elif closure.sink_trace.name.startswith("execl"):
                state = closure.sink_trace.state
                for idx, atoms in enumerate(closure.sink_trace.args_atoms[1:]):
                    arg_strings = []
                    vulnerable = False
                    for arg_atom in atoms:
                        pointer = state.deref(
                            arg_atom, closure.sink_trace.state.arch.bytes
                        )
                        values, vuln = self.value_from_pointer_atoms(
                            pointer, state, closure.sink_trace.code_loc
                        )
                        arg_strings.extend(values)
                        vulnerable |= vuln

                    args[idx] = arg_strings
                    if vulnerable:
                        vulnerable_args.append(idx)

            if len(vulnerable_args) > 0:
                for name in args[0]:
                    name = Path(name).name
                    if name not in self.execv_dict:
                        self.execv_dict[name] = []
                    self.execv_dict[name].append(
                        {
                            "args": args,
                            "vulnerable_args": vulnerable_args,
                            "addr": closure.sink_trace.code_loc.ins_addr,
                        }
                    )

    def trim_resolved_values(
        self, sink, dep, vulnerable_sinks, handler
    ) -> Dict[Definition, Tuple[networkx.DiGraph, LiveDefinitions, LocalHandler]]:
        # Get only the closures of the vulnerable atoms containing non-constant data.
        unresolved_closures: Dict[Definition] = {}
        for trace, defns in vulnerable_sinks.items():
            for atom in handler._sink_atoms:
                if atom not in trace.constant_data:
                    continue
                constant = trace.constant_data[atom] is not None and all(
                    d is not None for d in trace.constant_data[atom]
                )
                new_closure = Closure(trace, dep, handler)

                if (
                    constant
                    and sink.name.startswith("exec")
                    and sink.name != "execFormatCmd"
                ):
                    self.handle_exec(new_closure)

                for defn in sorted(
                    LiveDefinitions.extract_defs_from_mv(trace.arg_vals[atom]),
                    key=lambda x: (x.codeloc.ins_addr or x.codeloc.block_addr)
                    if x.codeloc
                    else 0,
                ):
                    if not constant:
                        if defn not in unresolved_closures:
                            unresolved_closures[defn] = set()
                        else:
                            for closure in unresolved_closures[defn].copy():
                                if closure < new_closure:
                                    unresolved_closures[defn].remove(closure)
                        if (
                            sink in self.all_unresolved_closures
                            and defn in self.all_unresolved_closures[sink]
                        ):
                            for closure in self.all_unresolved_closures[sink][
                                defn
                            ].copy():
                                if closure < new_closure:
                                    self.all_unresolved_closures[sink][defn].pop(
                                        closure
                                    )
                        if all(
                            y != new_closure
                            for x in unresolved_closures.values()
                            for y in x
                        ):
                            unresolved_closures[defn].add(new_closure)
                            break
                    else:
                        output, _ = self.result_formatter.log_function(trace)
                        self.log.info("[blue]Resolved call to %s:", sink.name)
                        for line in output:
                            self.log.info(line)
                        if sink not in self.all_unresolved_closures:
                            continue

                        if defn not in self.all_unresolved_closures[sink]:
                            continue

                        for closure in self.all_unresolved_closures[sink][defn].copy():
                            if closure < new_closure:
                                self.all_unresolved_closures[sink][defn].pop(closure)

        return unresolved_closures

    @staticmethod
    def search_for_external_input(
        closure, stored_func, valid_funcs=None, explored_funcs=None
    ):
        contains_external = False
        if valid_funcs is None:
            valid_funcs = set()

        if explored_funcs is None:
            explored_funcs = set()

        if stored_func in valid_funcs or stored_func in explored_funcs:
            return True, valid_funcs, explored_funcs

        explored_funcs.add(stored_func)
        if is_an_external_input_function(stored_func.name):
            valid_funcs.add(stored_func)
            return True, valid_funcs, explored_funcs

        parent_functions = set()
        for defn in {
            x
            for defn_set in stored_func.closures.values()
            for x in defn_set | stored_func.definitions | stored_func.return_definitions
        }:
            if not any(
                isinstance(tag, (ParameterTag, ReturnValueTag)) for tag in defn.tags
            ):
                continue

            if isinstance(defn.codeloc, ExternalCodeLocation):
                if (
                    not isinstance(defn.atom, Register)
                    or defn.atom.reg_offset != stored_func.state.arch.sp_offset
                ):
                    contains_external = True
                    valid_funcs.add(stored_func)
                    func_addrs = {
                        tag.function for tag in defn.tags if hasattr(tag, "function")
                    }
                    for func in closure.handler.analyzed_list:
                        if func.function.addr in func_addrs:
                            valid_funcs.add(func)
            else:
                func_idx = closure.handler.analyzed_list.index(stored_func)
                parent_functions |= {
                    x
                    for x in closure.handler.analyzed_list[:func_idx]
                    if defn in x.definitions | x.return_definitions
                }
                parent_functions.discard(closure.handler.analyzed_list[0])

        for func in parent_functions:
            ret = MangoAnalysis.search_for_external_input(
                closure, func, valid_funcs, explored_funcs
            )
            parent_contains_external, parent_valid_funcs, parent_explored = ret
            explored_funcs |= parent_explored
            if parent_contains_external:
                contains_external = True
                valid_funcs |= parent_valid_funcs
                valid_funcs.add(stored_func)

        return contains_external, valid_funcs, explored_funcs

    @staticmethod
    def merge_execve(directory: Path, result_path: Path):
        out_dict = {}
        execv_files = (
            subprocess.check_output(
                ["find", str(directory.resolve()), "-type", "f", "-name", "execv.json"]
            )
            .decode()
            .strip()
            .split("\n")
        )
        execv_files = [Path(x) for x in execv_files if Path(x).is_file()]
        if result_path in execv_files:
            execv_files.remove(result_path)

        for execv_file in execv_files:
            data = json.loads(execv_file.read_text())
            if not data:
                continue
            for bin_name, instances in data["execv"].items():
                if bin_name not in out_dict:
                    out_dict[bin_name] = {
                        "args": {},
                        "vulnerable_args": [],
                        "parent_bins": [],
                    }
                for val_dict in instances:
                    for pos, values in val_dict["args"].items():
                        if pos not in out_dict[bin_name]["args"]:
                            out_dict[bin_name]["args"][pos] = []
                        out_dict[bin_name]["args"][pos] = list(
                            set(out_dict[bin_name]["args"][pos] + values)
                        )

                    out_dict[bin_name]["vulnerable_args"] = list(
                        set(
                            out_dict[bin_name]["vulnerable_args"]
                            + val_dict["vulnerable_args"]
                        )
                    )
                    for x in out_dict[bin_name]["parent_bins"]:
                        if x["sha256"] == data["sha256"]:
                            x["addrs"] = list(set(x["addrs"] + [val_dict["addr"]]))
                            break
                    else:
                        out_dict[bin_name]["parent_bins"].append(
                            {
                                "name": data["name"],
                                "sha256": data["sha256"],
                                "addrs": [val_dict["addr"]],
                            }
                        )

        with result_path.open("w+") as f:
            json.dump(out_dict, f, indent=4)


def get_cli_args():
    parser, groups = default_parser()
    path_group, run_group, output_group = groups

    run_group.add_argument(
        "--arg",
        dest="arg_pos",
        default=0,
        type=int,
        help="The argument position in a sink function",
    )
    run_group.add_argument(
        "-c",
        "--category",
        dest="sink_category",
        default="cmdi",
        type=str,
        choices=list(VULN_TYPES.keys()),
        help="The category of sink to search for",
    )
    run_group.add_argument(
        "--sink",
        dest="sink",
        default="",
        type=str,
        help="Use the specified function sink",
    )

    run_group.add_argument(
        "--env-dict",
        dest="env_dict",
        default=None,
        help="Where to store the results of the analysis.",
    )

    run_group.add_argument(
        "--merge-execve",
        dest="merge",
        action="store_true",
        default=False,
        help="Merge all execv.json in a directory",
    )

    output_group.add_argument(
        "--concise",
        dest="concise",
        action="store_true",
        default=False,
        help="Speeds up overall analysis by outputting only the sink function",
    )

    parser.set_defaults(max_depth=7)
    return parser.parse_args()


def main():
    args = get_cli_args()
    if args.merge:
        MangoAnalysis.merge_execve(Path(args.bin_path), Path(args.result_path))
    else:
        args.__dict__.pop("merge")
        analyzer = MangoAnalysis(**args.__dict__)
        analyzer.analyze()


if __name__ == "__main__":
    main()
