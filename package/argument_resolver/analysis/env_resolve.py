import hashlib
import logging
import json
import subprocess

from pathlib import Path
from typing import Dict, List, Set

from angr.analyses.reaching_definitions import (
    LiveDefinitions,
    ReachingDefinitionsAnalysis,
)

from argument_resolver.formatters.log_formatter import make_logger
from argument_resolver.handlers.base import HandlerBase
from argument_resolver.utils.stored_function import StoredFunction

from argument_resolver.external_function.sink import ENV_SINKS, Sink
from argument_resolver.utils.transitive_closure import get_constant_data

from argument_resolver.utils.utils import Utils

from argument_resolver.analysis.base import default_parser, ScriptBase
from argument_resolver.utils.closure import Closure
import re


_l = make_logger()
_l.setLevel(logging.DEBUG)


# noinspection PyInterpreter
class EnvAnalysis(ScriptBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.resolved_values = {}

    @staticmethod
    def load_sinks(custom_sink=None, arg_pos=None, category=None) -> List[Sink]:
        return ENV_SINKS

    def load_excluded_functions(self, excluded_functions=None):
        excluded_functions = {}
        default_excluded_functions = self.find_default_excluded_functions()
        for f_sink in self.sinks:
            if f_sink.name not in self.project.kb.functions:
                continue
            sink_func = self.project.kb.functions[f_sink.name]
            excluded_functions[sink_func] = default_excluded_functions
        return excluded_functions

    @staticmethod
    def resolve_sinks(
        vulnerable_sinks: Set[StoredFunction],
    ) -> Dict[StoredFunction, Dict]:
        # Get only the closures of the vulnerable atoms containing non-constant data.
        resolved_dict = {}
        for trace in vulnerable_sinks:
            all_resolved = True
            resolved_dict[trace] = {}
            for arg, mv in trace.arg_vals.items():
                resolved_dict[trace][arg] = set()
                for defn in LiveDefinitions.extract_defs_from_mv(mv):
                    data = get_constant_data(defn, mv, trace.state)
                    resolved_dict[trace][arg].update(set(data) if data else {None})
                    if data is None or any(
                        x is None or trace.state.is_top(x) for x in data
                    ):
                        all_resolved = False
                        break
                if not all_resolved:
                    break
            resolved_dict[trace]["is_resolved"] = all_resolved

        return resolved_dict

    @staticmethod
    def strip_non_alphanumeric_from_ends(s):
        # Strip non-alphanumeric characters from the beginning and end of the string
        return re.sub(r"^[^a-zA-Z0-9]+|[^a-zA-Z0-9]+$", "", s)

    def post_analysis(self, dep: ReachingDefinitionsAnalysis, handler: HandlerBase):
        depth = len(dep.subject.content.callsites) if dep is not None else 1

        if depth not in self.resolved_values:
            self.resolved_values[depth] = {}

        # Relevant results are the `LiveDefinitions` captured at the `observation_points`.
        potential_sinks = self.vulnerable_sinks_from_call_trace(handler)
        sink_function = self.project.kb.functions[handler._sink_function_addr]
        if sink_function in self.trace_dict:
            for call_tup, trace_info in self.trace_dict[sink_function].items():
                if trace_info["constant"]:
                    potential_sinks.update(
                        {t_i: t_i.definitions for t_i in trace_info["constant"]}
                    )
                    self.trace_dict[sink_function][call_tup]["constant"] = set()
        _l.info("Found %d potential sinks.", len(potential_sinks))

        resolved_sinks: Dict[StoredFunction, Dict] = self.resolve_sinks(
            set(potential_sinks.keys())
        )

        self.save_results(resolved_sinks, handler=handler)
        # Change contains_external_definition
        if dep is not None:
            transitive_closures = {
                trace: {Closure(trace, dep, handler)}
                for trace, val_dict in resolved_sinks.items()
                if not val_dict["is_resolved"]
            }
            if (
                self.contains_external(dep, transitive_closures)
                or len(transitive_closures) == 0
            ):
                # fully resolved - we should exclude this function for future exploration
                return True

        return False

    def save_results(self, resolved_sinks=None, handler=None):
        self.save_resolved_values(resolved_sinks, handler)

    def save_resolved_values(self, resolved_sinks, handler):
        if resolved_sinks is None:
            return

        self.result_path.mkdir(parents=True, exist_ok=True)
        env_json = self.result_path / "env.json"
        if env_json.exists():
            prev_dict = json.loads(env_json.read_text())
            out_dict = prev_dict["results"]
        else:
            out_dict = {}
            prev_dict = {}

        has_sinks = len(self.get_sink_callsites(self.sinks)) != 0
        if not has_sinks:
            _l.critical("NO SINKS FOUND")

        curr_sink = None
        frontend_strs = {str(k): v for k, v in handler.keyword_access.items()}
        for sink, values in resolved_sinks.items():
            curr_sink = sink.name
            if sink.function.name not in out_dict:
                out_dict[sink.function.name] = {}
            keys = [
                Utils.bytes_from_int(val).decode("latin-1")
                if val is not None
                else "TOP"
                for atom in sink.args_atoms[0]
                for val in (sink.constant_data[atom] or [None])
            ]
            for key in [k for k in keys if len(k) > 1]:
                if key not in out_dict[sink.function.name]:
                    out_dict[sink.function.name][key] = {"keywords": []}

                if len(sink.args_atoms) > 1:
                    sink_atoms = sink.args_atoms[1:]
                else:
                    # This branch includes getenv first arg
                    sink_atoms = sink.args_atoms

                for idx, args in enumerate(sink_atoms):
                    idx = idx + 1
                    if idx not in out_dict[sink.function.name][key]:
                        out_dict[sink.function.name][key][idx] = {}
                    for arg in args:
                        if (
                            arg not in sink.constant_data
                            or sink.constant_data[arg] is None
                        ):
                            continue
                        for val in sink.constant_data[arg]:
                            if val is not None:
                                out_val = Utils.bytes_from_int(val).decode("latin-1")
                                out_val = (
                                    out_val[:-1]
                                    if out_val.endswith("\x00")
                                    else out_val
                                )
                            else:
                                out_val = "TOP"
                                if self.keyword_dict:
                                    strings = Utils.get_strings_from_pointers(
                                        sink.arg_vals[arg], sink.state, sink.code_loc
                                    )
                                    for string in Utils.get_values_from_multivalues(
                                        strings
                                    ):
                                        string_str = str(string)
                                        for k, v in frontend_strs.items():
                                            if k in string_str:
                                                out_dict[sink.function.name][key][
                                                    "keywords"
                                                ].extend(v)
                            self.log.info(
                                "Adding %s: %s @(%s)",
                                key,
                                out_val,
                                hex(sink.code_loc.ins_addr),
                            )
                            if out_val in out_dict[sink.function.name][key][idx]:
                                out_dict[sink.function.name][key][idx][out_val] = list(
                                    set(out_dict[sink.function.name][key][idx][out_val])
                                    | {hex(sink.code_loc.ins_addr)}
                                )
                            else:
                                out_dict[sink.function.name][key][idx][out_val] = [
                                    hex(sink.code_loc.ins_addr)
                                ]

        file = Path(self.project.filename)

        final_dict = {
            "results": out_dict,
            "name": file.name,
            "path": str(file),
            "error": None,
            "cfg_time": self.cfg_time,
            "vra_time": self.vra_time,
            "analysis_time": self.analysis_time,
            "has_sinks": has_sinks,
            "sink_times": {},
        }

        if not prev_dict:
            with file.open("rb") as f:
                final_dict["sha256"] = hashlib.file_digest(f, "sha256").hexdigest()
        else:
            final_dict["sha256"] = prev_dict["sha256"]
            if "sink_times" in prev_dict:
                final_dict["sink_times"] = prev_dict["sink_times"]
            else:
                final_dict["sink_times"][curr_sink] = self.sink_time

        if curr_sink is not None:
            final_dict["sink_times"][curr_sink] = self.sink_time

        with env_json.open("w+") as f:
            json.dump(final_dict, f, indent=4)

    @staticmethod
    def merge(directory: Path, result_path: Path):
        out_dict = {}
        env_files = (
            subprocess.check_output(
                ["find", str(directory.resolve()), "-type", "f", "-name", "env.json"]
            )
            .decode()
            .strip()
            .split("\n")
        )
        env_files = [Path(x) for x in env_files if Path(x).is_file()]
        if result_path in env_files:
            env_files.remove(result_path)

        for env_file in env_files:
            try:
                data = json.loads(env_file.read_text())
            except json.decoder.JSONDecodeError:
                continue

            if not data or "error" not in data or not isinstance(data["results"], dict):
                continue
            for sink, val_dict in data["results"].items():
                for key, values in val_dict.items():
                    if key not in out_dict:
                        out_dict[key] = {}
                    if sink not in out_dict[key]:
                        out_dict[key][sink] = {}
                    keywords = values.pop("keywords")
                    if data["name"] not in out_dict[key][sink]:
                        out_dict[key][sink][data["name"]] = {
                            "keywords": keywords,
                            "sha256": data["sha256"],
                            "values": [],
                        }
                    out_dict[key][sink][data["name"]]["keywords"] = list(
                        set(keywords)
                        | set(out_dict[key][sink][data["name"]]["keywords"])
                    )
                    for position, arg_vals in values.items():
                        for val, code_loc in arg_vals.items():
                            locations = [
                                hex(x) if isinstance(x, int) else x for x in code_loc
                            ]
                            if val == "":
                                val = "TOP"
                            val_dict = {
                                "value": val,
                                "locations": locations,
                                "pos": position,
                            }
                            out_dict[key][sink][data["name"]]["values"].append(val_dict)

        with result_path.open("w+") as f:
            json.dump(out_dict, f, indent=4)


def get_cli_args():
    parser, groups = default_parser()
    path_group, run_group, output_group = groups

    run_group.add_argument(
        "--merge",
        dest="merge",
        action="store_true",
        default=False,
        help="Merge all env.json in a directory",
    )

    parser.set_defaults(max_depth=2, result_path="results")

    return parser.parse_args()


def main():
    args = get_cli_args()
    if not args.merge:
        args.__dict__.pop("merge")
        analyzer = EnvAnalysis(**args.__dict__)
        analyzer.analyze()
    else:
        EnvAnalysis.merge(Path(args.bin_path), Path(args.result_path))


if __name__ == "__main__":
    main()
