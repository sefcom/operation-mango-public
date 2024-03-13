import hashlib
import json
import os
import pickle
import re
from pathlib import Path
from typing import Dict, Set, Tuple

import networkx
from networkx.drawing.nx_agraph import write_dot
from networkx.exception import NetworkXNoPath
from rich.console import Console

import angr
from angr.code_location import ExternalCodeLocation
from angr.knowledge_plugins.functions.function import Function
from angr.knowledge_plugins.key_definitions.atoms import Register
from angr.knowledge_plugins.key_definitions.definition import Definition
from argument_resolver.utils.closure import Closure
from argument_resolver.utils.stored_function import StoredFunction


def save_closure(
    project: angr.Project,
    cfg_time: float,
    vra_time: float,
    mango_time: float,
    closure: Closure,
    closure_info: Dict,
    execv_dict: Dict,
    result_path: Path,
    time_data: Dict[Tuple[int], Dict[str, float]],
    total_sinks=None,
    has_sinks=True,
    sink_time=0,
    category=None,
):
    res_name = f"{category}_results.json" if category is not None else "results.json"
    result_file = result_path / res_name

    file = Path(project.filename)

    if result_file.exists():
        closure_dict = json.loads(result_file.read_text())
    else:
        with file.open("rb") as f:
            sha_sum = hashlib.file_digest(f, "sha256").hexdigest()

        closure_dict = {
            "closures": [],
            "cfg_time": cfg_time,
            "vra_time": vra_time,
            "path": str(file.absolute()),
            "name": file.name,
            "has_sinks": has_sinks,
            "sha256": sha_sum,
            "sink_times": {},
            "error": None,
        }

    closure_dict["mango_time"] = (
        sum(mango_time) if isinstance(mango_time, list) else mango_time
    )
    closure_dict["sinks"] = total_sinks
    curr_sink = None
    if closure is not None and closure_info is not None:
        curr_sink = closure.sink_trace.name
        c_d = closure_to_dict(closure, closure_info["external_input"])
        closure_dict["closures"].append(c_d)
        closure_dir = result_path / f"{category}_closures"
        closure_dir.mkdir(parents=True, exist_ok=True)
        parent_func = closure.handler.analyzed_list[0].name
        parent_addr = hex(closure.handler.analyzed_list[0].code_loc.block_addr)
        sink_addr = hex(closure.sink_trace.code_loc.ins_addr)
        file_name = (
            closure_dir
            / f"{c_d['rank']:.2f}_{parent_func}_{parent_addr}_{closure.sink_trace.name}_{sink_addr}"
        )
        console = Console(file=open(file_name, "w+"), force_terminal=True)
        closure_dict["closures"][-1]["reachable_from_main"] = (
            closure.handler.analyzed_list[0].name == "main"
        )
        closure_dict["closures"][-1]["sanitized"] = closure_info["sanitized"]
        if (
            "main" in project.kb.functions
            and closure.handler.analyzed_list[0].name != "main"
        ):
            try:
                path = networkx.shortest_path(
                    project.kb.callgraph,
                    project.kb.functions["main"].addr,
                    closure.handler.analyzed_list[0].function.addr,
                )
                closure_dict["closures"][-1]["reachable_from_main"] = True
                console.print(
                    "->".join(
                        project.kb.functions[x].name
                        for x in path
                        + [
                            x.caller_func_addr
                            for x in closure.rda.subject.content.callsites
                        ]
                    )
                    + "->"
                    + closure.sink_trace.name
                )
                console.print("-" * 50 + "\n")
            except NetworkXNoPath:
                closure_dict["closures"][-1]["reachable_from_main"] = False
        for chunk in closure_info["output"]:
            for line in chunk:
                console.print(line)

        console.file.close()

    closure_dict["time_data"] = {
        " -> ".join(hex(x) for x in k): v for k, v in time_data.items()
    }
    if curr_sink is not None:
        if "sink_times" not in closure_dict:
            closure_dict["sink_times"] = {}
        closure_dict["sink_times"][curr_sink] = sink_time

    with open(result_file, "w+") as f:
        json.dump(closure_dict, f, indent=4)
    os.chmod(result_file, 0o666)

    if category == "cmdi":
        with open(result_path / "execv.json", "w+") as f:
            json.dump(
                {
                    "execv": execv_dict,
                    "name": file.name,
                    "sha256": closure_dict["sha256"],
                },
                f,
                indent=4,
            )


def closure_to_dict(closure: Closure, input_sources):
    caller_addrs = {x.caller_func_addr for x in closure.rda.subject.content.callsites}
    subject_funcs = [
        stored_func
        for stored_func in closure.handler.analyzed_list
        if stored_func.function.addr in caller_addrs
    ]
    sink = closure.sink_trace
    trace = [_stored_func_to_dict(stored_func) for stored_func in subject_funcs]

    closure_dict = {
        "trace": trace,
        "sink": _stored_func_to_dict(sink),
        "depth": sink.depth - 1,
        "inputs": {k: list(v) for k, v in input_sources["sources"].items()},
        "rank": input_sources["rank"],
    }
    return closure_dict


def _stored_func_to_dict(stored_func: StoredFunction):
    return {
        "function": stored_func.function.name,
        "string": str(stored_func),
        "ins_addr": hex(
            stored_func.code_loc.ins_addr or stored_func.code_loc.block_addr
        ),
    }


def save_graph(graph: networkx.DiGraph, filename: str, result_path: Path):
    """
    Save a graph on disk under two representations: serialized, and as an image.
    """
    path_and_filename = str(result_path / filename)

    with open(f"{path_and_filename}.pickle", "wb") as result_file:
        pickle.dump(graph, result_file)

    write_dot(graph, f"{path_and_filename}.dot")
    os.system(f"dot -Tsvg -o {path_and_filename}.svg {path_and_filename}.dot")
