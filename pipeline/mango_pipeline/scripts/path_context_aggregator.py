import subprocess
import json

import sys
import networkx as nx
import multiprocessing
import logging
import argparse
import pprint

from pathlib import Path

import angr
from rich.progress import track
from argument_resolver.external_function.sink import BUFFER_OVERFLOW_SINKS, COMMAND_INJECTION_SINKS

logging.getLogger('angr').setLevel('CRITICAL')

def get_path_contexts(context_args):
    target_folder, bin_path = context_args
    overflow_count = {}
    cmdi_count = {}
    if target_folder.exists():
        if (target_folder / "cmdi_results.json").exists():
            try:
                cmdi_data = json.loads((target_folder / "cmdi_results.json").read_text())
                if "sinks" in cmdi_data:
                    cmdi_count = cmdi_data["sinks"]
            except:
                pass
        if (target_folder / "overflow_results.json").exists():
            try:
                overflow_data = json.loads((target_folder / "overflow_results.json").read_text())
                if "sinks" in overflow_data:
                    overflow_count = overflow_data["sinks"]
            except:
                pass
    
    contexts = {}
    if not cmdi_count and not overflow_count:
        return contexts
    try:
        project = angr.Project(str(bin_path), auto_load_libs=False)
        cfg = project.analyses.CFGFast(normalize=True, data_references=True, show_progressbar=False)
        valid_sinks = [cfg.functions[x] for x in cmdi_count | overflow_count if x in cfg.functions]
        contexts = {k.name: {"paths": 0, "count": 0} for k in valid_sinks}
        contexts["cmdi"] = {"paths": 0, "count": sum(cmdi_count.values() or [0])}
        contexts["overflow"] = {"paths": 0, "count": sum(overflow_count.values() or [0])}
        for sink in valid_sinks:
            g = nx.dfs_tree(cfg.functions.callgraph.reverse(), source=sink.addr, depth_limit=7)
            leaf_nodes = {x for x in g.nodes() if g.out_degree(x) == 0}

            agg = "overflow" if sink.name == "strcpy" else "cmdi"
            if sink.name in cmdi_count:
                contexts[sink.name]["count"] += cmdi_count[sink.name]
            elif sink.name in overflow_count:
                contexts[sink.name]["count"] += overflow_count[sink.name]
            for node in leaf_nodes:
                paths = nx.all_simple_paths(cfg.functions.callgraph, node, sink.addr)
                total_paths = len(list(paths))
                contexts[sink.name]["paths"] += total_paths
                contexts[agg]["paths"] += total_paths

    except Exception as e:
        print(e)
    return contexts


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Angr Based Path Contex Aggregator')
    parser.add_argument('result_folder', type=str, help='Result Directory of Mango Analysis')
    parser.add_argument('--cores', type=int, default=int(multiprocessing.cpu_count() * 3 / 4), help="Amount of cores to dedicate to this (could take several hours)")
    args = parser.parse_args()
    vendor_file = json.loads(Path(args.result_folder + "/vendors.json").read_text())
    targets = set()
    for brand, firmwares in vendor_file.items():
        for firmware, vals in firmwares["firmware"].items():
            for sha, elf in vals["elfs"].items():
                targets.add((Path(args.result_folder) / brand / firmware / sha, Path(elf["path"])))
            
    context_counter = {}
    with multiprocessing.Pool(args.cores) as p:
        for res in track(p.imap_unordered(get_path_contexts, targets), total=len(targets), description="Running analysis..."):
            for key, values in res.items():
                if key not in context_counter:
                    context_counter[key] = {"paths": 0, "count": 0}
                context_counter[key]["paths"] += values["paths"]
                context_counter[key]["count"] += values["count"]
                pprint.pprint(context_counter, indent=4)

            with open("counter.agg", "w+") as f:
                json.dump(context_counter, f, indent=4)
    print("FINAL COUNTER:", context_counter)

