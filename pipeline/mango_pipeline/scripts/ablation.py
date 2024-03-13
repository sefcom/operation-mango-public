import argparse
import subprocess
import json
import statistics
import subprocess
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Tuple
from functools import reduce

from rich.console import Console
from rich.table import Table, Column

from pathlib import Path


@dataclass
class AblationInfo:
    path: Path
    assumed_execution: bool
    reverse_trace: bool
    timeouts: int
    errors: int
    average_time: float
    total_time: float
    alerts: int = 0
    oom: int = 0
    analysis_times: Dict[str, Tuple[int, int, int]] = None
    closures: dict = None
    trupocs: int = 0
    desc: str = ""
    invalid_shas: list = None

    def sort_score(self):
        if self.assumed_execution and self.reverse_trace:
            score = 0
        elif self.assumed_execution:
            score = 1
        elif self.reverse_trace:
            score = 2
        else:
            score = 3
        return score

    def get_files(self, firmware: Path, filename: str):
        all_files = subprocess.check_output(["find", firmware, "-type", "f", "-name", filename]).strip().decode().split("\n")
        return {Path(x) for x in all_files}

    def get_time_data(self, f: Path):
        data = json.loads(f.read_text())
        if data["error"] is not None and data["ret_code"] == 124:
            if "sinks" in data:
                return sum(data["sinks"].values())
            return 40*60

        if "cfg_time" not in data or data["cfg_time"] is None:
            return 0

        if "mango_time" in data:
            if isinstance(data["mango_time"], list):
                t = sum(data["mango_time"])
            else:
                t = data["mango_time"]
            if t == 0 and data["has_sinks"]:
                t = sum(data["sinks"])
            return sum([data["cfg_time"], data["vra_time"], t])
        else:
            return sum([data["cfg_time"], data["vra_time"], data["analysis_time"]])

    def get_run_time(self):
        files = self.get_files(self.path, "cmdi_results.json")
        result_files = {f.parent.name: self.get_time_data(f) for f in files}
        result_files = {k: v for k, v in result_files.items() if v != 0}

        for f in files:
            data = json.loads(f.read_text())
            if data["error"] is not None:
                if data["ret_code"] == 124:
                    self.timeouts += 1
                elif data["ret_code"] == -9:
                    self.oom += 1
                else:
                    self.errors += 1

        self.files = files
        self.analysis_times = result_files
        self.closures = {f.parent.name: json.loads(f.read_text())["closures"] for f in files}
        #self.timeouts = errors["timeout"]
        #self.errors = errors["early_termination"]
        #self.oom = errors["OOMKILLED"]
        self.alerts = sum(len(v) for v in self.closures.values())
        self.total_time = sum(self.analysis_times.values()) + (40*60*self.timeouts)
        self.average_time = (self.total_time / len(self.analysis_times))# if len(self.analysis_times) != 0 else -1
        self.trupocs = sum(1 for closure_list in self.closures.values() for closure in closure_list if closure["rank"] >= 7)
        return self

    def filter_run_time(self, valid_files, valid_alert_files):
        self.total_time = sum(v for k, v in self.analysis_times.items() if k in valid_files)
        self.average_time = (self.total_time / len(valid_files))# if len(valid_files) != 0 else -1
        self.alerts = sum(len(v) for k, v in self.closures.items() if k in valid_alert_files)

def de_duplicate(files: list, valid_files):
    default = files[0]
    other = files[1:]

    for sha in valid_files:
        default_paths = {tuple(
            sorted({x['ins_addr'] for x in closure['trace']} | {closure['sink']['ins_addr']}, key=lambda x: int(x, 16)))
            for closure in default.closures[sha]}
        if not default_paths:
            continue
        for a_f in other:
            minimum_paths = {tuple(sorted({x['ins_addr'] for x in closure['trace']} | {closure['sink']['ins_addr']}, key=lambda x: int(x, 16))) for closure in a_f.closures[sha]}
            changed = True
            while changed:
                for closure in minimum_paths.copy():
                    count = 0
                    for dc in default_paths:
                        if set(dc).issubset(set(closure)):
                            minimum_paths.discard(closure)
                            minimum_paths.add(dc)
                            count += 1
                            break
                else:
                    changed = False

            a_f.closures[sha] = minimum_paths

    return files



if __name__ == '__main__':
    brand = "NetGear"
    firmware = "R6400v2-V1.0.4.84_10.0.58"
    parser = argparse.ArgumentParser()
    parser.add_argument(dest="ablation_dir", help="Location of Ablation Directory")
    args = parser.parse_args()
    all_res = subprocess.check_output(["find", args.ablation_dir, "-type", "f", "-iname", "cmdi_results.json"]).decode().strip().split("\n")

    ablation_files = [
        AblationInfo(path=f"{args.ablation_dir}/ablation-default",
                     assumed_execution=True,
                     reverse_trace=True,
                     timeouts=0,
                     errors=0,
                     average_time=-1,
                     total_time=-1,
                     desc="Default").get_run_time(),

        AblationInfo(path=f"{args.ablation_dir}/ablation-assumed",
                     assumed_execution=False,
                     reverse_trace=True,
                     timeouts=0,
                     errors=0,
                     average_time=-1,
                     total_time=-1,
                     desc="Assumed").get_run_time(),

        AblationInfo(path=f"{args.ablation_dir}/ablation-trace",
                     assumed_execution=True,
                     reverse_trace=False,
                     timeouts=0,
                     errors=0,
                     average_time=-1,
                     total_time=-1,
                     desc="Trace").get_run_time(),

        AblationInfo(path=f"{args.ablation_dir}/ablation-all",
                     assumed_execution=False,
                     reverse_trace=False,
                     timeouts=0,
                     errors=0,
                     average_time=-1,
                     total_time=-1,
                     desc="All").get_run_time(),
        ]

    valid_files = set(reduce(lambda x, y: set(x).intersection(y), [x.analysis_times for x in ablation_files]))
    valid_alert_files = set(reduce(lambda x, y: set(x).intersection(y), [[k for k, v in x.analysis_times.items() if v != 40*60] for x in ablation_files]))

    ablation_files = de_duplicate(ablation_files, valid_files)
    table = Table(f"Desc [Binaries {len(valid_alert_files)}]",
                  Column("Assumed\nExecution", justify="center"),
                  Column("Reverse\nTrace", justify="center"),
                  Column("Average\n(seconds)", justify="center"),
                  Column("Total\n(minutes)"  , justify="center"),
                  Column("Alerts", justify="center"),
                  Column("TruPoCs", justify="center"),
                  Column("Errors"  , justify="center"),
                  Column("OOMKilled", justify="center"),
                  Column("Timeouts", justify="center"),
                  show_lines=True,
                  safe_box=True)

    good = "[green]:heavy_check_mark:"
    bad = "[red]:x:"

    for a_f in sorted(ablation_files, key=lambda x: x.sort_score()):
        a_f.filter_run_time(valid_files, valid_alert_files)
        row = [a_f.desc]
        row.append(good if a_f.assumed_execution else bad)
        row.append(good if a_f.reverse_trace else bad)
        row.append(f"{a_f.average_time:.2f}")
        row.append(f"{a_f.total_time/60:.2f}")
        row.append(f"[green]{a_f.alerts}")
        row.append(f"[bold green]{a_f.trupocs}")
        row.append(f"[red]{a_f.errors}")
        row.append(f"[yellow]{a_f.oom}")
        row.append(f"[blue]{a_f.timeouts}")
        table.add_row(*row)

    Console().print(table)