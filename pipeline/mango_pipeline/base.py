import csv
import datetime
import hashlib
import os
import subprocess
import shutil
import collections.abc

import elftools.common.exceptions
import toml
import json

from typing import Set, Dict, List, Tuple
from pathlib import Path

import docker
import rich

from docker.errors import ContainerError

from rich.progress import (
    Progress,
    MofNCompleteColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    BarColumn,
    TextColumn,
    SpinnerColumn,
)

from argument_resolver.external_function.sink import ENV_SINKS
from argument_resolver.analysis.base import ScriptBase

from rich.console import Console, Group

from elftools.elf.elffile import ELFFile

from . import PROJECT_DIR
from .firmware import ELFInfo, FirmwareFinder
from .scripts import data_printer


class MyProgress(Progress):
    def __init__(self, *args, renderable_callback=None, **kwargs):
        self.renderable_callback = renderable_callback
        super().__init__(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            *args,
            **kwargs,
        )

    def get_renderables(self):
        if self.renderable_callback:
            yield Group(self.make_tasks_table(self.tasks), self.renderable_callback())
        else:
            yield self.make_tasks_table(self.tasks)


class Pipeline:
    docker_file: Path

    def __init__(
        self,
        target: Path,
        results_dir: Path,
        parallel: int = 1,
        is_env=False,
        is_mango=False,
        category: str = None,
        brand="",
        firmware="",
        extra_args=None,
        job_name=None,
        py_spy=False,
        timeout=120 * 60,
        rda_timeout=5 * 60,
        bin_prep=False,
        exclude_libs=True,
        show_dups=False,
    ):

        self.target = target
        self.results_dir = results_dir
        self.is_env = is_env
        self.is_mango = is_mango
        self.brand = brand
        self.firmware = firmware
        self.category = category
        self.parallel = parallel
        self.total_mango_results = {}
        self.total_env_results = {}
        self.extra_args = extra_args
        self.job_name = job_name
        self.py_spy = py_spy
        self.timeout = timeout
        self.rda_timeout = rda_timeout
        self.bin_prep = bin_prep
        self.container_name = "mango_user"
        self.docker_file = Path(__file__).parent.parent.parent / "docker" / "Dockerfile"
        self.vendor_dict = {}
        self.exclude_libs = exclude_libs
        self.show_dups = show_dups

    @staticmethod
    def create_default_config(config_path: Path):
        """
        Creates Empty/Default Config Files
        :return:
        """

        pipeline_config_file = config_path
        pipeline_config = dict()
        pipeline_config["remote"] = {
            "local_image": "mango_kube",
            "auth_config": {"username": "", "password": ""},
            "registry": "",
            "registry_image": "",
            "registry_secret_name": "",
        }

        pipeline_config_file.parent.mkdir(parents=True, exist_ok=True)
        with pipeline_config_file.open("w") as f:
            toml.dump(pipeline_config, f)

    def get_experiment_targets(self, remote=False) -> Tuple[Set[ELFInfo], Dict]:
        if self.target.is_dir() or remote:
            if self.vendor_dict:

                if self.brand and self.brand not in self.vendor_dict:
                    rich.get_console().log(f"[red]FAILED TO FIND BRAND {self.brand}")
                    return set(), dict()

                if (
                    self.firmware
                    and self.firmware not in self.vendor_dict[self.brand]["firmware"]
                ):
                    rich.get_console().log(
                        f"[red]FAILED TO FIND FIRMWARE {self.firmware} in {self.brand}"
                    )
                    return set(), dict()

                exp_list = set()
                duplicates = dict()
                for brand, firmware_dict in self.vendor_dict.items():
                    if self.brand and brand != self.brand:
                        continue
                    (self.results_dir / brand).mkdir(parents=True, exist_ok=True)
                    for firmware, bin_dict in firmware_dict["firmware"].items():
                        if self.firmware and firmware != self.firmware:
                            continue
                        (self.results_dir / brand / firmware).mkdir(
                            parents=True, exist_ok=True
                        )
                        for sha, elf_dict in bin_dict["elfs"].items():
                            info = ELFInfo(
                                path=elf_dict["path"],
                                brand=brand,
                                firmware=firmware,
                                sha=sha,
                            )
                            if sha not in duplicates:
                                duplicates[sha] = []
                            duplicates[sha].append(info)
                            exp_list.add(info)
                for sha, elfs in duplicates.copy().items():
                    if len(elfs) < 2:
                        duplicates.pop(sha)
                return exp_list, duplicates

            with Progress() as progress:
                elfs = FirmwareFinder.find_elf_files(
                    self.target, progress, exclude_libs=self.exclude_libs
                )
            return {
                ELFInfo(sha=sha, path=path["path"], firmware="", brand="")
                for sha, path in elfs.items()
            }, dict()

        return {
            ELFInfo(
                sha=self.get_sha(self.target),
                path=str(self.target),
                firmware="",
                brand="",
            )
        }, dict()

    def get_symbols_and_targets(self) -> Tuple[Dict[str, set[str]], Set[ELFInfo]]:
        targets, duplicates = self.get_experiment_targets()
        self.link_duplicates(targets, duplicates)

        symbols = self.get_target_symbols(targets)

        return symbols, targets

    def run_experiment(self):
        """
        Function to run all experiments
        """

        symbols, targets = self.get_symbols_and_targets()

        if self.is_env:
            env_targets = self.filter_env_targets(targets, symbols)
            self.run_env_resolve(env_targets)

        if self.is_mango:
            mango_targets = self.filter_mango_targets(targets, symbols)
            self.run_mango(mango_targets)
            self.mango_results_to_csv()

    def link_duplicates(
        self, targets: Set[ELFInfo], duplicates: Dict[str, List[ELFInfo]]
    ):
        for target in targets:
            if target.sha in duplicates:
                target_file = (
                    self.results_dir / target.brand / target.firmware / target.sha
                )
                for dup in duplicates[target.sha]:
                    dup_file = self.results_dir / dup.brand / dup.firmware / dup.sha
                    dup_file.mkdir(parents=True, exist_ok=True)
                    if (
                        not (dup_file / "env.json").exists()
                        and (target_file / "env.json").exists()
                    ):
                        os.link(
                            (target_file / "env.json").absolute().resolve(),
                            (dup_file / "env.json").absolute().resolve(),
                        )
                    if (
                        not (dup_file / f"{self.category}_results.json").exists()
                        and (target_file / f"{self.category}_results.json").exists()
                    ):
                        os.link(
                            (target_file / f"{self.category}_results.json")
                            .absolute()
                            .resolve(),
                            (dup_file / f"{self.category}_results.json")
                            .absolute()
                            .resolve(),
                        )
                    if (
                        not (dup_file / f"{self.category}_mango.out").exists()
                        and (target_file / f"{self.category}_mango.out").exists()
                    ):
                        os.link(
                            (target_file / f"{self.category}_mango.out")
                            .absolute()
                            .resolve(),
                            (dup_file / f"{self.category}_mango.out")
                            .absolute()
                            .resolve(),
                        )

    def get_target_symbols(self, targets: Set[ELFInfo]) -> Dict[str, Set[str]]:
        """
        Analyzes target and creates a set of available functions
        :param targets:
        :return:
        """
        symbols = {}
        symbol_file = self.results_dir / self.brand / self.firmware / "symbols.json"
        prev_data = {}
        if symbol_file.exists():
            try:
                prev_data = json.loads(symbol_file.read_text())
                if not self.bin_prep:
                    return prev_data
            except json.decoder.JSONDecodeError:
                pass

        progressbar = Progress()
        progressbar.start()
        symbol_task = progressbar.add_task("Getting Symbols ...", total=len(targets))
        for target in targets:
            if target.brand not in symbols:
                symbols[target.brand] = {}
            if target.firmware not in symbols[target.brand]:
                symbols[target.brand][target.firmware] = {}

            with open(target.path, "rb") as f:
                try:
                    elf = ELFFile(f)
                    symbols_sections = [elf.get_section_by_name(".dynsym")]
                except (
                    elftools.common.exceptions.ELFParseError,
                    elftools.common.exceptions.ELFError,
                ):
                    progressbar.update(symbol_task, advance=1)
                    continue
                symbols_sections += [x for x in elf.iter_segments(type="PT_DYNAMIC")]
                symbols_sections = [x for x in symbols_sections if x]
                symbols[target.brand][target.firmware][target.sha] = []
                if symbols_sections:
                    for symbols_section in symbols_sections:
                        try:
                            symbols[target.brand][target.firmware][target.sha] = list(
                                set(symbols[target.brand][target.firmware][target.sha])
                                | {
                                    symbol.name
                                    for symbol in symbols_section.iter_symbols()
                                }
                            )
                        except (
                            elftools.common.exceptions.ELFError,
                            elftools.common.exceptions.ELFParseError,
                            ValueError,
                            AttributeError,
                            AssertionError,
                        ):
                            pass
            progressbar.update(symbol_task, advance=1)

        progressbar.stop()
        final_symbols = {}
        for brand, firmware_dict in symbols.items():
            for firmware, sha_dict in firmware_dict.items():
                symbol_dict = {
                    "brand": brand,
                    "firmware": firmware,
                    "symbols": {k: list(v) for k, v in sha_dict.items()},
                }
                final_symbols.update(sha_dict)
                with open(
                    self.results_dir / brand / firmware / "symbols.json", "w+"
                ) as f:
                    json.dump(symbol_dict, f, indent=4)

        final_symbols.update(prev_data)
        (self.results_dir / "symbols.json").write_text(json.dumps(final_symbols))

        return final_symbols

    def run_mango(self, targets: Set[ELFInfo]):
        """
        Function to run operation mango on targets
        :return:
        """
        raise NotImplementedError("Run Mango Function Must Be Implemented")

    def run_env_resolve(self, targets: Set[ELFInfo]):
        """
        Function to run env_resolve on targets
        :return:
        """
        raise NotImplementedError("Run EnvResolve Function Must Be Implemented")

    def build_container(self):
        """
        Builds docker container for target.
        """
        cli = docker.APIClient()
        resp = cli.build(
            path=str(PROJECT_DIR),
            dockerfile=str(self.docker_file),
            tag=self.container_name,
            decode=True,
        )
        console = Console()
        output = ""
        with console.screen():
            for line in resp:
                if "stream" in line:
                    console.print(line["stream"], end="")
                    output += line["stream"]
                elif "errorDetail" in line:
                    break
        if "errorDetail" in line:
            console.print(output)
            console.print(f"[red bold]{line['error']}")

    @staticmethod
    def get_sha(file: Path) -> str:
        """
        Get SHA256 sum for given file
        """
        with file.open("rb") as f:
            return hashlib.file_digest(f, "sha256").hexdigest()

    def mango_results_to_csv(self, full=False):
        csv_file = open(self.results_dir / "results.csv", "w", newline="")
        results_writer = csv.writer(
            csv_file, delimiter="\t", quotechar="|", quoting=csv.QUOTE_MINIMAL
        )

        titles = [
            "Brand",
            "Firmware",
            "SHA256",
            "Name",
            "Sink",
            "Addr",
            "TP",
            "CFG Time",
            "VRA Time",
            "Analysis Time",
            "Checked By",
            "Notes",
        ]
        rows = [titles]
        results = {}
        shas = set()
        brands = sorted(
            [x for x in self.results_dir.iterdir() if x.is_dir()], key=lambda x: x.name
        )
        for brand in brands:
            results[brand.name] = {}
            firmwares = sorted(
                [x for x in brand.iterdir() if x.is_dir()], key=lambda x: x.name
            )
            for firmware in firmwares:
                results[brand.name][firmware.name] = {
                    "env_time": 0,
                    "cfg_time": 0,
                    "vra_time": 0,
                    "analysis_time": 0,
                }

                elfs = sorted(
                    [x for x in firmware.iterdir() if x.is_dir()], key=lambda x: x.name
                )
                for elf in elfs:
                    results_file = elf / f"{self.category}_results.json"
                    env_file = elf / "env.json"

                    if not results_file.exists():
                        continue

                    if env_file.exists():
                        try:
                            env_data = json.loads(results_file.read_text())
                            if env_data["error"] is None:
                                results[brand.name][firmware.name]["env_time"] += (
                                    env_data["cfg_time"]
                                    + env_data["vra_time"]
                                    + env_data["mango_time"]
                                )
                        except:
                            pass

                    data = json.loads(results_file.read_text())
                    if data["error"] is not None or not data["has_sinks"]:
                        continue

                    results[brand.name][firmware.name]["cfg_time"] += data["cfg_time"]
                    results[brand.name][firmware.name]["vra_time"] += data["vra_time"]
                    results[brand.name][firmware.name]["analysis_time"] += data[
                        "mango_time"
                    ]

                    if not full and data["sha256"] in shas:
                        continue
                    else:
                        shas.add(data["sha256"])

                    if not full and len(data["closures"]) == 0:
                        continue

                    rows.append(
                        [
                            brand.name,
                            firmware.name,
                            elf.name,
                            data["name"],
                            "",
                            "",
                            "",
                            f"{data['cfg_time']:.2f}",
                            f"{data['vra_time']:.2f}",
                            f"{data['mango_time']:.2f}",
                            "",
                            "",
                        ]
                    )
                    for closure in sorted(
                        data["closures"], key=lambda x: x["sink"]["function"]
                    ):
                        sources = {x.split("(")[0].lower() for x in closure["inputs"]}
                        sources = {x if "nvram" not in x else "nvram" for x in sources}
                        sources = {x if "recv" not in x else "recv" for x in sources}
                        rows.append(
                            [
                                "",
                                "",
                                "",
                                "",
                                closure["sink"]["function"],
                                closure["sink"]["ins_addr"],
                                "",
                                "",
                                "",
                                "",
                                "",
                                "",
                                "",
                                ",".join(sorted(sources)),
                                str(closure["reachable_from_main"]),
                            ]
                        )

                rows.append([] * 4)
            rows.append([])
        rows.insert(
            0,
            [
                "Completed",
                f'=CountA(G5:G{len(rows)}) & " of " & CountA(F5:F{len(rows)})',
            ],
        )
        rows.insert(
            0,
            [
                "True Positives",
                f'=CountIF(H5:H{len(rows)-1}, "Y")/(CountIF(H5:H{len(rows)-1}, "Y") + CountIF(H5:H{len(rows)-1}, "N"))',
            ],
        )
        rows.insert(0, [])
        rows.append([] * 4)
        rows.append(
            [
                "Firmware",
                "ENV Time",
                "CFG Time",
                "VRA Time",
                "Analysis Time",
                "Total (Minutes)",
            ]
        )
        for firmware_dict in results.values():
            for firmware, vals in firmware_dict.items():
                rows.append(
                    [
                        firmware,
                        vals["env_time"],
                        vals["cfg_time"],
                        vals["vra_time"],
                        vals["analysis_time"],
                        f"=SUM(B{len(rows)+1}:E{len(rows)+1})/60",
                    ]
                )
        results_writer.writerows(rows)
        csv_file.close()

    def filter_mango_targets(
        self, targets: Set[ELFInfo], symbols: Dict[str, Set[str]]
    ) -> Set[ELFInfo]:
        if "symbols" in symbols:
            symbols = symbols["symbols"]
        mango_targets = set()
        mango_sinks = ScriptBase.load_sinks(category=self.category)

        known_shas = set()
        for target in targets:
            is_dup = target.sha in known_shas
            res_file = (
                self.result_dir_from_target(target) / f"{self.category}_results.json"
            )
            known_shas.add(target.sha)
            if res_file.exists():
                data_printer.parse_mango_result(
                    self.total_mango_results, res_file, target, dup=is_dup
                )
                mango_targets.discard(target)
            else:
                if target.sha not in symbols:
                    continue
                if not any(sink.name in symbols[target.sha] for sink in mango_sinks):
                    res_file.parent.mkdir(exist_ok=True, parents=True)
                    self.save_error_result(
                        res_file, target, "mango", None, has_sinks=False
                    )
                else:
                    mango_targets.add(target)

        return mango_targets

    def result_dir_from_target(self, target: ELFInfo) -> Path:
        return self.results_dir / target.brand / target.firmware / target.sha

    def filter_env_targets(
        self, targets: Set[ELFInfo], symbols: Dict[str, Set[str]]
    ) -> Set[ELFInfo]:
        env_targets = set()
        known_shas = set()
        for target in targets:
            is_dup = target.sha in known_shas
            known_shas.add(target.sha)
            res_file = self.result_dir_from_target(target) / "env.json"
            if res_file.exists():
                data_printer.parse_env_result(
                    self.total_env_results, res_file, target, dup=is_dup
                )
            else:
                if not any(
                    target.sha not in symbols or sink.name in symbols[target.sha]
                    for sink in ENV_SINKS
                ):
                    res_file.parent.mkdir(exist_ok=True, parents=True)
                    self.save_error_result(
                        res_file, target, "env_resolve", None, has_sinks=False
                    )
                else:
                    env_targets.add(target)
        return env_targets

    @staticmethod
    def save_error_result(
        result_path: Path, target: ELFInfo, script: str, error: str, has_sinks=True
    ):
        if script == "mango":
            out_dict = {
                "sha256": target.sha,
                "name": Path(target.path).name,
                "path": target.path,
                "closures": [],
                "cfg_time": 0,
                "vra_time": 0,
                "mango_time": 0,
                "error": error,
                "ret_code": 0 if not error else 1,
                "has_sinks": has_sinks,
            }

        elif script == "env_resolve":
            out_dict = {
                "sha256": target.sha,
                "name": Path(target.path).name,
                "path": target.path,
                "results": {},
                "cfg_time": 0,
                "vra_time": 0,
                "mango_time": 0,
                "ret_code": 0 if not error else 1,
                "has_sinks": has_sinks,
                "error": error,
            }

        else:
            out_dict = {"error": error}

        with result_path.open("w+") as f:
            json.dump(out_dict, f, indent=4)

    @staticmethod
    def console_subprocess(command: list, cwd=None):
        if cwd is None:
            cwd = os.getcwd()
        with Progress(SpinnerColumn(), TextColumn("{task.description}")) as progressbar:
            command_task = progressbar.add_task(
                description="[bold]Running ...", total=None
            )
            progressbar.update(
                command_task,
                description="[bold]Running " + (" ".join(str(x) for x in command)),
            )
            with Console() as c:
                with subprocess.Popen(
                    command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd
                ) as p:
                    output = []
                    while p.poll() is None:
                        line = p.stdout.readline().decode().strip()
                        if line:
                            c.print(line)
                            output.append(line)

                    ret_code = p.returncode
                progressbar.update(command_task, completed=1, total=1)
        return ret_code, output

    @staticmethod
    def prep_results(directory: Path, result_path: Path, category: str):
        results_files = (
            subprocess.check_output(
                [
                    "find",
                    str(directory.resolve()),
                    "-type",
                    "f",
                    "-name",
                    f"{category}_results.json",
                ]
            )
            .decode()
            .strip()
            .split("\n")
        )
        results_files = [
            Path(x)
            for x in results_files
            if Path(x).is_file() and not Path(x).is_symlink()
        ]

        for results_file in results_files:
            data = json.loads(results_file.read_text())
            if data["has_sinks"] is False or data["error"]:
                continue

            out_dir = result_path / (
                data["sha256"] if "sha256" in data else data["sha"]
            )
            if out_dir.exists():
                pass
            else:
                out_dir.mkdir(parents=True)
                shutil.copy(results_file, out_dir / results_file.name)
                shutil.copy(
                    str(data["path"]).replace(
                        "/shared/clasm", "/home/clasm/projects/angr-squad"
                    ),
                    out_dir / data["name"],
                )
                if (results_file.parent / f"{category}_mango.out").exists():
                    shutil.copy(
                        results_file.parent / f"{category}_mango.out",
                        out_dir / f"{category}_mango.out",
                    )

    def env_merge(self):
        for brand in [x for x in self.results_dir.iterdir() if x.is_dir()]:
            if self.brand and self.brand != brand.name:
                continue

            with MyProgress(transient=True) as progress:
                firmwares = [
                    x
                    for x in brand.iterdir()
                    if x.is_dir()
                    and (
                        not self.firmware or (self.firmware and self.firmware == x.name)
                    )
                ]
                firm_task = progress.add_task(
                    description="Merging Env Results", total=len(firmwares)
                )
                for firmware in firmwares:
                    merge_task = progress.add_task(
                        description=f"Merging {firmware.name}", total=None
                    )
                    self.env_merge_firmware(firmware)
                    progress.update(merge_task, visible=False)
                    progress.update(firm_task, advance=1)

    def env_merge_firmware(self, result_dir: Path):

        docker_client = docker.from_env()

        docker_res = Path("/tmp") / result_dir.name

        volumes = dict()
        volumes[str(result_dir.absolute())] = {"bind": str(docker_res), "mode": "rw"}

        escaped_docker_res = str(docker_res)
        escaped_out_file = str(docker_res / "env.json")
        command = [
            "/angr/bin/env_resolve",
            escaped_docker_res,
            "--merge",
            "--results",
            escaped_out_file,
        ]
        try:
            docker_client.containers.run(
                self.container_name,
                name=f"env_merge_{result_dir.name.replace('%', '_').replace('(', '_').replace(')', '_')}",
                command=command,
                volumes=volumes,
                stdout=True,
                stderr=True,
                auto_remove=True,
            )
        except ContainerError as e:
            print(e)

    @staticmethod
    def dict_update(d, u):
        for k, v in u.items():
            if isinstance(v, collections.abc.Mapping):
                d[k] = Pipeline.dict_update(d.get(k, {}), v)
            else:
                d[k] = v
        return d

    def merge_symbols(self):
        symbols = (
            subprocess.check_output(
                ["find", self.results_dir, "-type", "f", "-name", "symbols.json"]
            )
            .decode()
            .strip()
            .split("\n")
        )

        symbol_out = {}
        for symbol_file in symbols:
            if symbol_file == str(self.results_dir / "symbols.json"):
                continue
            with open(symbol_file, "r") as f:
                symbol_data = json.load(f)
                if "symbols" not in symbol_data:
                    continue
                symbol_out.update(symbol_data["symbols"])

        with open(self.results_dir / "symbols.json", "w+") as f:
            json.dump(symbol_out, f, indent=4)

        return symbol_out

    def merge_vendors(self):
        vendors = (
            subprocess.check_output(
                ["find", self.results_dir, "-type", "f", "-name", "vendor.json"]
            )
            .decode()
            .strip()
            .split("\n")
        )
        vendor_out = {}
        for vendor_file in vendors:
            if (
                not vendor_file
                or vendor_file == str(self.results_dir / "vendor.json")
                or not Path(vendor_file).exists()
            ):
                continue
            with open(vendor_file, "r") as f:
                vendor_data = json.load(f)
                p = Path(vendor_file)
                vendor_data = {
                    p.parent.parent.name: {"firmware": {p.parent.name: vendor_data}}
                }
                vendor_out = self.dict_update(vendor_out, vendor_data)

        with open(self.results_dir / "vendor.json", "w+") as f:
            json.dump(vendor_out, f, indent=4)

        return vendor_out
