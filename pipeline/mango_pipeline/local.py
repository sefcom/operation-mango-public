import json
from typing import Set, Tuple, Dict

import docker
from docker.errors import ContainerError, NotFound

from rich.console import Console
from rich.table import Table

from multiprocessing import Pool
from pathlib import Path

from . import PROJECT_DIR
from .base import Pipeline, ELFInfo, MyProgress
from .firmware.elf_finder import FirmwareFinder
from .scripts import data_printer


class PipelineLocal(Pipeline):
    """
    Pipeline Process for running experiments in local docker containers
    """

    docker_file = PROJECT_DIR / "./docker/mango_user/Dockerfile"

    def __init__(self, *args, quiet=True, **kwargs):

        super().__init__(*args, **kwargs)
        self.quiet = quiet

        self.results_dir.mkdir(parents=True, exist_ok=True)
        if self.target and self.target.is_dir():
            finder = FirmwareFinder(
                self.target,
                self.results_dir,
                bin_prep=self.bin_prep,
                exclude_libs=self.exclude_libs,
            )
            self.vendor_dict = finder.vendor_dict
        else:
            self.vendor_dict = {}

    def run_mango(self, targets: Set[ELFInfo]):
        with MyProgress(
            renderable_callback=self.mango_table_wrapper, transient=True
        ) as progress:
            mango_task = progress.add_task(
                description=f"Mango Analysis", total=len(targets)
            )

            with Pool(self.parallel) as p:
                for idx, results in enumerate(
                    p.imap_unordered(self.mango_wrapper, targets)
                ):
                    data_printer.parse_mango_result(self.total_mango_results, *results)
                    progress.update(mango_task, advance=1)

        Console().print(self.mango_table_wrapper())
        Console().print("[bold green]MANGO ANALYSIS COMPLETE")

    def mango_wrapper(self, target: ELFInfo) -> Tuple[Path, ELFInfo]:
        return self.run_analysis_container(target, "mango")

    def mango_table_wrapper(self):
        return data_printer.generate_mango_table(
            self.total_mango_results, show_dups=self.show_dups
        )

    def env_table_wrapper(self):
        return data_printer.generate_env_table(
            self.total_env_results, show_dups=self.show_dups
        )

    def run_env_resolve(self, targets: Set[ELFInfo]):
        with MyProgress(
            renderable_callback=self.env_table_wrapper, transient=True
        ) as progress:
            env_task = progress.add_task(
                description=f"ENV Analysis", total=len(targets)
            )
            with Pool(self.parallel) as p:
                for idx, results in enumerate(
                    p.imap_unordered(self.env_wrapper, targets)
                ):
                    data_printer.parse_env_result(self.total_env_results, *results)
                    progress.update(env_task, advance=1)

        Console().print(self.env_table_wrapper())
        self.env_merge()
        Console().print("[bold green]ENV RESOLVE COMPLETE")

    def env_wrapper(self, target: ELFInfo) -> Tuple[Path, ELFInfo]:
        return self.run_analysis_container(target, "env_resolve")

    def run_analysis_container(self, *args) -> Tuple[Path, ELFInfo]:
        target, script = args
        docker_client = docker.from_env()
        docker_bin_path = Path("/tmp") / target.path
        docker_res = Path("/tmp/results") / target.sha

        volumes = {
            Path(target.path).absolute(): {"bind": str(docker_bin_path), "mode": "ro"}
        }
        local_res_dir = self.result_dir_from_target(target)
        local_res_dir.mkdir(parents=True, exist_ok=True)

        if script == "mango":
            results_file = local_res_dir / f"{self.category}_results.json"
            if (local_res_dir.parent / "env.json").exists():
                local_env = local_res_dir.parent / "env.json"
                env_dict = Path("/tmp/results/env.json")
                volumes[str(local_env.absolute())] = {
                    "bind": str(env_dict),
                    "mode": "ro",
                }
        else:
            results_file = local_res_dir / "env.json"

        if results_file.exists():
            return results_file, target

        volumes[str(local_res_dir.absolute())] = {"bind": str(docker_res), "mode": "rw"}
        environment = {
            "SCRIPT": script,
            "TIMEOUT": self.timeout,
            "RDA_TIMEOUT": self.rda_timeout,
            "CATEGORY": json.dumps(self.category),
            "RESULT_DEST": str(docker_res),
            "TARGET_PATH": str(docker_bin_path),
            "TARGET_SHA": target.sha,
            "TARGET_BRAND": target.brand,
            "TARGET_FIRMWARE": target.firmware,
            "LD_PATHS": json.dumps(target.ld_paths),
            "EXTRA_ARGS": json.dumps(["--" + x for x in self.extra_args])
        }

        try:
            output = docker_client.containers.run(
                self.container_name,
                name=f"{script}_{Path(target.path).name}_{target.sha[:6]}_{self.category}_{Path(self.results_dir).name}".replace(
                    "+", "plus"
                ),
                command=f"/entrypoint.py {script}",
                volumes=volumes,
                environment=environment,
                stdout=True,
                stderr=True,
                auto_remove=True,
            )
        except ContainerError as e:
            try:
                self.save_error_result(
                    results_file, target, script, e.container.logs().decode()
                )
            except NotFound as e:
                self.save_error_result(results_file, target, script, str(e))
        except Exception as e:
            self.save_error_result(results_file, target, script, str(e))

        if not results_file.exists():
            self.save_error_result(results_file, target, script, "EARLY TERMINATION")

        return results_file, target

    def print_status(self):
        targets, duplicates = self.get_experiment_targets()
        symbols = self.get_target_symbols(targets)
        self.filter_env_targets(targets, symbols)
        self.filter_mango_targets(targets, symbols)

        env_table = data_printer.generate_env_table(
            self.total_env_results, show_dups=self.show_dups
        )
        mango_table = data_printer.generate_mango_table(
            self.total_mango_results, show_dups=self.show_dups
        )

        with Console() as console:
            console.print(env_table)
            console.print(mango_table)

    def print_errors(self):
        targets, _ = self.get_experiment_targets()
        error_table = {}

        paths = []
        for target in targets:
            result_path = (
                self.results_dir
                / target.brand
                / target.firmware
                / target.sha
                / f"{self.category}_results.json"
            )
            res_data = (
                json.loads(result_path.read_text()) if result_path.exists() else {}
            )
            if (
                "ret_code" in res_data
                and res_data["ret_code"] != 0
                and res_data["ret_code"] != -9
                and res_data != 124
            ):
                mango_file = (
                    self.results_dir
                    / target.brand
                    / target.firmware
                    / target.sha
                    / f"{self.category}_mango.out"
                )
                if not mango_file.exists():
                    continue
                for line in reversed(mango_file.read_text().split("\n")):
                    line = line.strip()
                    if line:
                        if "Finished Running Analysis" in line:
                            break
                        if "angr.errors.SimMemoryMissingError" in line:
                            line = "angr.errors.SimMemoryMissingError"
                        elif any(
                            line.startswith(x)
                            for x in [
                                "INFO      |",
                                "ERROR    |",
                                "WARNING   |",
                                "WARNING  |",
                            ]
                        ):
                            paths.append(
                                (
                                    str(result_path),
                                    len(mango_file.read_text().split("\n")),
                                )
                            )
                            line = "UNKNOWN"
                        if line not in error_table:
                            error_table[line] = []
                        error_table[line].append(result_path)
                        break
        print(
            "\n".join(
                f"{x[0]} {x[1]}"
                for x in sorted(paths, reverse=True, key=lambda x: x[1])
            )
        )
        console = Console()

        table = Table(title="Mango Errors")
        table.add_column("Error")
        table.add_column("Amount")

        worst = None
        for error, count in sorted(error_table.items(), key=lambda x: len(x[1])):
            if not worst:
                worst = count
            table.add_row(error, str(len(count)))

        console.print(table)
        console.print(worst)
