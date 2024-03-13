#!/angr/bin/python

import os
import sys
import json
import shutil
import subprocess
import tarfile
import hashlib
import time

from pathlib import Path
from typing import Tuple, List, Any


def give_write_permissions(file_path: Path):
    os.chmod(file_path, os.stat(file_path).st_mode | 0o002)


def get_kube_data() -> tuple[
    Path | Any, Path | Any, int, int, Any, Any, Any | None, Path
]:
    experiment_list_loc = Path(sys.argv[1])
    with experiment_list_loc.open("r", encoding="ascii") as f:
        experiment_data = json.load(f)

    index = os.environ["JOB_COMPLETION_INDEX"]
    script = experiment_data["script"]
    timeout = int(experiment_data["timeout"])
    rda_timeout = int(experiment_data["rda_timeout"])
    category = experiment_data["category"]
    result_dest = Path(experiment_data["result_dest"])
    target_dir = Path(experiment_data["target_dir"])

    if script != "bin_prep":
        brand = experiment_data["targets"][index]["brand"]
        firmware = experiment_data["targets"][index]["firmware"]
        sha = experiment_data["targets"][index]["sha"]
        if experiment_data["targets"][index]["ld_paths"]:
            ld_paths = experiment_data["targets"][index]["ld_paths"]
        else:
            ld_paths = None

        local_res = result_dest / brand / firmware / sha
        target = Path(experiment_data["targets"][index]["path"])
    else:
        local_res = result_dest
        target = experiment_data["targets"][index]
        ld_paths = None

    return (
        local_res,
        target,
        timeout,
        rda_timeout,
        script,
        category,
        ld_paths,
        target_dir,
    )


def get_local_data() -> tuple[Path, Path, int, int, str, Any, str | None | Any, None]:
    script = os.environ.get("SCRIPT", None)
    timeout = int(os.environ.get("TIMEOUT", 3 * 60 * 60))
    rda_timeout = int(os.environ.get("RDA_TIMEOUT", 0))
    category = json.loads(os.environ.get("CATEGORY", "[]"))

    result_dest = Path(os.environ.get("RESULT_DEST", ""))

    target = Path(os.environ.get("TARGET_PATH", ""))
    ld_paths = os.environ.get("LD_PATHS", None)
    if ld_paths:
        ld_paths = json.loads(ld_paths)

    return result_dest, target, timeout, rda_timeout, script, category, ld_paths, None


def gen_error_dict(target_path, time_str, script):
    sha = None
    if os.path.exists(target_path):
        with open(target_path, "rb") as f:
            sha = hashlib.file_digest(f, "sha256").hexdigest()
    data = {
        "results": {},
        "sha256": sha,
        "name": target_path.name,
        "path": str(target_path),
        "closures" if script == "mango" else "results": [],
        "cfg_time": None,
        "vra_time": None,
        time_str: None,
        "error": None,
        "has_sinks": True,
        "ret_code": 0,
    }
    return data


def run_local():
    if len(sys.argv) > 1 and sys.argv[1] == "mango":
        script = "/angr/bin/mango"
    elif len(sys.argv) > 1 and sys.argv[1] == "env_resolve":
        script = "/angr/bin/env_resolve"
    else:
        print("Requires eiter: mango or env_resolve to be argv[1]")
        return

    subprocess.run([script, *sys.argv[2:]])


def main():
    get_data = (
        get_kube_data if os.environ.get("KUBE", None) is not None else get_local_data
    )
    (
        local_result,
        target_path,
        timeout,
        rda_timeout,
        script,
        category,
        ld_paths,
        target_dir,
    ) = get_data()

    if script is None:
        run_local()
        return

    debug = os.environ.get("DEBUG", None)

    local_result.mkdir(exist_ok=True, parents=True)

    if "ZIP_DEST" in os.environ:
        zip_dest = Path(os.environ["ZIP_DEST"])
        os.makedirs(zip_dest, exist_ok=True)
        if script == "bin_prep":
            print("SHOULDNT BE HERE", target_path, zip_dest)
            subprocess.call(["tar", "-xvzf", target_path, "-C", zip_dest])
        else:
            firm_zip = str(target_dir / local_result.parent.name) + ".tar.gz"
            print("Extracting", firm_zip, "to", zip_dest)
            subprocess.call(["tar", "-xvzf", firm_zip, "-C", zip_dest])

    if script == "bin_prep":
        if tarfile.is_tarfile(target_path):
            target_path = os.environ["ZIP_DEST"]
        command = [
            "/angr/bin/mango-pipeline",
            "--path",
            str(target_path),
            "--results",
            str(local_result),
            "--bin-prep",
        ]
        subprocess.call(command)

    else:
        command = []
        if "PYSPY" in os.environ:
            command += [
                "/angr/bin/py-spy",
                "record",
                "--format",
                "speedscope",
                "-o",
                f"{str(local_result)}/speedscope.json",
                "--",
            ]
            print("RUNNING PYSPY")
        else:
            print("NOT RUNNING PYSPY")
        command += [f"/angr/bin/{script}", target_path]

        command += ["--rda-timeout", str(rda_timeout)]
        command += ["--results", str(local_result)]
        # Ignoring this option atm
        # command += ["--ld-paths", " ".join(ld_paths)]
        result_file = None

        if "EXTRA_ARGS" in os.environ:
            command += json.loads(os.environ["EXTRA_ARGS"])

        keyword_dict = local_result.parent / "keywords.json"
        if not keyword_dict.exists():
            with keyword_dict.open("w+") as f:
                f.write("{}")
        command += ["--keyword-dict", str(keyword_dict)]
        command += ["--workers", "0"]

        ret_code = None
        start_time = time.time()
        if script == "mango":
            result_file = f"{category}_results.json"
            if category:
                command += ["--category", category]
            env_dict = local_result.parent / "env.json"
            if not env_dict.exists():
                with env_dict.open("w+") as f:
                    f.write("{}")
            command += ["--env-dict", str(env_dict)]
            if debug is not None:
                command += ["--loglevel", "DEBUG"]
            command += ["--concise"]

            print("COMMAND:", command)
            try:
                result = subprocess.run(command, timeout=timeout)
                ret_code = result.returncode
            except subprocess.TimeoutExpired as e:
                ret_code = 124

            if ret_code != 0:
                tmp_path = Path("/tmp/mango.out")
                if tmp_path.exists():
                    shutil.copy(tmp_path, local_result / "mango.out")
            else:
                real_path = local_result / "mango.out"
                if real_path.exists():
                    real_path.unlink()

            firmware_dst = local_result.parent
            subprocess.call(
                [
                    "/angr/bin/mango",
                    str(firmware_dst),
                    "--merge-execve",
                    "--results",
                    str(firmware_dst / "execv.json"),
                ]
            )
        elif script == "env_resolve":
            print("COMMAND:", command)
            try:
                ret_code = subprocess.call(command, timeout=timeout)
            except subprocess.TimeoutExpired:
                ret_code = 124
            result_file = "env.json"

            firmware_dst = local_result.parent
            subprocess.call(
                [
                    "/angr/bin/env_resolve",
                    str(firmware_dst),
                    "--merge",
                    "--results",
                    str(firmware_dst / result_file),
                ]
            )

        time_str = "mango_time" if script == "mango" else "analysis_time"
        try:
            with (local_result / result_file).open("r") as f:
                data = json.load(f)
        except FileNotFoundError:
            data = gen_error_dict(target_path, time_str, script)
        except json.decoder.JSONDecodeError:
            with (local_result / result_file).open("r") as f:
                data = f.read()
                print("FAILED TO DECODE JSON")
                print(data)
            data = gen_error_dict(target_path, time_str, script)

        data["ret_code"] = ret_code

        if ret_code == 124 and "cfg_time" in data and data["cfg_time"]:
            data["ret_code"] = ret_code
            data["error"] = "timeout"
            data[time_str] = time.time() - start_time

            with (local_result / result_file).open("w") as f:
                json.dump(data, f, indent=4)

        elif ret_code == 124:
            data["ret_code"] = ret_code
            data["error"] = "potential_timeout"
            data[time_str] = time.time() - start_time

        elif ret_code == -9:
            data["error"] = "OOMKILLED"
            data["ret_code"] = ret_code
            data[time_str] = time.time() - start_time
            with (local_result / result_file).open("w") as f:
                json.dump(data, f, indent=4)

        elif ret_code != 0:
            data["error"] = "early_termination"
            data["ret_code"] = ret_code
            data[time_str] = time.time() - start_time
            with (local_result / result_file).open("w") as f:
                json.dump(data, f, indent=4)

        if (local_result / result_file).exists():
            give_write_permissions(local_result / result_file)

        print(data)


if __name__ == "__main__":
    main()
