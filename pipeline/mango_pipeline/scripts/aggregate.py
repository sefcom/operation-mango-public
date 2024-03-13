import sys
import subprocess
import json
import shutil
import csv

from pathlib import Path


def prep_results(directory: Path, result_path: Path, prefix=None):
    results_files = subprocess.check_output(
        ["find", str(directory.resolve()), "-type", "f", "-name", "results.json"]).decode().strip().split('\n')
    results_files = [Path(x) for x in results_files if Path(x).is_file() and not Path(x).is_symlink()]

    for results_file in results_files:
        data = json.loads(results_file.read_text())
        if data["has_sinks"] is False or data["error"] or len(data["closures"]) == 0:
            continue

        out_dir = result_path / (data["sha256"] if "sha256" in data else data["sha"])
        out_dir.mkdir(parents=True, exist_ok=True)
        prefix = "" if prefix is None else prefix
        filename = prefix + "-" + results_file.name
        shutil.copy(results_file, out_dir / filename)
        try:
            local_path = str(data["path"]).replace("/shared/clasm", "/home/clasm/projects/angr-squad")
            output = subprocess.check_output(["file", local_path]).decode()
            if "shared object" in output:
                shutil.rmtree(out_dir)
                continue
            shutil.copy(local_path, out_dir / data["name"])
        except PermissionError:
            pass
        if (results_file.parent / "mango.out").exists():
            filename = prefix + "-" + "mango.out"
            shutil.copy(results_file.parent / "mango.out", out_dir / filename)


def combine_csv(csv_paths):
    out_data = {}
    title = []
    vendor = None
    firmware = None
    sha = None
    name = None
    cfg_time = None
    vra_time = None
    analysis_time = None
    found_bins = set()
    found_header = False
    for path in csv_paths:
        with open(path / "results.csv", newline='') as csvfile:
            spamreader = csv.reader(csvfile, delimiter='\t', quotechar='|')
            for line in spamreader:

                if line and line[0].strip() in ["Brand", "Firmware"]:
                    title = line
                    found_header = not found_header
                    continue

                if not found_header:
                    continue

                if line and line[0]:
                    vendor, firmware, sha, name = line[:4]
                    cfg_time, vra_time, analysis_time = [float(x) for x in line[7:10]]

                    if not vendor in out_data:
                        out_data[vendor] = {}
                    if not firmware in out_data[vendor]:
                        out_data[vendor][firmware] = {}
                    if not sha in out_data[vendor][firmware]:
                        out_data[vendor][firmware][sha] = {"name": name, "cfg_time": cfg_time, "vra_time": vra_time, "analysis_time": analysis_time, "rows": []}
                    else:
                        out_data[vendor][firmware][sha]["analysis_time"] += analysis_time
                        out_data[vendor][firmware][sha]["cfg_time"] = max(analysis_time, out_data[vendor][firmware][sha]["cfg_time"])
                        out_data[vendor][firmware][sha]["vra_time"] = max(analysis_time, out_data[vendor][firmware][sha]["vra_time"])
                    continue

                if not any(x for x in line):
                    continue

                out_data[vendor][firmware][sha]["rows"].append(line)

    with open("../../aggregate_results/results.csv", "w+", newline="") as csvfile:
        spamwriter = csv.writer(csvfile, delimiter='\t',
                                quotechar='|', quoting=csv.QUOTE_MINIMAL)
        spamwriter.writerow(title)
        for vendor in sorted(out_data.keys()):
            for firmware in sorted(out_data[vendor].keys()):
                for sha in sorted(out_data[vendor][firmware].keys()):
                    if sha in found_bins:
                        continue
                    if not Path("aggregate_results/"+sha).exists():
                        continue
                    found_bins.add(sha)
                    data = out_data[vendor][firmware][sha]
                    if data['name'] == "busybox":
                        continue
                    spamwriter.writerow([vendor, firmware, sha, data['name'], "", "", "Blank", "", data["cfg_time"], data["vra_time"], data["analysis_time"]])
                    for row in sorted(data["rows"], key=lambda x: x[4]):
                        row[6] = "Unfilled"
                        spamwriter.writerow(row)

if __name__ == '__main__':
    dataset_dir = Path(sys.argv[1])
    result_dirs = [(Path(x.split("|")[0]), x.split("|")[1]) for x in sys.argv[2:]]
    for result_dir, prefix in result_dirs:
        prep_results(result_dir, Path("../../aggregate_results"), prefix)
    combine_csv([x[0] for x in result_dirs])