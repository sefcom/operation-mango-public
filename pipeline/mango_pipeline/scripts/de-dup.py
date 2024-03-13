import sys
import csv

from pathlib import Path

def get_csv_data(csv_path: Path, prev=False, delim="\t"):
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

    with open(csv_path, newline='') as csvfile:
        spamreader = csv.reader(csvfile, delimiter=delim, quotechar='|')
        for line in spamreader:

            if line and line[0].strip() in ["Brand", "Firmware"]:
                if not title:
                    title = line
                found_header = not found_header
                continue

            if not found_header:
                continue

            if line and line[0]:
                vendor, firmware, sha, name = line[:4]
                cfg_time, vra_time, analysis_time = [float(x) if x else 0 for x in line[8:11]]

                if not vendor in out_data:
                    out_data[vendor] = {}
                if not firmware in out_data[vendor]:
                    out_data[vendor][firmware] = {}
                if not sha in out_data[vendor][firmware]:
                    out_data[vendor][firmware][sha] = {"name": name, "cfg_time": cfg_time, "vra_time": vra_time, "analysis_time": analysis_time, "rows": {}}
                else:
                    out_data[vendor][firmware][sha]["analysis_time"] += analysis_time
                    out_data[vendor][firmware][sha]["cfg_time"] = max(analysis_time, out_data[vendor][firmware][sha]["cfg_time"])
                    out_data[vendor][firmware][sha]["vra_time"] = max(analysis_time, out_data[vendor][firmware][sha]["vra_time"])
                continue

            if not any(x for x in line):
                continue

            if prev:
                line = line[2:]
            addr = line[5]
            out_data[vendor][firmware][sha]["rows"][addr] = line
    return out_data, title


def get_total_data(prev_data, new_data):
    sha_set = set()
    all_lens = set()
    for brand, firm_dict in new_data.items():
        if brand not in prev_data:
            continue
        for firmware, sha_dict in firm_dict.items():
            if firmware not in prev_data[brand]:
                continue
            for sha, row_dict in sha_dict.items():
                if sha in sha_set:
                    new_data[brand][firmware].pop(sha)
                    continue
                else:
                    sha_set.add(sha)

                if sha not in prev_data[brand][firmware]:
                    continue

                for addr, row in row_dict["rows"].items():
                    if addr in prev_data[brand][firmware][sha]["rows"]:
                        new_data[brand][firmware][sha]["rows"][addr] = prev_data[brand][firmware][sha]["rows"][addr]
                        new_data[brand][firmware][sha]["rows"][addr].extend(row[-2:])
                    else:
                        while len(new_data[brand][firmware][sha]["rows"][addr]) < 15:
                            new_data[brand][firmware][sha]["rows"][addr].insert(-3, "")

    return new_data


def gen_csv(title, csv_data):
    with open("./updated.csv", "w", newline="") as csvfile:
        spamwriter = csv.writer(csvfile, delimiter='\t',
                                quotechar='|', quoting=csv.QUOTE_MINIMAL)

        title = title[:3] + ["Name"] + title[3:]
        all_rows = []
        for vendor in sorted(csv_data.keys()):
            for firmware in sorted(csv_data[vendor].keys()):
                for sha in sorted(csv_data[vendor][firmware].keys()):
                    data = csv_data[vendor][firmware][sha]
                    all_rows.append([vendor, firmware, sha, data['name'], "", "", "", "", data["cfg_time"], data["vra_time"], data["analysis_time"]])
                    for row in sorted(data["rows"], key=lambda x: int(x, 16)):
                        all_rows.append([""] + data["rows"][row])

        for idx in range(len(all_rows)):
            all_rows[idx][4] = f'=IF(ISBLANK(D{idx+5}), "", D{idx+5} & " [" & COUNTIF($D$5:$D, D{idx+5}) & "]")'
        all_rows = [title] + [x for x in all_rows]
        all_rows.insert(0, [])
        all_rows.insert(0, ["Completed", f'=CountA(H5:H{len(all_rows)-1}) & " of " & CountA(F5:F{len(all_rows)-1})'])
        all_rows.insert(0, ["True Positives", f'=CountIF(H5:H{len(all_rows)-1}, "Y")/(CountIF(H5:H{len(all_rows)-1}, "Y") + CountIF(H5:H{len(all_rows)-1}, "N"))'])
        spamwriter.writerows(all_rows)

def print_stats(total_data):
    valid_rows = []
    from collections import Counter
    paired_d = {}
    shas = set()
    for vendor, firm_dict in total_data.items():
        for firmware, sha_dict in firm_dict.items():
            for sha, data_dict in sha_dict.items():
                if any(y == "TP" or y == "FP" for x in data_dict["rows"].values() for y in x):
                    shas.add(sha)
                valid_rows.extend([(x[6], x[13], x[14], vendor) for x in data_dict["rows"].values() if len(x) > 6 and x[6]])
    d = {"TP": {}, "FP": {}}
    total = 0
    file_ops = ["fgets", "read", "open", "fread"]
    network_ops = ["socket", "recv"]
    vendor_dict = {}
    for i, tags, xrefs, vendor in valid_rows:
        if i not in d:
            continue
        if vendor not in vendor_dict:
            vendor_dict[vendor] = {}
        if i not in vendor_dict[vendor]:
            vendor_dict[vendor][i] = 0

        vendor_dict[vendor][i] += 1
        other = {"network_ops" if x in network_ops else "file_ops" if x in file_ops else "unknown" if not x else x for x in tags.split(",")}
        other = sorted(other)
        tup = tuple(other + [i])
        if tup not in paired_d:
            paired_d[tup] = 0
        paired_d[tup] += 1
        for t in other:
            if t not in d[i]:
                d[i][t] = 0
            d[i][t] += 1
            total += 1
    for t in d["TP"]:
        if t not in d["FP"]:
            d["FP"][t] = 0
        print(f"{t.ljust(10, ' ')}: {d['TP'][t]}/{(d['TP'][t] + d['FP'][t])} = {(d['TP'][t]/(d['TP'][t] + d['FP'][t]))*100:.2f}%")
    print(f"{len(shas) = }")
    print(f"{total = }")


if __name__ == '__main__':
    assert(len(sys.argv) == 3)
    prev_version = Path(sys.argv[1])
    new_version = Path(sys.argv[2])
    prev_data, title = get_csv_data(prev_version, prev=True, delim="\t")
    new_data, _ = get_csv_data(new_version)
    total_data = get_total_data(prev_data, new_data)
    print_stats(total_data)
    gen_csv(title, total_data)