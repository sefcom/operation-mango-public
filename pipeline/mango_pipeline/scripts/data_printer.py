import datetime
import json

from typing import List, Dict
from pathlib import Path

from rich.table import Table
from ..firmware import ELFInfo


class ResultAccumulator:
    def __init__(self, fields: List[str]):
        self.field_dict = {x: {"uniq": 0, "dup": 0} for x in fields}

    def __getattr__(self, name: str):
        if name == "field_dict":
            return self.__getattribute__(name)
        return self.field_dict[name]

    def make_table_row(self, field, modifier="", show_dup=False):
        if show_dup:
            row = f'{modifier}{self.field_dict[field]["dup"]}'
        else:
            row = f'{modifier}{self.field_dict[field]["uniq"]}'
        return row

    def make_table_rows(self, fields, show_dup=False):
        row = []
        for modifier, field in fields:
            row.append(self.make_table_row(field, modifier, show_dup))
        return row

    # update all fields based on provided dict
    def update(self, data: dict, dup=False):
        for field, value in data.items():
            if value is None:
                continue
            if field == "mango_time" and isinstance(value, list):
                value = sum(value)
            if not dup:
                self.field_dict[field]["uniq"] += value
            self.field_dict[field]["dup"] += value


def parse_mango_result(
    mango_results: Dict[str, ResultAccumulator],
    result_file: Path,
    info: ELFInfo,
    dup=False,
):
    if info.brand not in mango_results:
        mango_results[info.brand] = ResultAccumulator(
            [
                "binaries",
                "binaries_alerted",
                "binaries_resolved",
                "total_alerts",
                "trupocs",
                "no_sinks",
                "timeout",
                "oom",
                "error",
                "cfg_time",
                "vra_time",
                "mango_time",
            ]
        )

    if result_file.exists():
        try:
            result = json.loads(result_file.read_text())
            hits = len(result.get("closures", result.get("results", [])))
            has_hits = hits > 0
            resolved = not has_hits - (not result["has_sinks"])
            no_sinks = 0 if result["has_sinks"] else 1
            error = 1 if result["error"] else 0
            timeout = 1 if "ret_code" in result and result["ret_code"] == 124 else 0
            error -= timeout
            oom = 1 if "ret_code" in result and result["ret_code"] == -9 else 0
            cfg_time = result["cfg_time"] if result["cfg_time"] else 0
            vra_time = result["vra_time"] if result["vra_time"] else 0
            mango_time = (
                result["mango_time"] if "mango_time" in result else result["analysis_time"]
            )
            trupocs = len([x for x in result.get("closures", [{"rank": 0}]) if x["rank"] >= 7])

            update_dict = {
                "binaries_alerted": has_hits,
                "binaries_resolved": resolved,
                "total_alerts": hits,
                "trupocs": trupocs,
                "no_sinks": no_sinks,
                "error": error,
                "timeout": timeout,
                "oom": oom,
                "cfg_time": cfg_time,
                "vra_time": vra_time,
                "mango_time": mango_time,
                "binaries": 1,
            }
        except json.decoder.JSONDecodeError:
            update_dict = {"error": 1, "binaries": 1}

    else:
        update_dict = {"error": 1, "binaries": 1}

    mango_results[info.brand].update(update_dict, dup=dup)


def parse_env_result(
    env_results: Dict[str, ResultAccumulator],
    result_file: Path,
    info: ELFInfo,
    dup=False,
):
    if info.brand not in env_results:
        env_results[info.brand] = ResultAccumulator(
            [
                "binaries",
                "binaries_alerted",
                "binaries_resolved",
                "total_alerts",
                "no_sinks",
                "timeout",
                "oom",
                "error",
                "cfg_time",
                "vra_time",
                "analysis_time",
            ]
        )

    if result_file.exists():
        result = json.loads(result_file.read_text())
        hits = len(result.get("closures", result.get("results", [])))
        has_hits = hits > 0
        resolved = not has_hits - (not result["has_sinks"])
        no_sinks = 0 if result["has_sinks"] else 1
        error = 1 if result["error"] else 0
        timeout = 1 if "ret_code" in result and result["ret_code"] == 124 else 0
        error -= timeout
        oom = 1 if "ret_code" in result and result["ret_code"] == -9 else 0
        cfg_time = result["cfg_time"] if result["cfg_time"] else 0
        vra_time = result["vra_time"] if result["vra_time"] else 0
        mango_time = (
            result["mango_time"] if "mango_time" in result else result["analysis_time"]
        )
        if mango_time == 0 and "sink_times" in result:
            mango_time = sum(result["sink_times"].values())


        update_dict = {
            "binaries_alerted": has_hits,
            "binaries_resolved": resolved,
            "total_alerts": hits,
            "no_sinks": no_sinks,
            "error": error,
            "timeout": timeout,
            "oom": oom,
            "cfg_time": cfg_time,
            "vra_time": vra_time,
            "analysis_time": mango_time,
            "binaries": 1,
        }

    else:
        update_dict = {"error": 1, "binaries": 1}

    env_results[info.brand].update(update_dict, dup=dup)


def generate_mango_table(
    mango_results: Dict[str, ResultAccumulator], show_dups=False
) -> Table:
    """Make a new table."""
    table = Table(title="MANGO RESULTS")
    table.add_column("Vendor", vertical="middle", style="bold")
    table.add_column("Binaries")
    table.add_column("[green]Binaries Alerted")
    table.add_column("Binaries Resolved")
    table.add_column("No Sinks")
    table.add_column("[green]Total Alerts")
    table.add_column("[bold green]TruPoCs")
    table.add_column("[red]Error")
    table.add_column("[blue]Timeout")
    table.add_column("[yellow]OOM")
    table.add_column("Analysis Time", justify="right")

    selector = "dup" if show_dups else "uniq"
    for idx, vendor in enumerate(sorted(list(mango_results))):
        data = mango_results[vendor]
        vendor_time = datetime.timedelta(
            seconds=int(
                data.mango_time[selector]
                + data.cfg_time[selector]
                + data.vra_time[selector]
            )
        )
        row = [vendor]
        styled_rows = data.make_table_rows(
            [
                ("", "binaries"),
                ("[green]", "binaries_alerted"),
                ("", "binaries_resolved"),
                ("", "no_sinks"),
                ("[green]", "total_alerts"),
                ("[bold green]", "trupocs"),
                ("[red]", "error"),
                ("[blue]", "timeout"),
                ("[yellow]", "oom"),
            ],
            show_dup=show_dups,
        )
        row.extend(styled_rows)
        row.append(f"{vendor_time}")
        table.add_row(*row, end_section=idx == len(list(mango_results)) - 1)
    table.add_row(
        "Total",
        str(sum(x.binaries[selector] for x in mango_results.values())),
        f"[green]{sum(x.binaries_alerted[selector] for x in mango_results.values())}",
        f"{sum(x.binaries_resolved[selector] for x in mango_results.values())}",
        f"{sum(x.no_sinks[selector] for x in mango_results.values())}",
        f"[green]{sum(x.total_alerts[selector] for x in mango_results.values())}",
        f"[bold green]{sum(x.trupocs[selector] for x in mango_results.values())}",
        f"[red]{sum(x.error[selector] for x in mango_results.values())}",
        f"[blue]{sum(x.timeout[selector] for x in mango_results.values())}",
        f"[yellow]{sum(x.oom[selector] for x in mango_results.values())}",
        str(
            datetime.timedelta(
                seconds=int(
                    sum(
                        x.mango_time[selector]
                        + x.cfg_time[selector]
                        + x.vra_time[selector]
                        for x in mango_results.values()
                    )
                )
            )
        ),
    )
    return table


def generate_env_table(
    env_results: Dict[str, ResultAccumulator], show_dups=False
) -> Table:
    """Make a new table."""
    table = Table(title="ENV RESULTS")
    table.add_column("Vendor")
    table.add_column("Binaries")
    table.add_column("[green]Binaries Alerted")
    table.add_column("Binaries Resolved")
    table.add_column("No Sinks")
    table.add_column("Total Alerts")
    table.add_column("[red]Error")
    table.add_column("[blue]Timeout")
    table.add_column("[yellow]OOM")
    table.add_column("Analysis Time", justify="right")

    selector = "dup" if show_dups else "uniq"
    for idx, vendor in enumerate(sorted(list(env_results))):
        data = env_results[vendor]
        vendor_time = datetime.timedelta(
            seconds=int(
                data.analysis_time[selector]
                + data.cfg_time[selector]
                + data.vra_time[selector]
            )
        )
        row = [vendor]
        styled_rows = data.make_table_rows(
            [
                ("", "binaries"),
                ("[green]", "binaries_alerted"),
                ("", "binaries_resolved"),
                ("", "no_sinks"),
                ("[green]", "total_alerts"),
                ("[red]", "error"),
                ("[blue]", "timeout"),
                ("[yellow]", "oom"),
            ],
            show_dup=show_dups,
        )
        row.extend(styled_rows)
        row.append(f"{vendor_time}")
        table.add_row(*row, end_section=idx == len(list(env_results)) - 1)

    table.add_row(
        "Total",
        str(sum(x.binaries[selector] for x in env_results.values())),
        f"[green]{sum(x.binaries_alerted[selector] for x in env_results.values())}",
        str(sum(x.binaries_resolved[selector] for x in env_results.values())),
        f"{sum(x.no_sinks[selector] for x in env_results.values())}",
        f"[green]{sum(x.total_alerts[selector] for x in env_results.values())}",
        f"[red]{sum(x.error[selector] for x in env_results.values())}",
        f"[blue]{sum(x.timeout[selector] for x in env_results.values())}",
        f"[yellow]{sum(x.oom[selector] for x in env_results.values())}",
        str(
            datetime.timedelta(
                seconds=int(
                    sum(
                        x.analysis_time[selector]
                        + x.cfg_time[selector]
                        + x.vra_time[selector]
                        for x in env_results.values()
                    )
                )
            )
        ),
    )
    return table
