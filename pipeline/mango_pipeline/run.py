#!/usr/bin/env python
import argparse
import sys

from pathlib import Path

from mango_pipeline import PipelineRemote, PipelineLocal, PipelineKube
from argument_resolver.external_function.sink import VULN_TYPES


def cli_args():
    parser = argparse.ArgumentParser()
    path_group = parser.add_argument_group(
        "Path Args", "Deciding source and result destination"
    )
    run_group = parser.add_argument_group(
        "Running", "Options that modify how mango runs"
    )
    output_group = parser.add_argument_group(
        "Output", "Options to increase or modify output"
    )
    path_group.add_argument(
        "--path", default=None, help="Binary or Directory of binaries to analyze"
    )
    path_group.add_argument(
        "--results",
        dest="result_folder",
        default="./results",
        help="Where to store the results of the analysis. (Default: ./results)",
    )
    path_group.add_argument(
        "--download-results",
        dest="download",
        action="store_true",
        default=False,
        help="Download the latest results from remote server",
    )
    output_group.add_argument(
        "--status",
        dest="status",
        default=False,
        action="store_true",
        help="Display current status of either results folder or kube",
    )

    output_group.add_argument(
        "--show-dups",
        dest="show_dups",
        default=False,
        action="store_true",
        help="Include duplicates in status (Only applies to --status flag)",
    )

    output_group.add_argument(
        "--verbose",
        dest="verbose",
        action="store_true",
        default=False,
        help="Print STDOUT as operation runs (single target only)",
    )
    output_group.add_argument(
        "--build-docker",
        dest="build_docker",
        action="store_true",
        default=False,
        help="Build Docker Container (Requires internet access if kube)",
    )
    output_group.add_argument(
        "--gen-csv",
        dest="csv",
        action="store_true",
        default=False,
        help="Explicitly generate CSV with current results",
    )

    output_group.add_argument(
        "--show-errors",
        dest="show_errors",
        action="store_true",
        default=False,
        help="Show table of errors for local results",
    )
    output_group.add_argument(
        "--aggregate-results",
        dest="agg_results",
        default=None,
        help="Aggregate all results into a single folder [Requires: --results]",
    )

    output_group.add_argument(
        "--py-spy",
        dest="py_spy",
        default=False,
        action="store_true",
        help="Enable PySpy data logging",
    )

    run_group.add_argument(
        "--category",
        dest="sink_category",
        default="cmdi",
        choices=VULN_TYPES.keys(),
        help="Analyze sinks from category",
    )

    run_group.add_argument(
        "--kube",
        dest="kube",
        action="store_true",
        default=False,
        help="Run experiment on the cluster",
    )
    run_group.add_argument(
        "--env",
        dest="is_env",
        action="store_true",
        default=False,
        help="Run env resolver",
    )
    run_group.add_argument(
        "--mango",
        dest="is_mango",
        action="store_true",
        default=False,
        help="Run mango",
    )
    run_group.add_argument(
        "--full",
        dest="is_full",
        action="store_true",
        default=False,
        help="Run full pipeline (Not recommended for remote workloads)",
    )
    run_group.add_argument(
        "--parallel",
        dest="parallel",
        default=1,
        type=int,
        help="Run experiment on the cluster",
    )
    run_group.add_argument(
        "--brand",
        dest="brand",
        default="",
        type=str,
        help="Select specific brand to run experiments on",
    )
    run_group.add_argument(
        "--firmware",
        dest="firmware",
        default="",
        type=str,
        help="Select specific firmware to run experiments on (Brand Must Be Set)",
    )

    run_group.add_argument(
        "--extra-args",
        dest="extra_args",
        default=[],
        nargs="+",
        help="Extra args to run analysis with",
    )

    run_group.add_argument(
        "--job-name",
        dest="job_name",
        default="mango-job",
        type=str,
        help="Job Name used for kubernetes",
    )

    run_group.add_argument(
        "--timeout",
        dest="timeout",
        default=3 * 60 * 60,
        type=int,
        help="Timeout for each container/pod (Default: 3hrs)",
    )
    run_group.add_argument(
        "--rda-timeout",
        dest="rda_timeout",
        default=5 * 60,
        type=int,
        help="Timeout for each sub analysis in a job (Default: 5min)",
    )

    run_group.add_argument(
        "--bin-prep",
        dest="bin_prep",
        default=False,
        action="store_true",
        help="Find binaries and symbols in firmware (Happens automatically with other options)",
    )
    run_group.add_argument(
        "--giga-kube",
        dest="giga_kube",
        default=False,
        action="store_true",
        help="Reserved for only the largest datasets",
    )

    run_group.add_argument(
        "--include-libs",
        dest="exclude_libs",
        default=True,
        action="store_false",
        help="Include libraries in the analysis",
    )

    return parser


def main():
    parser = cli_args()
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        exit(-2)

    path = Path(args.path) if args.path else None
    results_dir = Path(args.result_folder)

    if args.kube:
        pipeline_class = PipelineRemote
    elif args.giga_kube:
        pipeline_class = PipelineKube
        args.kube = True
    else:
        pipeline_class = PipelineLocal

    pipeline = pipeline_class(
        path,
        results_dir,
        parallel=args.parallel,
        quiet=not args.verbose,
        is_env=args.is_env or args.is_full,
        is_mango=args.is_mango or args.is_full,
        category=args.sink_category,
        brand=args.brand,
        firmware=args.firmware,
        extra_args=args.extra_args,
        job_name=args.job_name,
        py_spy=args.py_spy,
        timeout=args.timeout,
        rda_timeout=args.rda_timeout,
        bin_prep=args.bin_prep,
        exclude_libs=args.exclude_libs,
        show_dups=args.show_dups,
    )

    if args.build_docker:
        pipeline.build_container()

    if args.kube and args.status and args.job_name:
        pipeline.watch_job(args.job_name, "clasm")
        return

    if results_dir.exists():
        if args.status:
            pipeline.print_status()
            return
        elif args.show_errors:
            if not args.kube:
                pipeline.print_errors()

    if args.download and args.kube:
        pipeline.download_new_results()

    if args.agg_results is not None and results_dir.exists():
        pipeline.prep_results(results_dir, Path(args.agg_results), args.category)

    if args.csv or args.agg_results is not None:
        if args.agg_results is not None:
            pipeline.results_dir = Path(args.agg_results)
        pipeline.mango_results_to_csv()

    if path is None:
        exit(-1)

    pipeline.run_experiment()


if __name__ == "__main__":
    main()
