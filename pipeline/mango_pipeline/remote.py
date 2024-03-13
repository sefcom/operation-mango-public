import base64
import json
import os
import time
import toml

from typing import Set
from pathlib import Path
from zipfile import ZipFile

import docker

from rich.console import Console
from rich.table import Table
from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TaskProgressColumn,
    TransferSpeedColumn,
    TimeRemainingColumn,
)

from kubernetes import config, watch
from kubernetes import client as kube_client

from kubernetes.client import (
    V1ResourceRequirements,
    V1PersistentVolumeClaimVolumeSource,
    V1VolumeMount,
    V1Volume,
    V1Container,
    V1EnvVar,
    V1PodTemplateSpec,
    V1PodSpec,
    V1ObjectMeta,
    V1Job,
    V1JobSpec,
    V1LocalObjectReference,
    V1DeleteOptions,
)

from .base import Pipeline, MyProgress, ELFInfo
from .firmware.elf_finder import FirmwareFinder


class PipelineRemote(Pipeline):
    """
    Pipeline process for running experiments on a remote kubernetes setup
    (Tailored specifically for @Clasm's setup: buyer beware)
    """

    REMOTE_DIR = Path("/tank/kubernetes/clasm")
    REMOTE_RESULT_DIR = REMOTE_DIR / "mango-results"
    KUBE_MOUNT_DIR = Path("/shared")
    KUBE_RESULT_DIR = KUBE_MOUNT_DIR / "clasm" / "mango-results"
    SSH_SERVER = "nfs_server"

    def __init__(self, *args, quiet=True, parallel=500, watch=None, **kwargs):
        super().__init__(*args, parallel=parallel, **kwargs)

        config_path = Path(__file__).parent.absolute() / "configs" / "pipeline.toml"
        if not config_path.exists():
            self.create_default_config(config_path)

        self.config = toml.loads(config_path.read_text())

        self.REMOTE_RESULT_DIR = self.REMOTE_DIR / self.results_dir.name
        self.KUBE_RESULT_DIR = self.KUBE_MOUNT_DIR / "clasm" / self.results_dir.name
        config.load_kube_config()
        self.api_client = kube_client.ApiClient()
        self.k8_client = kube_client.CoreV1Api(self.api_client)
        self._get_time = time.time
        self.job_status = {
            "name": "Unknown",
            "status": "Unknown",
            "active": None,
            "failed": None,
            "succeeded": None,
        }
        if self.target:
            self.remote_target = self.REMOTE_DIR / self.target.name

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

        if watch is not None:
            self.watch_job(job_name=watch, namespace="clasm")

    def build_container(self):
        super().build_container()
        self.push_container()

    def push_container(self):
        """
        Pushes built container to repository
        """

        client = docker.from_env()
        image = client.images.get(self.container_name)
        success = image.tag(self.config["remote"]["registry_image"])
        if not success:
            with Console() as console:
                console.print("[red bold]Failed to tag container")
            return

        push_info = {}
        resp = client.images.push(
            self.config["remote"]["registry_image"],
            auth_config=self.config["remote"]["auth_config"],
            stream=True,
            decode=True,
        )

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            transient=True,
        ) as progress:
            for line in resp:
                if "status" in line and line["status"] == "Pushing":
                    item_id = line["id"]

                    info = line["progressDetail"]
                    current = info["current"]
                    total = info["total"] if "total" in info else None
                    if item_id in push_info:
                        progress.update(
                            push_info[item_id], completed=current, total=total
                        )
                    else:
                        push_info[item_id] = progress.add_task(
                            description=f"Pushing {item_id}",
                            completed=current,
                            total=total,
                        )
                else:
                    if "errorDetail" in line:
                        progress.print(line)
        Console().print(
            f"[green]Pushed Container to {self.config['remote']['registry_image']}!"
        )

    def run_mango(self, targets: Set[ELFInfo]):

        # self.env_merge()
        job_name = "mango-job" if self.job_name is None else self.job_name
        self.upload_targets(targets)
        self.upload_current_results(targets, "mango")

        self.create_job(completions=len(targets), job_name=job_name)

        self.watch_job(job_name=job_name, namespace="clasm")
        self.download_new_results()

    def translate_local_to_remote_targets(self, targets: Set[ELFInfo]):
        remote_targets = set()
        for target in targets:
            root_path = self.target.absolute().resolve()
            remote_root_path = self.KUBE_MOUNT_DIR / "clasm" / self.target.name
            target_path = Path(target.path).absolute().resolve()

            remote_path = str(target_path).replace(
                str(root_path), str(remote_root_path)
            )
            remote_ld_paths = [
                x.replace(str(root_path), str(remote_root_path))
                for x in target.get_lib_locations()
            ]
            remote_target = ELFInfo(
                path=remote_path,
                brand=target.brand,
                firmware=target.firmware,
                sha=target.sha,
                ld_paths=remote_ld_paths,
            )

            remote_targets.add(remote_target)
        return remote_targets

    def upload_targets(self, targets: Set[ELFInfo]):
        """
        Zips targets and extracts it at the remote dir, preserving path
        :param local_dir_loc:
        :param remote_dir_loc:
        :param targets:
        :return:
        """
        temp_loc = Path("/tmp") / f"{self.target.name}.zip"

        with MyProgress() as progress:
            zip_task = progress.add_task("Zipping...", total=len(targets))
            with ZipFile(temp_loc, "w") as zip_obj:
                resolved_path = self.target.absolute().resolve()
                for target in targets:
                    p = Path(
                        target.path.replace(str(resolved_path), resolved_path.name)
                    )
                    zip_obj.write(target.path, str(p))
                    progress.update(zip_task, advance=1)

        self.console_subprocess(["scp", temp_loc, f"{self.SSH_SERVER}:{temp_loc}"])
        self.console_subprocess(
            ["ssh", self.SSH_SERVER, "unzip", "-o", temp_loc, "-d", self.REMOTE_DIR]
        )
        self.console_subprocess(["ssh", self.SSH_SERVER, "rm", temp_loc])
        os.remove(temp_loc)

    def upload_current_results(self, targets: Set[ELFInfo], script: str):

        remote_targets = self.translate_local_to_remote_targets(targets)

        experiment_json = dict()
        experiment_json["script"] = script
        experiment_json["timeout"] = self.timeout
        experiment_json["rda_timeout"] = self.rda_timeout
        experiment_json["category"] = self.category
        experiment_json["targets"] = {
            idx: target.to_dict() for idx, target in enumerate(remote_targets)
        }
        experiment_json["result_dest"] = str(self.KUBE_RESULT_DIR)
        experiment_json["target_dir"] = "/tmp"

        self.results_dir.mkdir(exist_ok=True, parents=True)
        with (self.results_dir / f"{self.category}_experiment_list.json").open(
            "w+"
        ) as f:
            json.dump(experiment_json, f, indent=4)

        results_zip = Path("/tmp/results.zip")
        self.console_subprocess(
            ["zip", "-r", results_zip, self.results_dir.name],
            cwd=self.results_dir.parent,
        )
        self.console_subprocess(
            ["scp", results_zip, f"{self.SSH_SERVER}:{results_zip}"]
        )
        self.console_subprocess(
            ["ssh", self.SSH_SERVER, "unzip", "-o", results_zip, "-d", self.REMOTE_DIR]
        )
        self.console_subprocess(["ssh", self.SSH_SERVER, "rm", results_zip])
        os.remove(results_zip)

    def download_new_results(self):
        results_zip = Path("/tmp/results.zip")
        self.console_subprocess(
            [
                "ssh",
                self.SSH_SERVER,
                "cd",
                self.REMOTE_DIR,
                "&&",
                "zip",
                "-r",
                results_zip,
                self.REMOTE_RESULT_DIR.name,
            ]
        )
        self.console_subprocess(
            ["scp", f"{self.SSH_SERVER}:{results_zip}", results_zip]
        )
        self.console_subprocess(
            ["unzip", "-o", results_zip, "-d", self.results_dir.parent]
        )
        self.console_subprocess(["ssh", self.SSH_SERVER, "rm", results_zip])
        os.remove(results_zip)

    def run_env_resolve(self, targets: Set[ELFInfo]):

        job_name = "env-resolve-job" if self.job_name is None else self.job_name
        self.upload_targets(targets)
        self.upload_current_results(targets, "env_resolve")

        self.create_job(completions=len(targets), job_name=job_name)

        self.watch_job(job_name=job_name, namespace="clasm")
        self.download_new_results()

    def parse_mango_result(self, res_file, target):
        pass

    def create_job(
        self,
        completions: int,
        job_name="mango-job",
        cpu_min="1000m",
        cpu_max="1000m",
        mem_min="5Gi",
    ):
        # Container should grab the indexed job
        share_name = "nfs-shared"
        claim_name = "nfs"

        self.create_registry_secret()

        resources = V1ResourceRequirements(
            requests={"memory": mem_min, "cpu": cpu_min}, limits={"cpu": cpu_max}
        )

        container_volume_mounts = [
            V1VolumeMount(name=share_name, mount_path=str(self.KUBE_MOUNT_DIR))
        ]

        env = [V1EnvVar(name="KUBE", value="True")]
        if self.extra_args:
            env += [
                V1EnvVar(
                    name="EXTRA_ARGS",
                    value=json.dumps(["--" + x for x in self.extra_args]),
                )
            ]
        if self.py_spy:
            env += [V1EnvVar(name="PYSPY", value="")]

        container = V1Container(
            name="mango-worker",
            image=self.config["remote"]["registry_image"],
            env=env,
            command=[
                "/entrypoint.py",
                str(self.KUBE_RESULT_DIR / f"{self.category}_experiment_list.json"),
            ],
            resources=resources,
            volume_mounts=container_volume_mounts,
        )

        # Create and configure a spec section
        nfs_volume = V1Volume(
            name=share_name,
            persistent_volume_claim=V1PersistentVolumeClaimVolumeSource(
                claim_name=claim_name
            ),
        )

        template = V1PodTemplateSpec(
            metadata=V1ObjectMeta(labels={"app": "operation-mango"}),
            spec=V1PodSpec(
                containers=[container],
                volumes=[nfs_volume],
                restart_policy="Never",
                image_pull_secrets=[
                    V1LocalObjectReference(
                        name=self.config["remote"]["registry_secret_name"]
                    )
                ],
            ),
        )

        # Create the specification of deployment

        spec = V1JobSpec(
            template=template,
            completions=completions,
            completion_mode="Indexed",
            backoff_limit=completions,
            parallelism=self.parallel,
        )

        # Instantiate the job object
        job = V1Job(
            api_version="batch/v1",
            kind="Job",
            metadata=V1ObjectMeta(name=job_name),
            spec=spec,
        )

        batch_api = kube_client.BatchV1Api()
        while True:
            try:
                batch_api.create_namespaced_job(body=job, namespace="clasm")
                break
            except kube_client.exceptions.ApiException as e:
                if e.reason == "Conflict":
                    Console().print(f"Attempting to delete {job_name}")
                    self.delete_job(batch_api, job_name)
                    time.sleep(30)
                    batch_api.create_namespaced_job(body=job, namespace="clasm")

    def create_registry_secret(self):
        auth = base64.b64encode(
            f"{self.config['remote']['auth_config']['username']}:{self.config['remote']['auth_config']['password']}".encode(
                "utf-8"
            )
        ).decode("utf-8")

        docker_config_dict = {
            "auths": {
                self.config["remote"]["registry"]: {
                    "username": self.config["remote"]["auth_config"]["username"],
                    "password": self.config["remote"]["auth_config"]["password"],
                    "auth": auth,
                }
            }
        }

        docker_config = base64.b64encode(
            json.dumps(docker_config_dict).encode("utf-8")
        ).decode("utf-8")

        try:
            self.k8_client.create_namespaced_secret(
                namespace="clasm",
                body=kube_client.V1Secret(
                    metadata=kube_client.V1ObjectMeta(
                        name=self.config["remote"]["registry_secret_name"],
                    ),
                    type="kubernetes.io/dockerconfigjson",
                    data={".dockerconfigjson": docker_config},
                ),
            )
        except kube_client.exceptions.ApiException as e:
            if e.reason != "Conflict":
                raise e

    @staticmethod
    def delete_job(api_instance, job_name):
        api_response = api_instance.delete_namespaced_job(
            name=job_name,
            namespace="clasm",
            body=V1DeleteOptions(
                propagation_policy="Foreground", grace_period_seconds=5
            ),
        )
        Console().print(f"[bold red]Job deleted. status='{api_response.status}'")

    def gen_job_table(self):
        # Display the job status in a table
        table = Table(
            title=f"{self.job_status['name']} Status - {self.job_status['status']}",
            min_width=100,
        )
        table.add_column("Status", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_row("Active", str(self.job_status["active"] or 0))
        table.add_row("Succeeded", str(self.job_status["succeeded"] or 0))
        table.add_row("Failed", str(self.job_status["failed"] or 0))

        return table

    def get_time(self):
        return self._get_time()

    def print_status(self):
        self.watch_job(self.job_name, "clasm")

    def watch_job(self, job_name, namespace):
        # Load the kubeconfig file
        config.load_kube_config()

        # Set up the Kubernetes API client
        api = kube_client.BatchV1Api()

        # Create a watch object
        job_watch = watch.Watch()

        # Watch for events related to the specified job
        self.job_status["name"] = job_name
        with MyProgress(
            renderable_callback=self.gen_job_table, get_time=time.time
        ) as progress:
            progress_bar = None
            done = False
            while not done:
                for event in job_watch.stream(
                    api.list_namespaced_job, namespace=namespace, timeout_seconds=None
                ):
                    job = event["object"]

                    if job.metadata.name == job_name:
                        job_status = job.status
                        self.job_status["status"] = event["type"]
                        self.job_status["active"] = job_status.active
                        self.job_status["succeeded"] = job_status.succeeded
                        self.job_status["failed"] = job_status.failed

                        completed = job_status.succeeded or 0
                        total = job.spec.completions

                        if progress_bar is None:
                            self._get_time = (
                                lambda: time.time() - job_status.start_time.timestamp()
                            )
                            progress_bar = progress.add_task(
                                description=f"[cyan] Running {job_name}..."
                            )
                            try:
                                progress._tasks[
                                    progress_bar
                                ].start_time = job_status.start_time.timestamp()
                                if total == completed:
                                    start_time = job_status.start_time.timestamp()
                                    end_time = job_status.completion_time.timestamp()
                                    progress._tasks[
                                        progress_bar
                                    ].start_time = time.time() - (end_time - start_time)
                            except AttributeError:
                                pass
                            progress.start_task(progress_bar)

                        progress.update(progress_bar, completed=completed, total=total)

                        # Stop watching the job when it's complete
                        if total == completed:
                            job_watch.stop()
                            progress.print(f"Job {job_name} completed.")
                            done = True
                            break

                time.sleep(5)
