# Mango Pipeline

This package is specifically for running operation mango on large datasets for maximum parallelization

## Installation

Run `pip install -e .` (Note: mango must already be installed and this can only be installed with `-e`)

The `mango-pipeline` utility is now available for your use.

## Layout

`mango-pipeline` expects either a flat directory filled with binaries or a structured directory.
This tool was specifically built to tackle firmware, you can try your luck with other usecases.
If you are attempting to run this tool on multiple firmware, this is the directory structure you will want to use:
```
root_dir/
    vendor_name/
        firmware_name/
            .....
                squashfs-root/
```

## Usage

This package allows you to run a parallelized version of mango either locally or remotely.

You'll always want these two options filled out.

`mango-pipeline --path /directory/to/analyze --results /output_dir`

If you want to run a parallelized workload locally, try doing something like this:

```mango-pipeline --path /directory/to/analyze --results /output_dir --build-docker --full --parallel NUM_CONTAINERS --categories cmdi```

If you're attempting to run this on a remote kubernetes cluster, first edit the `mango_pipeline/configs/pipeline.toml` with your cluster information.
> [!CAUTION]  
> This is probably super broken as it was tailored to my exact setup, try the docker container version.   
> Attempting this route is pain and you have been warned.

First run the environment analysis:

```mango-pipeline --path /directory/to/analyze --results /output_dir --build-docker --kube --env --parallel NUM_CONTAINERS```

Download the results:

```mango-pipeline --path /directory/to/analyze --results /output_dir --kube --download-results```

Run the analysis:

```mango-pipeline --path /directory/to/analyze --results /output_dir --kube --mango --categories cmdi --parallel NUM_CONTAINERS```

Download the final results:

```mango-pipeline --path /directory/to/analyze --results /output_dir --kube --download-results```

### Local
`--build-docker` - You only need to run this once unless you're editing the codebase.
This will build the docker container found in the `docker` folder in the root of this project.

### Remote
`--kube` - This option forces all work to be done on a remote kubernetes setup.
Use `--build-docker` it will attempt to push the container to the remote docker repository denoted in the `mango_pipeline/configs` folder. (unstable)

### Output
`--status` - A static printout of how many results there are, how many have errored and which vendor/firmware the results belong to.

`--gen-csv` - Generate a CSV file of all the results.

`--aggregate-results AGG_FOLDER` - Generate a folder of all the unique results with potential bugs
