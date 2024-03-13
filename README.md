# Operation Mango \[[Paper PDF](https://wilgibbs.com/papers/mango_usenix24.pdf)\] 

## Fast taint-style static analysis based vulnerability discovery

Common vulnerability discovery techniques all follow a top-down scheme: They start from the entry point of the target program, reach as deep as possible, and examine all encountered program states against a set of security violations. These vulnerability discovery techniques are all limited by the complexity of programs, and are all prone to the path/state explosion problem.

Alternatively, we can start from the location where vulnerabilities might occur (vulnerability sinks), trace back, and verify if the corresponding data flow may lead to a vulnerability. On top of this, we need “assumed execution”, which means when we are tracing back from a vulnerability sink to its sources, we do not faithfully execute or analyze every function on the path, instead we assume a data flow based on prior knowledge or some static analysis in advance and skip as many functions as possible during back tracing.

Checkout our [experiment reproduction section](ExperimentReplication.md) to reproduce all the figures found in the paper.

## Getting Started
There are several ways to run operation mango if you so choose.

### Docker
Bypass all this non-sense and just use the container.
> [!TIP]  
> Don't forget to add volumes with -v for both the binary and result directory
```
docker run -it cl4sm/operation-mango:latest
```

### Local
I highly recommend you create a separate python virtualenv for this method.
```bash
source venv/bin/activate
git clone https://github.com/sefcom/operation-mango-public.git
cd operation-mango-public
pip install .
```

To build the docker container locally:
```bash
cd operation-mango-public
docker build -f docker/Dockerfile . -t mango-user
```

## Using Operation Mango
Once you install Operation Mango or use the docker container, you'll have access to two commands: `mango` and `env_resolve`.

### mango
`mango` is your default command for running our basic taint analysis on binaries.
> [!TIP]
> Using the `--concise` will significantly shrink the output size and speed up analysis.  
> It will not print the entire analysis taint trace in your results, but normally you won't need that.
```
mango /path/to/bin --results your_res_dir
```
will run the basic command injection taint analysis, checkout the `--help` flag for more options.

### mango output structure
The output of this tool is fairly verbose, you'll be given the following:
> [!TIP]  
> Any values labeled as TOP are of unknown or unresolvable values

`{category}_mango.out` - The entire stdout/stderr of the mango run.  
`{category}_results.json` - The json is as follows:
```
{
    "closures": [
        {
            "trace": {} // Function trace starting from input down to sink
            "sink": {} // Sink location
            "depth": int
            "inputs": {
                "likely": [] //Functions that flow directly into the sink
                "possibly": [] //Functions seen along the way that generally are used as inputs
            }
            "rank": int // How confident are we this function is a TruPoC
        },
    ],
    "cfg_time": float // time it took to generate the cfg in seconds
    "vra_time": float // time it took to run the variable recovery in seconds
    "mango_time": float // time it took for actual mango analysis in seconds
    "path": str // path to analyzed binary
    "name": str // binary name
    "sha256": str // sha256 of the file
    "error": str|None // If an error occured print it here
    ... // Other timing info
}
```
`{category}_closures/` - The folder containing the results of individual flows to the sink, all of these are unresolvable by our tool.
`{category}_closures/0.{rank}_{entry_func@addr}_{sink_func@addr}` - The individual closures printed with extra information about likely and possible input sources.  
e.g. `0.70_main_0x403e70_system_0x40143c`:
```
|||system(
|||       a0: <BV32 0x4455f8> -> "<BV32 TOP>",
|||       ) @ 0x40143c -> <BV32 0x0>

INPUT SOURCES:
Likely:
NONE
Possibly:
----------
KEY: "accept(fd: 3)@0x403fb0_274_3"
Keywords: None
Binary Source - UNKNOWN
socket(AF_INET, SOCK_DGRAM, 0)_273_32
accept(fd: 3)@0x403fb0_274_32
recv(accept(fd: 3)@0x403fb0_274_32)@0x404088
----------
RANK: 0.700
```
`execv.json` - This is mostly unused but should contain info about which other processes this binary tries to execute.

### env_resolve
`env_resolve` performs a taint analysis of a given binary to find all uses of `env` and `nvram` variables.
This is what enables our cross-binary bug finding.
```
env_resolve /path/to/bin --results your_res_dir
```

The output of this tool will be found at `your_res_dir/env.json`.  
To feed this info into `mango` merge all of the env.json files together (even if there is only one) with
```bash
env_resolve /path/to/bin --results your_res_dir/env.json --merge
``` 

This will spit out the file `your_res_dir/env.json`.  
Then feed it into `mango`.

```bash
mango /path/to/bin --env-dict your_res_dir/env.json --results your_res_dir
```

### env_resolve output structure
The `env.json` output from `env_resolve` follows the `results.json` that `mango` outputs e.g.  
```
{
    "results": {
        "func_name": // i.e. nvram_get
            {
                "key_name": //key used to retrieve the value i.e. "http_passwd
                {
                    "keywords": str // Any frontend keywords used to retrieve this value
                    "1":  // position of the argument starting from "1" (i know...)
                    {
                        "arg_value": [ // arg value, in the case of getter funcs it's always the key name.
                            "0xaddr", // addr where the value is used

                        ]
                    }
                }

            }
    },
    "cfg_time": float // time it took to generate the cfg in seconds
    "vra_time": float // time it took to run the variable recovery in seconds
    "analysis_time": float // time it took for actual mango analysis in seconds
    "path": str // path to analyzed binary
    "name": str // binary name
    "sha256": str // sha256 of the file
    "error": str|None // If an error occured print it here
    ... // Other timing info
}
```

## Firmware Cross Binary and Frontend Keyword Bug Finding

If you're trying to find bugs in some firmware samples as described in our paper, then have a look at the `mango_pipeline` [`Here`](pipeline/README.md).  
For further examples of how to use this checkout the [Experiment Replication](ExperimentReplication.md) section.

## Testing

```bash
# run all the tests for the developed features (isolated in the `package` module)
pip install pytest-cov
pytest
```


### Handcrafted binaries

To ease testing, we crafted small binaries highlighting one (or several) case(s) we wanted to be able to handle properly.
It was particularly helpful to drive the development of the [`Handlers`](package/argument_resolver/handlers/).

They are located under the `package/tests/binaries/` folder.

| Binary                                    | Description                                                                                                               |
| ----------------------------------------  | ------------------------------------------------------------------------------------------------------------------------- |
| `after_values/program`                    | Contains multiple calls to a sink in a single function.                                                                   |
| `layered/program`                         | Nested calls running more than the default 7-depth limit before reaching the sink.                                        |
| `looper/program`                          | Runs a loop before reaching a sink.                                                                                       |
| `off_shoot/program`                       | Calls multiple functions that alter the input in sub functions before reaching the sink.                                  |
| `recursive/program`                       | Contains direct and in-direct recursive calls (Highlights flaw of unresolvable call-depth).                               |
| `nested/program`                          | Nested calls and returns before reaching a sink.                                                                          |
| `simple/program`                          | Contains call to external function `puts`. Run through nested functions, leading to different sinks (`execve`, `system`). |
| `sprintf_resolved_and_unresolved/program` | Contains two calls to `system`: one with constant data, the other one that could be influenced by the program user.       |


To ensure reproducibility of testing, the binaries have been added to the repository.
Although, if looking to add a new one, a `Makefile` has been written for convenience.
```bash
# build some homemade light binaries
cd binaries/ && make && cd -
```
