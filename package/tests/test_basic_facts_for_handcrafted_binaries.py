import json
import os
import pathlib
import re
import subprocess
import tempfile

import unittest


class TestBasicFactsForHandcraftedBinaries(unittest.TestCase):
    """
    Sanity checks over handcrafted binaries.
    Real-world binaries tests are usually a bit slower, and more involved, so it's more practical to keep them separate.
    """

    PROJECT_ROOT = pathlib.Path(__file__).parent.parent.absolute()

    def _run_analysis(self, name, expected_results, *args):
        binary_path = self.PROJECT_ROOT / "tests" / "binaries" / name / "program"
        with tempfile.TemporaryDirectory() as results_folder:
            p = subprocess.run(
                [
                    "mango",
                    binary_path,
                    "--disable-progress",
                    "--results",
                    results_folder,
                    *args,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            results_file = pathlib.Path(results_folder) / "cmdi_results.json"
            try:
                self.assertTrue(p.returncode == 0)  # Ran Successfully
                if "mango" in expected_results:
                    results = json.loads(results_file.read_text())

                    self.assertEqual(len(results["closures"]), len(expected_results["mango"]))

                    for expected_result in expected_results["mango"]:
                        matching_res = next(
                            (
                                x
                                for x in results["closures"]
                                if int(x["sink"]["ins_addr"], 16)
                                   == expected_result["call_addr"]
                            ),
                            None,
                        )
                        self.assertIsNotNone(matching_res)
                        self.assertEqual(
                            matching_res["sink"]["function"], expected_result["sink"]
                        )
                        self.assertEqual(matching_res["depth"], expected_result["depth"])

                if "execv" in expected_results:
                    exec_file = pathlib.Path(results_folder) / "execv.json"
                    results = json.loads(exec_file.read_text())
                    for expected_result in expected_results["execv"]:
                        print(results)
                        self.assertTrue(expected_result["bin"] in results["execv"])

                        name = expected_result["bin"]
                        num_args = len(results["execv"][name][0]["args"])
                        vuln_args = results["execv"][name][0]["vulnerable_args"]
                        self.assertEqual(num_args, expected_result["num_args"])
                        self.assertListEqual(vuln_args, expected_result["vuln_args"])

            except AssertionError as e:
                print("FAIL")
                print(p.stdout.decode())
                raise e

    def _run_env_analysis(self, name, bin_name, expected_results):
        binary_path = self.PROJECT_ROOT / "tests" / "binaries" / name / bin_name
        with tempfile.TemporaryDirectory() as results_folder:
            p = subprocess.run(
                [
                    "env_resolve",
                    binary_path,
                    "--disable-progress",
                    "--results",
                    results_folder,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            results_file = pathlib.Path(results_folder) / "env.json"
            try:
                self.assertTrue(p.returncode == 0)  # Ran Successfully
                results = json.loads(results_file.read_text())

                for expected_result in expected_results["env"]:
                    matching_res = next(
                        (
                            val_dict
                            for sink, val_dict in results["results"].items()
                            if sink == expected_result["sink"]
                        ),
                        None,
                    )
                    self.assertIsNotNone(matching_res)
                    for key_dict in expected_result["keys"]:
                        for key, args_dict in key_dict.items():
                            self.assertTrue(key in matching_res)
                            for arg, arg_dict in args_dict.items():
                                self.assertTrue(arg in matching_res[key])
                                self.assertTrue(arg_dict["value"] in matching_res[key][arg])
                                self.assertTrue(hex(arg_dict["loc"]) in matching_res[key][arg][arg_dict["value"]])
            except AssertionError as e:
                print("FAIL")
                print(p.stdout.decode())
                raise e

            subprocess.run(["env_resolve", results_folder, "--merge", "--results", "/tmp/env.json"])


    def test_simple_binary(self):
        name = "simple"
        expected_results = {
            "mango": [
                {"depth": 2, "sink": "system", "call_addr": 0x40115F},
                {"depth": 2, "sink": "execve", "call_addr": 0x401190},
            ]
        }
        self._run_analysis(name, expected_results)

    def test_looper_binary(self):
        name = "looper"
        expected_results = {
            "mango": [{"depth": 1, "sink": "system", "call_addr": 0x401166}]
        }
        self._run_analysis(name, expected_results)

    def test_nested_binary(self):
        name = "nested"
        expected_results = {
            "mango": [{"depth": 1, "sink": "system", "call_addr": 0x401165}]
        }
        self._run_analysis(name, expected_results)

    def test_sprintf_resolved_and_unresolved_binary(self):
        name = "sprintf_resolved_and_unresolved"
        expected_results = {
            "mango": [{"depth": 2, "sink": "system", "call_addr": 0x401266}]
        }
        self._run_analysis(name, expected_results)

    def test_layered_binary(self):
        name = "layered"
        expected_results = {
            "mango": [{"depth": 8, "sink": "system", "call_addr": 0x4012A3}]
        }
        self._run_analysis(name, expected_results, "--max-depth", "10")

    def test_off_shoot_binary(self):
        name = "off_shoot"
        expected_results = {
            "mango": [{"depth": 2, "sink": "system", "call_addr": 0x4013E6}]
        }
        self._run_analysis(name, expected_results)

    def test_recursion(self):
        name = "recursive"
        expected_results = {
            "mango": [{"depth": 2, "sink": "system", "call_addr": 0x4011D1}] * 2
        }
        self._run_analysis(name, expected_results)

    def test_nvram(self):
        name = "nvram"
        expected_results = {
            "mango": [{"depth": 1, "sink": "system", "call_addr": 0x40004C}],
            "env": [{"sink": "acosNvramConfig_set",
                     "keys": [{"command1":
                                   {"1":
                                        {"value": "ls -la",
                                         "loc": 0x401150}
                                    }
                               },
                              {"command2":
                                   {"1":
                                        {"value": "TOP",
                                         "loc": 0x40116d}
                                    }
                               }]
                     }]
        }

        self._run_env_analysis(name, "keys", expected_results)

        env_file = "/tmp/env.json"
        self._run_analysis(name, expected_results, "--env-dict", env_file)
        os.unlink(env_file)

    def test_heap(self):
        name = "heap"
        expected_results = {
            "mango": [{"depth": 1, "sink": "system", "call_addr": 0x401225}]
        }
        self._run_analysis(name, expected_results)

    def test_wrapper_funcs(self):
        name = "wrapper"
        expected_results = {
            "mango": [{"depth": 2, "sink": "system", "call_addr": 0x4011A5}] * 2
        }
        self._run_analysis(name, expected_results)

    def test_early_resolve(self):
        name = "early_resolve"
        expected_results = {
            "mango": [
                {"depth": 1, "sink": "system", "call_addr": 0x4012FE},
                {"depth": 2, "sink": "system", "call_addr": 0x401200},
            ],
        }
        self._run_analysis(name, expected_results)

    def test_execve_resolve(self):
        name = "execve"
        expected_results = {
            "execv": [{"bin": "other_prog", "num_args": 3, "vuln_args": [2]}]
        }
        self._run_analysis(name, expected_results)

    def test_execlp_resolve(self):
        name = "execlp"
        expected_results = {
            "execv": [{"bin": "echo", "num_args": 3, "vuln_args": [2]}]
        }
        self._run_analysis(name, expected_results)
