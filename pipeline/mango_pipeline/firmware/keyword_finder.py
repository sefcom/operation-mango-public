import sys
import re
import subprocess
import json
import string
import ipdb
import inspect


from typing import Set, Union
from pathlib import Path

import yaml
import esprima

from rich.progress import (
    Progress,
    TimeElapsedColumn,
    TextColumn,
)
from bs4 import BeautifulSoup

MIN_STRING_LENGTH = 3

text_endings = {
    ".cfg",
    ".conf",
    ".config",
    ".ini",
    ".init",
    ".txt",
}

bash_endings = {
    ".sh",
}

php_endings = {
    ".php",
    ".cgi",
}

js_endings = {
    ".js",
}

html_endings = {
    ".htm",
    ".html",
    ".asp",
}

object_endings = {".xml", ".json", ".yaml", ".yml"}

all_endings = (
    text_endings
    | php_endings
    | js_endings
    | html_endings
    | object_endings
    | bash_endings
)

current_progress = None

AVOID_KEYWORDS = {"true", "false", "static", "radio", "none", "disabled", "fixed"}


def bp_hook(*args, **kwargs):
    if current_progress is not None:
        current_progress.stop()

    frame = inspect.currentframe().f_back
    ipdb.set_trace(frame)


sys.breakpointhook = bp_hook


def strip_non_alpha(s) -> str:
    s = s.split("=")[0]
    s = s.split(":")[0]
    s = s.split(";")[0]
    stripped = re.sub(r"^[^a-zA-Z]+|[^a-zA-Z0-9]+$", "", s)
    if any(x in stripped for x in string.whitespace):
        return ""
    left = stripped.find("<")
    if left != -1:
        stripped = stripped[left + 1 :]

    right = stripped.rfind(">")
    if right != -1:
        stripped = stripped[:right]
    backslash = stripped.find("\\")
    if backslash != -1:
        stripped = stripped[:backslash]
    question = stripped.find("?")
    if question != -1 and question != len(stripped) - 1:
        stripped = stripped[question + 1 :]
    return stripped


def is_php(filename: Path) -> bool:
    with filename.open("r") as f:
        for line in f.readlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("<?"):
                return True
            else:
                return False
    return False


def get_strings_from_javascript(file: Union[Path, str]) -> Set[str]:
    try:
        if isinstance(file, str):
            tokens = esprima.tokenize(file)
            script = esprima.parse(file)
        else:
            tokens = esprima.tokenize(file.read_text())
            script = esprima.parse(file.read_text())
    except (esprima.error_handler.Error, UnicodeDecodeError):
        return set()

    pattern = re.compile(r'property:\s*{[^}]*name:\s*"([^"]*)"[^}]*}', re.DOTALL)

    # Find matches
    valid_strings = set()
    for obj_string in pattern.findall(str(script)):
        stripped = strip_non_alpha(obj_string)
        if len(stripped) > MIN_STRING_LENGTH:
            valid_strings.add(stripped)

    for token in tokens:
        if token.type == "String":
            stripped = strip_non_alpha(token.value)
            if len(stripped) > MIN_STRING_LENGTH:
                valid_strings.add(stripped)

    return valid_strings


def get_strings_from_html(file_path: Path, parser=None) -> Set[str]:
    try:
        soup = BeautifulSoup(file_path.read_text(), parser or "html.parser")
    except UnicodeDecodeError:
        return set()
    valid_strings = set()

    # Find all input tags and extract name and value attributes
    for input_tag in soup.find_all("input"):
        name = input_tag.get("name")
        if name:
            valid_strings.add(name)
        id_ = input_tag.get("id")
        if id_:
            valid_strings.add(id_)

    # Find all select tags and extract name attribute
    for select_tag in soup.find_all("select"):
        name = select_tag.get("name")
        if name:
            valid_strings.add(name)
        id_ = select_tag.get("id")
        if id_:
            valid_strings.add(id_)

    for script in soup.find_all("script"):
        if script.string:
            valid_strings |= get_strings_from_javascript(script.string)

    return valid_strings


def get_strings_from_php(file_path: Path) -> Set[str]:
    valid_strings = get_strings_from_html(file_path, parser="lxml")
    matches = re.findall(
        """\$_(?:GET|POST|SERVER)\[(?:"|')(.*)(?:"|')\]""", file_path.read_text()
    )
    valid_strings |= set(matches)

    return valid_strings


def get_strings_from_json(file_path: Path, data=None, strings=None) -> Set[str]:
    # Parses JSON and returns all keys that are strings
    strings = strings or set()
    try:
        data = data or json.loads(file_path.read_text())
    except json.decoder.JSONDecodeError:
        return strings
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(key, str):
                if len(key) > MIN_STRING_LENGTH:
                    strings.add(key)
            get_strings_from_json(file_path, value, strings)
    elif isinstance(data, list):
        for item in data:
            get_strings_from_json(file_path, item, strings)
    return strings


def get_strings_from_xml(file_path: Path) -> Set[str]:
    soup = BeautifulSoup(file_path.read_text(), "lxml-xml")
    tag_names = {tag.name for tag in soup.find_all(True)}
    return tag_names


def get_strings_from_object(file_path: Path) -> Set[str]:
    # if file_path.suffix == ".json":
    #    strings = get_strings_from_json(file_path)
    #    return strings
    # elif file_path.suffix == ".yml" or file_path.suffix == ".yaml":
    #    data = yaml.safe_load(file_path.read_text())
    #    strings = get_strings_from_json(file_path, data)
    #    return strings
    if file_path.suffix == ".xml":
        strings = get_strings_from_xml(file_path)
        return strings

    return set()


def find_potential_files(directory: Path):
    endings = []
    for idx, tup in enumerate([["-iname", "*" + ending] for ending in all_endings]):
        if idx > 0:
            endings.append("-o")
        endings.extend(tup)
    files = (
        subprocess.check_output(["find", directory, "-type", "f", *endings])
        .decode()
        .split("\n")
    )
    final_files = []
    for file in files:
        fp = Path(file)
        if not fp.exists():
            continue

        file_out = subprocess.check_output(["file", fp])
        is_ascii = b"ASCII" in file_out or b"Unicode text" in file_out
        if is_ascii:
            final_files.append(fp)

    return final_files


def find_keywords(firmware_dir: Path, progress=None):
    global current_progress
    had_progress = progress is not None
    progress = progress or Progress(transient=True)
    current_progress = progress
    find_task = progress.add_task("[green]Finding potential keyword files", total=1)
    files = find_potential_files(firmware_dir)
    progress.update(find_task, visible=False)

    string_dict = {}
    current_progress = progress
    task = progress.add_task("[green]Scanning files for keywords", total=len(files))
    for file in files:
        strings = set()
        progress.advance(task)

        if file.suffix in js_endings:
            if not file.exists():
                continue

            strings |= get_strings_from_javascript(file)

        elif file.suffix in php_endings:
            if is_php(file):
                strings |= get_strings_from_php(file)

        elif file.suffix in object_endings:
            strings |= get_strings_from_object(file)

        elif file.suffix in html_endings:
            strings |= get_strings_from_html(file)

        elif file.suffix in bash_endings:
            pass

        else:
            pass
        for s in strings:
            if s.lower() in AVOID_KEYWORDS:
                continue
            if s not in string_dict:
                string_dict[s] = []
            string_dict[s].append(file.name)

    progress.update(task, visible=False)
    if not had_progress:
        progress.stop()

    return string_dict


if __name__ == "__main__":
    import pprint

    print(f"Searching", sys.argv[1])
    keywords = find_keywords(Path(sys.argv[1]))
    pprint.pprint(keywords, indent=4)
    with open("keywords.json", "w+") as f:
        json.dump(keywords, f, indent=4)
