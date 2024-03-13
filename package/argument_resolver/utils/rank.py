from itertools import combinations
from functools import reduce

tag_values = {
    "env": 0.7,
    "file": 0.5,
    "argv": 0.4,
    "network": 0.6,
    "unknown": 0,
}

categories = {
    "env": ["env", "getenv", "nvram", "frontend_param", "getvalue"],
    "file": ["fopen", "read", "open", "fread", "fgets", "stdin"],
    "argv": ["argv"],
    "network": ["socket", "accept", "recv", "nflog_get_payload"],
    "unknown": ["unknown"],
}


def calc_probability(tags):
    valid_tags = set()
    for tag in tags:
        for category, funcs in categories.items():
            if tag in funcs:
                valid_tags.add(category.lower())

    if len(tags) == 0:
        return tag_values["unknown"]
    elif len(tags) == 1:
        return tag_values[next(iter(valid_tags))]

    probability = max(tag_values[x] for x in valid_tags)
    return probability


def get_value_from_source(tag):
    func = tag.split("(")[0].lower()
    func = "nvram" if "nvram" in func else func
    func = "recv" if "recv" in func else func
    for category, funcs in categories.items():
        if func in funcs:
            return tag_values[category]
    return 0


def get_rank(sources):
    return {source: get_value_from_source(source) for source in sources}
