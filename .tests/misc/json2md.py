#!/usr/bin/python3

from io import StringIO
from json import loads
from glob import glob
from pytablewriter import MarkdownTableWriter


def print_md_table(settings) -> MarkdownTableWriter:
    writer = MarkdownTableWriter(
        headers=["Setting", "Default", "Context", "Multiple", "Description"],
        value_matrix=[
            [
                f"`{setting}`",
                "" if data["default"] == "" else f"`{data['default']}`",
                data["context"],
                "no" if "multiple" not in data else "yes",
                data["help"],
            ]
            for setting, data in settings.items()
        ],
    )
    return writer


def stream_support(support) -> str:
    md = "STREAM support "
    if support == "no":
        md += ":x:"
    elif support == "yes":
        md += ":white_check_mark:"
    else:
        md += ":warning:"
    return md


doc = StringIO()

# Print plugin settings
core_settings = {}
for core in glob("*/plugin.json"):
    with open(core, "r") as f:
        core_plugin = loads(f.read())
        if len(core_plugin["settings"]) > 0:
            core_settings[core_plugin["name"]] = core_plugin

for name, data in dict(sorted(core_settings.items())).items():
    print(f"### {data['name']}\n", file=doc)
    print(f"{stream_support(data['stream'])}\n", file=doc)
    print(f"{data['description']}\n", file=doc)
    print(print_md_table(data["settings"]), file=doc)

doc.seek(0)
content = doc.read()
doc = StringIO(content.replace("\\|", "|"))
doc.seek(0)

print(doc.read())
