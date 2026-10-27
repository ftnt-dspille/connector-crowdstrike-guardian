#!/usr/bin/env python3
"""Regenerate the generated sections of README.md.

    python3 scripts/gen_docs.py          # rewrite README.md in place
    python3 scripts/gen_docs.py --check  # exit 1 if README.md is out of date

Everything between <!-- BEGIN GENERATED --> and <!-- END GENERATED --> comes
from info.json. tests/test_docs.py runs --check, so the README cannot drift
from the manifest.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
INFO_PATH = os.path.join(ROOT, "crowdstrike_guardian", "info.json")
README = os.path.join(ROOT, "README.md")

BEGIN = "<!-- BEGIN GENERATED -->"
END = "<!-- END GENERATED -->"

GROUPS = [
    (
        "AI agent inventory (AI entity store)",
        [
            "list_ai_agents",
            "get_ai_agent",
            "list_agent_sessions",
            "get_agent_sessions",
            "list_agent_installations",
            "get_agent_installations",
            "list_os_users",
            "get_os_user",
            "list_tools",
            "get_tools",
            "list_skills",
            "get_skills",
            "list_mcp_server_names",
            "list_model_names",
        ],
    ),
    (
        "Per-invocation activity (LogScale-backed)",
        [
            "list_executions",
            "get_execution_detail",
            "list_tool_usage",
            "list_skill_usage",
            "list_prompts",
        ],
    ),
    (
        "Agentic graph (ThreatGraph)",
        [
            "get_session_activity",
            "get_process_tree",
            "get_network_events",
            "get_file_events",
            "get_classified_file_access",
        ],
    ),
    ("Detections", ["list_ai_detections", "get_detection_scores"]),
    (
        "Fleet rollups (aggregates)",
        [
            "get_agent_product_counts",
            "get_session_product_counts",
            "get_tool_name_counts",
            "get_skill_name_counts",
            "get_tool_usage_counts",
            "get_skill_usage_counts",
            "get_fleet_inventory",
        ],
    ),
    ("Ingestion", ["ingest_ai_detections"]),
]


def cell(text):
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ") or "-"


def param_row(param):
    required = "yes" if param.get("required") else "no"
    kind = param["type"]
    extra = ""
    if param.get("apiOperation"):
        extra = " (dropdown, filled by `{}`)".format(param["apiOperation"])
    default = param.get("value")
    if default is not None and default != "":
        extra += f" (default `{default}`)"
    return "| `{}` | {} | {} | {} | {} |".format(
        param["name"], cell(param["title"]), kind, required, cell(param["description"]) + extra
    )


def render():
    info = json.load(open(INFO_PATH))
    ops = {o["operation"]: o for o in info["operations"]}
    out = []

    def line(text=""):
        out.append(text)

    line("### Configuration")
    line()
    line("| Field | Type | Required | Default | Description |")
    line("|---|---|---|---|---|")
    for field in info["configuration"]["fields"]:
        default = field.get("value")
        if field["type"] == "password":
            default = ""
        default = (f"`{default}`") if default not in (None, "", [], {}) else "-"
        line(
            "| `{}` | {} | {} | {} | {} |".format(
                field["name"],
                field["type"],
                "yes" if field.get("required") else "no",
                default,
                cell(field["description"]),
            )
        )
    line()
    line(
        "The Cloud field carries an onchange rule: picking *Custom (base URL below)* "
        "reveals a required **Base URL** field for deployments not covered by the dropdown."
    )
    line()

    for group, names in GROUPS:
        line(f"### {group}")
        line()
        for name in names:
            op = ops[name]
            line("#### {}`{}`".format("(hidden) " if not op.get("visible", True) else "", name))
            line()
            line(op["description"])
            line()
            if op["parameters"]:
                line("| Parameter | Title | Type | Required | Description |")
                line("|---|---|---|---|---|")
                for param in op["parameters"]:
                    line(param_row(param))
            else:
                line("No parameters.")
            line()

    line("### Output conventions")
    line()
    line(
        "- List actions return `records` (the API records, original field names), "
        "`count`, `pagination` when the API paged, and `notices` when something had "
        "to be adjusted (a narrowed time range, a truncated aggregate)."
    )
    line("- Get actions return `record`.")
    line(
        "- Aggregates return rows of `label`/`count` (or `product`/`count`, "
        "`tool`/`count`, `skill`/`count`); counts arrive as JSON strings from the "
        "API and are returned as numbers."
    )
    line(
        "- `get_fleet_inventory` returns `agents_by_product`, `sessions_by_product`, "
        "`tools_by_name`, `skills_by_name` and a `detections` rollup."
    )
    line()
    return "\n".join(out)


def main():
    check = "--check" in sys.argv
    current = open(README).read()
    start = current.index(BEGIN) + len(BEGIN)
    stop = current.index(END)
    updated = current[:start] + "\n" + render() + current[stop:]
    if check:
        if updated != current:
            print("README.md is out of date; run python3 scripts/gen_docs.py")
            return 1
        print("README.md is current")
        return 0
    open(README, "w").write(updated)
    print(f"rewrote {README}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
