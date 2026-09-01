"""Build the demonstration control subset from a pinned NIST OSCAL catalog."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path
from xml.etree import ElementTree as ET

import yaml

OSCAL_NAMESPACE = "http://csrc.nist.gov/ns/oscal/1.0"
NS = {"o": OSCAL_NAMESPACE}

SOURCE_TAG = "v1.4.0"
SOURCE_COMMIT = "bc8a528770033611df899b3d52703fb3dc91a20d"
SOURCE_SHA256 = "341f7dd2636b89b6d54b51fcf090e4cd18459b9e4ef4798f854f1a918023a650"
SOURCE_URL = (
    "https://github.com/usnistgov/oscal-content/blob/v1.4.0/"
    "src/nist.gov/SP800-53/rev5/xml/NIST_SP-800-53_rev5_catalog.xml"
)

SELECTED_CONTROL_IDS = (
    "ac-1",
    "ac-2",
    "ac-3",
    "ac-6",
    "ac-7",
    "ia-1",
    "ia-2",
    "ia-2.1",
    "ia-2.2",
    "ia-5",
    "ia-5.1",
    "ia-6",
    "au-1",
    "au-2",
    "au-3",
    "au-6",
    "cm-1",
    "cm-2",
    "cm-6",
    "cm-7",
)


class LiteralDumper(yaml.SafeDumper):
    """Emit multiline strings as readable YAML literal blocks."""


def _represent_string(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


LiteralDumper.add_representer(str, _represent_string)


def _local_name(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _parameter_labels(control: ET.Element) -> dict[str, str]:
    parameters = control.findall("o:param", NS)
    labels = {parameter.get("id", ""): parameter.get("id", "parameter") for parameter in parameters}

    for _ in range(2):
        for parameter in parameters:
            parameter_id = parameter.get("id", "")
            label = parameter.find("o:label", NS)
            if label is not None:
                labels[parameter_id] = _render_inline(label, labels)

    for parameter in parameters:
        parameter_id = parameter.get("id", "")
        if parameter.find("o:label", NS) is not None:
            continue
        choices = [
            _render_inline(choice, labels) for choice in parameter.findall("o:select/o:choice", NS)
        ]
        if choices:
            labels[parameter_id] = "one or more of: " + "; ".join(choices)
    return labels


def _render_inline(element: ET.Element, parameters: dict[str, str]) -> str:
    chunks = [element.text or ""]
    for child in element:
        if _local_name(child) == "insert" and child.get("type") == "param":
            parameter_id = child.get("id-ref", "")
            label = parameters.get(parameter_id, parameter_id)
            chunks.append(f"[organization-defined parameter: {label}]")
        else:
            chunks.append(_render_inline(child, parameters))
        chunks.append(child.tail or "")
    return _normalize("".join(chunks))


def _part_label(part: ET.Element) -> str:
    label = part.find("o:prop[@name='label']", NS)
    return label.get("value", "") if label is not None else ""


def _statement_lines(part: ET.Element, parameters: dict[str, str]) -> list[str]:
    lines: list[str] = []
    for child in part:
        child_name = _local_name(child)
        if child_name == "p":
            rendered = _render_inline(child, parameters)
            if rendered:
                lines.append(rendered)
        elif child_name == "part":
            nested = _statement_lines(child, parameters)
            label = _part_label(child)
            if nested and label:
                nested[0] = f"{label} {nested[0]}"
            lines.extend(nested)
    return lines


def _control_label(control: ET.Element) -> str:
    label = control.find("o:prop[@name='label'][@class='zero-padded']", NS)
    if label is None:
        label = control.find("o:prop[@name='label']", NS)
    if label is None:
        raise ValueError(f"Control {control.get('id')} has no label")
    value = label.get("value", "")
    return re.sub(r"-0([0-9])", r"-\1", value).replace("(0", "(")


def _catalog_controls(root: ET.Element) -> dict[str, tuple[str, ET.Element]]:
    controls: dict[str, tuple[str, ET.Element]] = {}

    def add_control(family: str, control: ET.Element) -> None:
        control_id = control.get("id")
        if control_id:
            controls[control_id] = (family, control)
        for enhancement in control.findall("o:control", NS):
            add_control(family, enhancement)

    for group in root.findall("o:group", NS):
        family = _normalize(group.findtext("o:title", default="", namespaces=NS))
        for control in group.findall("o:control", NS):
            add_control(family, control)
    return controls


def build_subset(catalog_path: Path) -> dict:
    """Parse and return the pinned subset, failing if source integrity changes."""
    source_bytes = catalog_path.read_bytes()
    actual_sha256 = hashlib.sha256(source_bytes).hexdigest()
    if actual_sha256 != SOURCE_SHA256:
        raise ValueError(
            f"Catalog SHA-256 mismatch: expected {SOURCE_SHA256}, got {actual_sha256}"
        )

    root = ET.fromstring(source_bytes)
    controls_by_id = _catalog_controls(root)
    output_controls = []

    for oscal_id in SELECTED_CONTROL_IDS:
        if oscal_id not in controls_by_id:
            raise ValueError(f"Selected control is absent from catalog: {oscal_id}")
        family, control = controls_by_id[oscal_id]
        title = _normalize(control.findtext("o:title", default="", namespaces=NS))
        label = _control_label(control)
        parameters = _parameter_labels(control)
        statement = control.find("o:part[@name='statement']", NS)
        if statement is None:
            raise ValueError(f"Control has no statement: {oscal_id}")
        lines = _statement_lines(statement, parameters)
        text = f"Control: {label} — {title}.\n" + "\n".join(lines)
        output_controls.append(
            {
                "id": label,
                "oscal_id": oscal_id,
                "family": family,
                "title": title,
                "text": text,
            }
        )

    metadata = root.find("o:metadata", NS)
    if metadata is None:
        raise ValueError("Catalog metadata is absent")

    return {
        "source": {
            "title": _normalize(metadata.findtext("o:title", default="", namespaces=NS)),
            "tag": SOURCE_TAG,
            "commit": SOURCE_COMMIT,
            "catalog_version": metadata.findtext("o:version", default="", namespaces=NS),
            "oscal_version": metadata.findtext("o:oscal-version", default="", namespaces=NS),
            "last_modified": metadata.findtext("o:last-modified", default="", namespaces=NS),
            "url": SOURCE_URL,
            "sha256": SOURCE_SHA256,
            "license": "NIST public domain and CC0-1.0",
            "transformation": "Statement text extracted by scripts/build_control_subset.py",
        },
        "controls": output_controls,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", type=Path, help="Path to the pinned NIST OSCAL catalog XML")
    parser.add_argument("output", type=Path, help="Destination YAML path")
    args = parser.parse_args()

    subset = build_subset(args.catalog)
    rendered = yaml.dump(
        subset,
        Dumper=LiteralDumper,
        allow_unicode=True,
        sort_keys=False,
        width=100,
    )
    args.output.write_text(
        "# Generated from pinned official NIST OSCAL content. Do not edit by hand.\n" + rendered
    )


if __name__ == "__main__":
    main()
