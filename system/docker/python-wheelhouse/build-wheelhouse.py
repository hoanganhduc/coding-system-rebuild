#!/usr/bin/env python3
"""Build eight native CPython 3.12 wheel directories and canonical manifests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from wheelhouse_lib import ENVIRONMENTS, WheelhouseError, build_manifests, canonical_name, inspect_wheel


BUILD_SCHEMA = "coding-system.python-wheelhouse-build/v1"
PIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9][A-Za-z0-9._+!-]*$")
GIT_PIN = re.compile(r"^git\+https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git@[0-9a-f]{40}$")


def run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


def load_inputs(path: Path, source_root: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WheelhouseError(f"cannot read build inputs: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != BUILD_SCHEMA or value.get("python") != "3.12":
        raise WheelhouseError("unsupported wheelhouse build-input schema/Python")
    environments = value.get("environments")
    if not isinstance(environments, dict) or tuple(environments) != ENVIRONMENTS:
        raise WheelhouseError("build inputs must contain the eight environments in canonical order")
    pure = value.get("pureSdistWheels")
    if not isinstance(pure, list) or not pure or any(not isinstance(item, str) or not PIN.fullmatch(item) for item in pure):
        raise WheelhouseError("pureSdistWheels must be exact name==version pins")
    git_wheels = value.get("gitWheels")
    if not isinstance(git_wheels, list) or len(git_wheels) != 3:
        raise WheelhouseError("exactly three pinned Git wheels are required")
    known_git_wheels = set()
    for item in git_wheels:
        if (
            not isinstance(item, dict)
            or set(item) != {"requirement", "name", "version"}
            or not isinstance(item["requirement"], str)
            or not GIT_PIN.fullmatch(item["requirement"])
            or not isinstance(item["name"], str)
            or not isinstance(item["version"], str)
            or not PIN.fullmatch(f"{item['name']}=={item['version']}")
        ):
            raise WheelhouseError("Git wheel inputs must be credential-free HTTPS 40-hex pins")
        identity = canonical_name(item["name"])
        if identity in known_git_wheels:
            raise WheelhouseError(f"duplicate Git wheel input: {identity}")
        known_git_wheels.add(identity)
    for name, spec in environments.items():
        if not isinstance(spec, dict) or spec.get("strategy") not in {"frozen-no-deps", "resolve"}:
            raise WheelhouseError(f"invalid environment strategy: {name}")
        supplemental = spec.get("supplementalRequirements", [])
        if (
            not isinstance(supplemental, list)
            or any(not isinstance(item, str) or not PIN.fullmatch(item) for item in supplemental)
        ):
            raise WheelhouseError(f"supplemental requirements must be exact pins: {name}")
        required_git_wheels = spec.get("requiredGitWheels", [])
        if (
            not isinstance(required_git_wheels, list)
            or any(not isinstance(item, str) or canonical_name(item) != item for item in required_git_wheels)
            or len(set(required_git_wheels)) != len(required_git_wheels)
        ):
            raise WheelhouseError(f"requiredGitWheels must contain unique canonical names: {name}")
        unknown_git_wheels = sorted(set(required_git_wheels) - known_git_wheels)
        if unknown_git_wheels:
            raise WheelhouseError(
                f"requiredGitWheels contains unknown inputs: {name}: {unknown_git_wheels}"
            )
        requirements = spec.get("requirements")
        if isinstance(requirements, str):
            candidate = source_root / requirements
            try:
                candidate.resolve(strict=True).relative_to(source_root.resolve(strict=True))
            except (OSError, ValueError) as exc:
                raise WheelhouseError(f"requirements path escapes or is missing: {requirements}") from exc
            if candidate.is_symlink() or not candidate.is_file():
                raise WheelhouseError(f"requirements input is unsafe: {requirements}")
        elif not isinstance(requirements, list) or not requirements or any(not isinstance(item, str) or not PIN.fullmatch(item) for item in requirements):
            raise WheelhouseError(f"inline requirements must be exact pins: {name}")
    return value


def build_one(command_base: list[str], requirement: str, output: Path, *, sdist: bool = False) -> None:
    command = command_base + ["wheel", "--disable-pip-version-check", "--no-cache-dir", "--no-deps", "--wheel-dir", str(output)]
    if sdist:
        command += ["--no-binary", ":all:"]
    command.append(requirement)
    before = {path.name for path in output.glob("*.whl")}
    run(command)
    created = [path for path in output.glob("*.whl") if path.name not in before]
    if len(created) != 1:
        raise WheelhouseError(f"expected one wheel from {requirement}, found {len(created)}")
    if sdist and not created[0].name.endswith("-none-any.whl"):
        raise WheelhouseError(f"declared pure sdist produced a non-pure wheel: {created[0].name}")


def write_inline_requirements(path: Path, values: list[str]) -> None:
    path.write_text("".join(f"{value}\n" for value in values), encoding="utf-8")


def download_environment(
    python: str,
    source_root: Path,
    name: str,
    spec: dict[str, object],
    built: Path,
    destination: Path,
) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix=f"requirements-{name}-") as temporary:
        requirements = spec["requirements"]
        supplemental = list(spec.get("supplementalRequirements", []))
        if isinstance(requirements, str):
            source_requirements = source_root / requirements
            if supplemental:
                requirement_path = Path(temporary) / "requirements.txt"
                base = source_requirements.read_text(encoding="utf-8")
                if base and not base.endswith("\n"):
                    base += "\n"
                requirement_path.write_text(
                    base + "".join(f"{value}\n" for value in supplemental),
                    encoding="utf-8",
                )
            else:
                requirement_path = source_requirements
        else:
            requirement_path = Path(temporary) / "requirements.txt"
            write_inline_requirements(requirement_path, list(requirements) + supplemental)

        if name == "docling-cpu":
            cpu_wheels = Path(temporary) / "cpu-wheels"
            cpu_wheels.mkdir()
            cpu_packages = spec.get("cpuPyTorch")
            cpu_index = spec.get("cpuIndex")
            if (
                not isinstance(cpu_packages, list)
                or not cpu_packages
                or any(not isinstance(item, str) or "+cpu" not in item for item in cpu_packages)
                or not isinstance(cpu_index, str)
                or cpu_index != "https://download.pytorch.org/whl/cpu"
            ):
                raise WheelhouseError("docling-cpu requires explicit +cpu PyTorch pins and the CPU index")
            run(
                [
                    python,
                    "-m",
                    "pip",
                    "download",
                    "--disable-pip-version-check",
                    "--no-cache-dir",
                    "--no-deps",
                    "--only-binary",
                    ":all:",
                    "--index-url",
                    cpu_index,
                    "--dest",
                    str(cpu_wheels),
                    *cpu_packages,
                ]
            )
            find_links = [built, cpu_wheels]
        else:
            find_links = [built]

        command = [
            python,
            "-m",
            "pip",
            "download",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--only-binary",
            ":all:",
            "--prefer-binary",
            "--dest",
            str(destination),
        ]
        if spec["strategy"] == "frozen-no-deps":
            command.append("--no-deps")
        for directory in find_links:
            command += ["--find-links", directory.as_uri()]
        command += ["--requirement", str(requirement_path)]
        run(command)

    unexpected = [path.name for path in destination.iterdir() if not path.name.endswith(".whl")]
    if unexpected:
        raise WheelhouseError(f"environment contains non-wheel downloads: {name}: {unexpected}")


def verify_built_sources(
    destination: Path,
    built: Path,
    architecture: str,
    required_git_wheels: list[dict[str, str]],
) -> None:
    built_artifacts = {}
    for path in built.glob("*.whl"):
        artifact = inspect_wheel(path, architecture)
        built_artifacts[(str(artifact["name"]), str(artifact["version"]))] = artifact
    delivered_artifacts = {}
    for path in destination.glob("*.whl"):
        artifact = inspect_wheel(path, architecture)
        delivered_artifacts[(str(artifact["name"]), str(artifact["version"]))] = artifact
    for identity in set(built_artifacts) & set(delivered_artifacts):
        if built_artifacts[identity]["sha256"] != delivered_artifacts[identity]["sha256"]:
            raise WheelhouseError(
                f"download replaced locally built wheel bytes: {identity[0]}=={identity[1]}"
            )
    required = {(canonical_name(item["name"]), item["version"]) for item in required_git_wheels}
    missing = sorted(f"{name}=={version}" for name, version in required - set(delivered_artifacts))
    if missing:
        raise WheelhouseError(f"environment omits required Git-built wheels: {missing}")


def verify_built_identity(directory: Path, expected_name: str, expected_version: str, architecture: str) -> None:
    matches = []
    for path in directory.glob("*.whl"):
        artifact = inspect_wheel(path, architecture)
        if artifact["name"] == canonical_name(expected_name) and artifact["version"] == expected_version:
            matches.append(path)
    if len(matches) != 1:
        raise WheelhouseError(f"built wheel identity mismatch for {expected_name}=={expected_version}")


def build(source_root: Path, output: Path, platform_name: str, python: str, inputs_path: Path) -> None:
    if output.exists():
        raise WheelhouseError(f"output already exists: {output}")
    architecture = platform_name.removeprefix("linux/")
    if architecture not in {"amd64", "arm64"}:
        raise WheelhouseError(f"unsupported native architecture: {platform_name}")
    inputs = load_inputs(inputs_path, source_root)
    output.mkdir(parents=True)
    built = output.parent / ".built-wheels"
    built.mkdir()
    command_base = [python, "-m", "pip"]
    git_wheels_by_name = {
        canonical_name(item["name"]): item for item in inputs["gitWheels"]
    }
    try:
        for requirement in inputs["pureSdistWheels"]:
            build_one(command_base, str(requirement), built, sdist=True)
        for item in inputs["gitWheels"]:
            build_one(command_base, str(item["requirement"]), built)
            verify_built_identity(built, str(item["name"]), str(item["version"]), architecture)
        for name in ENVIRONMENTS:
            spec = inputs["environments"][name]
            download_environment(
                python,
                source_root,
                name,
                spec,
                built,
                output / name,
            )
            verify_built_sources(
                output / name,
                built,
                architecture,
                [git_wheels_by_name[item] for item in spec.get("requiredGitWheels", [])],
            )
        build_manifests(output, platform_name)
    finally:
        shutil.rmtree(built, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--python", default="python3")
    parser.add_argument("--inputs", type=Path)
    args = parser.parse_args(argv)
    source_root = args.source_root.resolve(strict=True)
    inputs = args.inputs or source_root / "system/docker/python-wheelhouse/build-inputs.json"
    try:
        build(source_root, args.output, args.platform, args.python, inputs)
        print(f"wheelhouse built: {args.output} ({args.platform})")
        return 0
    except (WheelhouseError, OSError, subprocess.CalledProcessError) as exc:
        print(f"build-python-wheelhouse: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
