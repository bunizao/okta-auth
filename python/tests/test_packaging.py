import tomllib
from pathlib import Path


def test_project_scripts_include_okta_cli() -> None:
    pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with pyproject_path.open("rb") as file:
        pyproject = tomllib.load(file)

    assert pyproject["project"]["name"] == "okta-auth-cli"

    scripts = pyproject["project"]["scripts"]

    assert scripts == {
        "okta": "okta_auth.cli:main",
        "okta-auth": "okta_auth.server:main",
    }
