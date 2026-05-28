"""
invoke tasks — local developer workflow for building and publishing MCPyGhidra.

Publishing to PyPI requires a ~/.pypirc file with a [mcpyghidra] section,
or set TWINE_USERNAME / TWINE_PASSWORD environment variables.
See https://packaging.python.org/en/latest/guides/distributing-packages-using-setuptools/#uploading-your-project-to-pypi

Quick reference:
  inv install-tools   install build and twine into the current environment
  inv build           clean then build wheel + sdist into dist/
  inv publish         upload dist/* to PyPI via twine
  inv clean           remove dist/, build artifacts, and egg-info
"""

from invoke import task


@task
def install_tools(ctx):
    """Install build and twine into the current Python environment."""
    ctx.run("pip install --upgrade build twine")


@task
def clean(ctx):
    """Remove dist/, build artifacts, egg-info directories, and compiled bytecode."""
    ctx.run("rm -rf dist/")
    ctx.run("rm -rf build/")
    ctx.run("rm -rf src/build/")
    ctx.run("rm -rf src/*.egg-info")
    ctx.run("find . -type d -name __pycache__ -not -path './.git/*' -exec rm -rf {} +")
    ctx.run("find . -name '*.pyc' -not -path './.git/*' -delete")


@task(pre=[clean])
def build(ctx):
    """Clean then build the wheel and sdist into dist/ using python -m build."""
    ctx.run("python -m build")


@task
def publish(ctx):
    """Upload dist/* to PyPI via twine.

    Reads credentials from ~/.pypirc under the [mcpyghidra] section,
    or from TWINE_USERNAME / TWINE_PASSWORD environment variables.
    Run `inv build` first if dist/ is empty.
    """
    ctx.run("python -m twine upload --repository mcpyghidra dist/*")
