"""Runner-only startup wrapper. Executes original Python from V: unchanged.

Unlike relying solely on sitecustomize, this explicitly installs the optional
SQLite driver before any imports from the user's project. Source, databases,
and persistent files stay on the host PC; only this tiny runtime is ephemeral.
"""
import runpy
import sys
from pathlib import Path

from sqlite_bridge_client import install_from_env


def main():
    if len(sys.argv) < 2:
        raise SystemExit('Uso: sqlite_project_launcher.py V:\\proyecto.py [args]')
    script = str(Path(sys.argv[1]).absolute())
    install_from_env()
    # Recreate the import behavior of `python V:\\app.py`.
    sys.argv = [script] + sys.argv[2:]
    sys.path.insert(0, str(Path(script).parent))
    runpy.run_path(script, run_name='__main__')


if __name__ == '__main__':
    main()
