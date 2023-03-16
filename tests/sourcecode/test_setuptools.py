import os
import subprocess


def test_example(example):
    git_sha = subprocess.check_output("git rev-parse HEAD", shell=True).decode("utf-8").strip()
    expected = "Project-URL: source_code_link, https://github.com/companydotcom/repo#{}".format(git_sha)
    subprocess.check_output("python setup.py bdist", shell=True)
    pkg_info = os.path.join(
        example,
        "mypackage.egg-info",
        "PKG-INFO",
    )
    with open(pkg_info, "r") as f:
        project_url = f.readlines()[-1].strip()

    assert project_url == expected
