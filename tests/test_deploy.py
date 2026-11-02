from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_render_yaml_forces_local_scan_off_and_sets_health():
    text = (ROOT / "render.yaml").read_text()
    assert "healthCheckPath: /api/health" in text
    assert "TRUSTMAP_ALLOW_LOCAL_SCAN" in text
    assert 'value: "0"' in text
    assert "MODEL_API_KEY" in text
    assert "sync: false" in text
    assert "TRUSTMAP_TRUSTED_PROXY_HOPS" in text
    assert 'value: "1"' in text
    assert "TRUSTMAP_DAILY_CAP_USD" in text
    assert "TRUSTMAP_IP_SCANS_PER_HOUR" in text
    assert "TRUSTMAP_CACHE_DB" in text
    assert "/var/data/trustmap.db" in text
    assert "TRUSTMAP_ALLOW_LOCAL_SCAN" in text
    after = text.split("TRUSTMAP_ALLOW_LOCAL_SCAN", 1)[1]
    assert '"1"' not in after.split("TRUSTMAP_", 1)[0]


def test_dockerfile_factory_and_local_scan_off():
    text = (ROOT / "Dockerfile").read_text()
    assert "TRUSTMAP_ALLOW_LOCAL_SCAN=0" in text
    assert "uvicorn api.main:app --factory" in text
    assert "TRUSTMAP_CACHE_DB=/var/data/trustmap.db" in text
    assert "mkdir -p /var/data" in text
    assert not any(line.strip() == "COPY . ." for line in text.splitlines())
    assert not any(line.strip().startswith("USER ") for line in text.splitlines())


def test_dockerignore_excludes_secrets_and_local_junk():
    lines = {
        item.strip()
        for item in (ROOT / ".dockerignore").read_text().splitlines()
        if item.strip()
    }
    assert lines >= {
        ".env",
        ".env.*",
        "eval/labels.jsonl",
        ".git",
        "*.db",
        "Untitled",
    }


def test_dockerfile_installs_git_for_repo_scans():
    text = (ROOT / "Dockerfile").read_text()
    # a repository target is fetched with `git clone`, which the slim base lacks
    assert "git" in text
    assert "apt-get install" in text
    assert "rm -rf /var/lib/apt/lists/*" in text


def test_render_yaml_plan_and_disk_agree():
    # a persistent cache needs a disk, and only a paid plan can mount one
    text = (ROOT / "render.yaml").read_text()
    has_disk = "mountPath:" in text
    on_free = "plan: free" in text
    assert has_disk != on_free, (
        "free plans cannot mount a disk; a paid plan without one silently "
        "loses the cache on every restart"
    )
    # either way the app is pointed at a writable path it creates itself
    assert "TRUSTMAP_CACHE_DB" in text
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "mkdir -p /var/data" in dockerfile


def test_requirements_txt_matches_pyproject():
    # pip users and uv users must install the same thing
    import tomllib

    declared = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
    listed = [
        line.strip()
        for line in (ROOT / "requirements.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert sorted(listed) == sorted(declared)


def test_vercel_sees_one_fastapi_app_and_no_api_functions():
    # Vercel builds every api/**/*.js|ts|go|rb|rs file as its own function (the FastAPI
    # preset only switches that off for .py), so the page has to live outside api/
    import json
    import re

    config = json.loads((ROOT / "vercel.json").read_text())
    assert config["framework"] == "fastapi"
    pattern = re.compile(r"\.(js|mjs|ts|tsx|go|rb|rs)$")
    offenders = [
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "api").rglob("*")
        if path.is_file() and pattern.search(path.name)
    ]
    assert offenders == []
    assert (ROOT / "public" / "index.html").is_file()
    assert "COPY public ./public" in (ROOT / "Dockerfile").read_text()
