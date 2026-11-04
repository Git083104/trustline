from scanner.copy import decorate
from scanner.models import Finding
from scanner.sarif import findings_to_sarif


def test_sarif_shape_and_severity_map():
    item = decorate(
        Finding(
            target="gone-bucket",
            kind="bucket",
            references=["deploy.yml:4"],
            severity="critical",
            model_severity="critical",
            final_severity="critical",
            classified_blast_radius=3,
            ranked_blast_radius=3,
            risk="NoSuchBucket",
            fix="re-register what you abandoned",
            evidence={"bucket_probe": {"status": "NoSuchBucket", "name": "gone-bucket"}},
            locations=[{"file": "deploy.yml", "line": 4, "runs_in": "deploy"}],
        )
    )
    doc = findings_to_sarif([item])
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Tether"
    assert run["results"]
    result = run["results"][0]
    assert result["ruleId"] == "nosuchbucket"
    assert result["level"] == "error"
    assert result["message"]["text"] == item.headline
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "deploy.yml"
    assert loc["region"]["startLine"] == 4
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert "nosuchbucket" in rule_ids


def test_sarif_medium_is_warning():
    item = Finding(
        target="example.com",
        kind="domain",
        references=["README.md:1"],
        severity="medium",
        model_severity="medium",
        final_severity="medium",
        classified_blast_radius=1,
        ranked_blast_radius=1,
        risk="review",
        fix="remove dead reference",
        locations=[{"file": "README.md", "line": 1}],
    )
    result = findings_to_sarif([item])["runs"][0]["results"][0]
    assert result["level"] == "warning"
