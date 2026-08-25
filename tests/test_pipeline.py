"""
tests/test_pipeline.py — orchestration contract for run_pipeline()

run_pipeline() wires CTI Agent -> TTP Agent -> Answer Agent together. We
test that wiring here, not the internals of each agent (those have their
own tests in test_agents.py) — each agent call is monkeypatched so this
test file only fails if the *orchestration logic* breaks.
"""
import pipeline


class FakeRAG:
    def __init__(self, known_group=None):
        self.known_group = known_group

    def find_group(self, query):
        return self.known_group if query == self.known_group else None

    def get_group_names(self):
        return [self.known_group] if self.known_group else []


def test_run_pipeline_returns_error_when_group_not_found():
    rag = FakeRAG(known_group=None)
    result = pipeline.run_pipeline("Not A Real Group", rag)
    assert result["status"] == "error"
    assert "not found" in result["message"].lower()


def test_run_pipeline_stops_early_if_cti_agent_fails(monkeypatch):
    rag = FakeRAG(known_group="APT1")
    monkeypatch.setattr(
        pipeline, "run_cti_agent",
        lambda group, rag: {"status": "not_found", "summary": "no CTI data"},
    )
    result = pipeline.run_pipeline("APT1", rag)
    assert result["status"] == "error"
    assert result["message"] == "no CTI data"


def test_run_pipeline_stops_early_if_no_ttps_found(monkeypatch):
    rag = FakeRAG(known_group="APT1")
    monkeypatch.setattr(
        pipeline, "run_cti_agent",
        lambda group, rag: {"status": "ok", "group": "APT1", "summary": "summary"},
    )
    monkeypatch.setattr(
        pipeline, "run_ttp_agent",
        lambda group, rag: {"status": "no_ttps", "group": "APT1", "ttp_count": 0, "ttps": []},
    )
    result = pipeline.run_pipeline("APT1", rag)
    assert result["status"] == "error"
    assert "No TTPs found" in result["message"]


def test_run_pipeline_happy_path_wires_all_three_agents(monkeypatch):
    rag = FakeRAG(known_group="APT1")

    monkeypatch.setattr(
        pipeline, "run_cti_agent",
        lambda group, rag: {"status": "ok", "group": "APT1", "summary": "APT1 summary"},
    )
    monkeypatch.setattr(
        pipeline, "run_ttp_agent",
        lambda group, rag: {"status": "ok", "group": "APT1", "ttp_count": 1,
                              "ttps": [{"id": "T1059", "name": "CLI", "description": "", "domain": "enterprise-attack"}]},
    )
    monkeypatch.setattr(
        pipeline, "run_answer_agent",
        lambda group, cti_summary, ttps, llm=None: {
            "status": "ok", "group": group, "hunt_summary": "summary",
            "yara_rule": "rule X {}", "kql_query": "// kql", "spl_query": "| spl",
        },
    )

    result = pipeline.run_pipeline("APT1", rag)

    assert result["status"] == "ok"
    assert result["group"] == "APT1"
    assert result["cti"]["summary"] == "APT1 summary"
    assert result["ttp"]["ttp_count"] == 1
    assert result["answer"]["yara_rule"] == "rule X {}"
