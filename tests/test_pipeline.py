"""
tests/test_pipeline.py — orchestration contract for run_pipeline()

run_pipeline() wires CTI Agent -> TTP Agent -> Answer Agent together. We
test that wiring here, not the internals of each agent (those have their
own tests in test_agents.py) — each agent call is monkeypatched so this
test file only fails if the *orchestration logic* breaks.
"""
import pipeline


class FakeRAG:
    def __init__(self, known_group=None, method="exact"):
        self.known_group = known_group
        self.method = method

    def resolve_group(self, query):
        if query == self.known_group:
            return self.known_group, self.method
        return None, None

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


class CountingRAG:
    """Real agents run against this; it counts every group resolution."""

    def __init__(self):
        self.resolve_calls = 0
        self.find_calls = 0

    def resolve_group(self, query):
        self.resolve_calls += 1
        return ("APT28", "alias") if query == "Fancy Bear" else (None, None)

    def find_group(self, query):
        self.find_calls += 1
        return self.resolve_group(query)[0]

    def get_group_names(self):
        return ["APT28"]

    def get_cti_summary(self, group_name):
        return "APT28 summary"

    def get_ttp_ids(self, group_name):
        return ["T1059"]

    def enrich_ttps(self, ttp_ids):
        return [{"id": t, "name": "CLI", "description": "", "domain": "enterprise-attack"} for t in ttp_ids]


def test_run_pipeline_resolves_the_group_exactly_once(monkeypatch):
    """
    Regression test for M1: the pipeline used to call find_group() three
    times per request (pipeline, CTI agent, TTP agent). With a Pass 4
    query that meant three embedding computations for one answer.
    """
    rag = CountingRAG()
    monkeypatch.setattr(
        pipeline, "run_answer_agent",
        lambda group, cti_summary, ttps, llm=None: {"status": "ok", "group": group},
    )

    result = pipeline.run_pipeline("Fancy Bear", rag)

    assert result["status"] == "ok"
    assert result["group"] == "APT28"
    assert rag.resolve_calls == 1
    assert rag.find_calls == 0


def test_run_pipeline_reports_how_the_group_was_matched(monkeypatch):
    rag = FakeRAG(known_group="APT1", method="semantic")
    monkeypatch.setattr(pipeline, "run_cti_agent",
                        lambda group, rag: {"status": "ok", "group": group, "summary": "s"})
    monkeypatch.setattr(pipeline, "run_ttp_agent",
                        lambda group, rag: {"status": "ok", "group": group, "ttp_count": 0, "ttps": []})
    monkeypatch.setattr(pipeline, "run_answer_agent",
                        lambda group, cti_summary, ttps, llm=None: {"status": "ok"})

    result = pipeline.run_pipeline("APT1", rag)

    assert result["match_method"] == "semantic"
