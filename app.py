"""
ThreatHunt-GPT — Streamlit UI
"""

import streamlit as st
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from rag_engine import RAGEngine
from pipeline import run_pipeline, run_log_triage_pipeline, simulate_logs

# ──────────────────────────────────────────
# 頁面配置
# ──────────────────────────────────────────
st.set_page_config(
    page_title="ThreatHunt-GPT",
    page_icon="🎯",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────
# CSS
# ──────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap');

/* ══════════════════════════════════════════
   GLOBAL — force dark everywhere
══════════════════════════════════════════ */
html, body { background-color: #060a08 !important; }

/* Main app container & all generic divs */
.stApp,
.stApp > div,
[data-testid="stAppViewContainer"],
[data-testid="stAppViewContainer"] > section,
[data-testid="stMain"],
[data-testid="stMain"] > div,
.main .block-container,
div[class*="block-container"],
div[data-testid="stVerticalBlock"],
div[data-testid="stHorizontalBlock"] {
    background-color: #060a08 !important;
    color: #b8d4c0 !important;
}

/* Catch-all for any remaining white backgrounds */
div[class*="css"], section[class*="css"] {
    background-color: #060a08 !important;
}

/* ══════════════════════════════════════════
   SIDEBAR
══════════════════════════════════════════ */
section[data-testid="stSidebar"],
section[data-testid="stSidebar"] > div,
section[data-testid="stSidebar"] > div > div {
    background-color: #040806 !important;
    border-right: 1px solid #0f2a1a !important;
}
section[data-testid="stSidebar"] p,
section[data-testid="stSidebar"] span,
section[data-testid="stSidebar"] label {
    color: #4a8a6a !important;
}

/* ══════════════════════════════════════════
   TYPOGRAPHY
══════════════════════════════════════════ */
p, span, label, div { color: #b8d4c0; }

.threat-header {
    font-family: 'Rajdhani', sans-serif;
    font-weight: 700;
    font-size: 2.6rem;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: #00ff9d;
    text-shadow: 0 0 24px rgba(0,255,157,0.45), 0 0 60px rgba(0,255,157,0.15);
    line-height: 1;
    margin-bottom: 2px;
}
.threat-subtitle {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.72rem;
    color: #2a6a4a;
    letter-spacing: 0.28em;
    text-transform: uppercase;
    margin-bottom: 28px;
}

/* ══════════════════════════════════════════
   SECTION LABELS
══════════════════════════════════════════ */
.section-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.62rem;
    letter-spacing: 0.32em;
    text-transform: uppercase;
    color: #00ff9d;
    border-left: 2px solid #00ff9d;
    padding-left: 10px;
    margin-bottom: 14px;
    opacity: 0.8;
}

/* ══════════════════════════════════════════
   STAT CARDS
══════════════════════════════════════════ */
.stat-card {
    background: #0a120d;
    border: 1px solid #0f2a1a;
    border-top: 2px solid #00ff9d;
    border-radius: 3px;
    padding: 14px 16px;
    text-align: center;
}
.stat-number {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1.9rem;
    color: #00ff9d;
    line-height: 1;
    text-shadow: 0 0 12px rgba(0,255,157,0.4);
}
.stat-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.6rem;
    color: #2a5a3a;
    letter-spacing: 0.22em;
    text-transform: uppercase;
    margin-top: 6px;
}

/* ══════════════════════════════════════════
   INFO CARDS
══════════════════════════════════════════ */
.info-card {
    background: #0a120d;
    border: 1px solid #0f2a1a;
    border-left: 3px solid #00ff9d;
    border-radius: 3px;
    padding: 18px 22px;
    margin-bottom: 14px;
    font-size: 0.92rem;
    line-height: 1.75;
    color: #c8e0d0 !important;
}

/* ══════════════════════════════════════════
   TTP MATRIX
══════════════════════════════════════════ */
.ttp-row {
    display: flex;
    gap: 14px;
    padding: 12px 4px;
    border-bottom: 1px solid #0f2a1a;
    align-items: flex-start;
}
.ttp-id {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    color: #00ff9d;
    min-width: 110px;
    padding-top: 3px;
    flex-shrink: 0;
}
.ttp-name {
    font-family: 'Rajdhani', sans-serif;
    font-weight: 600;
    font-size: 0.95rem;
    color: #e8f4ee;
    letter-spacing: 0.03em;
}
.ttp-desc {
    font-size: 0.8rem;
    color: #5a8a6a;
    line-height: 1.55;
    margin-top: 4px;
}
.ttp-link {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.62rem;
    color: #00cc7a;
    text-decoration: none;
    opacity: 0.7;
    margin-top: 4px;
    display: inline-block;
}
.ttp-link:hover { opacity: 1; }

/* ══════════════════════════════════════════
   BADGE
══════════════════════════════════════════ */
.badge {
    display: inline-block;
    background: rgba(0,255,157,0.08);
    border: 1px solid rgba(0,255,157,0.25);
    color: #00ff9d;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.58rem;
    padding: 2px 6px;
    border-radius: 2px;
    letter-spacing: 0.1em;
    margin-right: 4px;
    margin-bottom: 4px;
    display: block;
}

/* ══════════════════════════════════════════
   ERROR BOX
══════════════════════════════════════════ */
.error-box {
    background: #120808;
    border: 1px solid #ff3333;
    border-left: 3px solid #ff3333;
    border-radius: 3px;
    padding: 16px 20px;
    color: #ff7777;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.82rem;
    line-height: 1.6;
}

/* ══════════════════════════════════════════
   INPUT
══════════════════════════════════════════ */
.stTextInput > div > div > input {
    background: #0a120d !important;
    border: 1px solid #1a3a24 !important;
    border-radius: 3px !important;
    color: #c8e0d0 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.88rem !important;
    padding: 12px 16px !important;
    caret-color: #00ff9d !important;
}
.stTextInput > div > div > input::placeholder {
    color: #2a4a34 !important;
}
.stTextInput > div > div > input:focus {
    border-color: #00ff9d !important;
    box-shadow: 0 0 0 1px #00ff9d44 !important;
    outline: none !important;
}

/* ══════════════════════════════════════════
   BUTTONS
══════════════════════════════════════════ */
.stButton > button {
    background: #0a120d !important;
    border: 1px solid #00ff9d !important;
    color: #00ff9d !important;
    font-family: 'Rajdhani', sans-serif !important;
    font-weight: 700 !important;
    font-size: 0.85rem !important;
    letter-spacing: 0.18em !important;
    text-transform: uppercase !important;
    padding: 8px 16px !important;
    border-radius: 2px !important;
    transition: all 0.15s ease !important;
    width: 100% !important;
}
.stButton > button:hover {
    background: rgba(0,255,157,0.12) !important;
    box-shadow: 0 0 14px rgba(0,255,157,0.2) !important;
    color: #ffffff !important;
}
/* HUNT button — main CTA */
div[data-testid="stHorizontalBlock"] > div:last-child .stButton > button {
    background: #00ff9d22 !important;
    font-size: 1rem !important;
    letter-spacing: 0.22em !important;
    padding: 12px 20px !important;
}

/* ══════════════════════════════════════════
   TABS
══════════════════════════════════════════ */
.stTabs [data-baseweb="tab-list"] {
    background: transparent !important;
    border-bottom: 1px solid #0f2a1a !important;
    gap: 0 !important;
}
.stTabs [data-baseweb="tab"] {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.65rem !important;
    letter-spacing: 0.22em !important;
    color: #2a5a3a !important;
    background: transparent !important;
    border: none !important;
    padding: 10px 18px !important;
    text-transform: uppercase !important;
}
.stTabs [aria-selected="true"] {
    color: #00ff9d !important;
    border-bottom: 2px solid #00ff9d !important;
    background: rgba(0,255,157,0.04) !important;
}
/* Tab panel background */
.stTabs [data-baseweb="tab-panel"] {
    background: transparent !important;
    padding-top: 20px !important;
}

/* ══════════════════════════════════════════
   CODE BLOCKS
══════════════════════════════════════════ */
.stCodeBlock,
.stCodeBlock > div,
.stCodeBlock pre,
.stCodeBlock code,
[data-testid="stCodeBlock"],
[data-testid="stCodeBlock"] > div,
[data-testid="stCodeBlock"] pre {
    background: #050908 !important;
    background-color: #050908 !important;
    border: 1px solid #0f2a1a !important;
    border-radius: 3px !important;
}
.stCodeBlock code,
.stCodeBlock span,
.stCodeBlock pre {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.8rem !important;
    color: #00ff9d !important;
    line-height: 1.7 !important;
}
/* Override syntax highlight token colours for readability */
.stCodeBlock .token.comment  { color: #2a6a4a !important; }
.stCodeBlock .token.keyword  { color: #00ddff !important; }
.stCodeBlock .token.string   { color: #ffdd66 !important; }
.stCodeBlock .token.number   { color: #ff9955 !important; }
.stCodeBlock .token.operator { color: #cc88ff !important; }
/* Copy button */
.stCodeBlock button {
    background: #0a120d !important;
    border-color: #0f2a1a !important;
    color: #2a6a4a !important;
}

/* ══════════════════════════════════════════
   SPINNER
══════════════════════════════════════════ */
.stSpinner > div { border-top-color: #00ff9d !important; }

/* ══════════════════════════════════════════
   DIVIDER & MISC
══════════════════════════════════════════ */
hr { border-color: #0f2a1a !important; margin: 20px 0 !important; }
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
/* Keep header visible so sidebar toggle works */
header { visibility: visible !important; background: transparent !important; }
header [data-testid="stHeader"] { background: transparent !important; }
/* But hide the header toolbar decoration */
header::before { display: none; }

/* ══════════════════════════════════════════
   ANIMATIONS
══════════════════════════════════════════ */
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
.cursor { animation: blink 1.2s infinite; color: #00ff9d; }

@keyframes fadeIn { from{opacity:0; transform:translateY(6px)} to{opacity:1; transform:translateY(0)} }
.info-card, .stat-card, .ttp-row { animation: fadeIn 0.3s ease forwards; }

/* ══════════════════════════════════════════
   SCROLLBAR
══════════════════════════════════════════ */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: #060a08; }
::-webkit-scrollbar-thumb { background: #1a4a2a; border-radius: 2px; }
::-webkit-scrollbar-thumb:hover { background: #00ff9d44; }

/* ══════════════════════════════════════════
   NOTICE BOXES (inside tabs)
══════════════════════════════════════════ */
.notice-box {
    background: #0a120d;
    border: 1px solid #0f3a1a;
    border-left: 3px solid #2a6a4a;
    border-radius: 3px;
    padding: 10px 14px;
    margin-bottom: 16px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.68rem;
    color: #3a7a5a;
    line-height: 1.6;
}
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────
# 初始化 RAG 引擎
# ──────────────────────────────────────────
@st.cache_resource(show_spinner=False)
def init_engine():
    base_dir = os.path.dirname(__file__) or "."
    rag = RAGEngine(
        faiss_path=os.path.join(base_dir, "combined_index.faiss"),
        metadata_path=os.path.join(base_dir, "combined_metadata.json"),
        mitre_path=os.path.join(base_dir, "combined_mitre.json"),
    )
    return rag


# ──────────────────────────────────────────
# ──────────────────────────────────────────
# Session state 初始化
# ──────────────────────────────────────────
if "selected_group" not in st.session_state:
    st.session_state.selected_group = ""
if "auto_run" not in st.session_state:
    st.session_state.auto_run = False
if "compare_groups" not in st.session_state:
    st.session_state.compare_groups = []
if "compare_mode" not in st.session_state:
    st.session_state.compare_mode = False
if "triage_mode" not in st.session_state:
    st.session_state.triage_mode = False
if "triage_scenario" not in st.session_state:
    st.session_state.triage_scenario = "brute_force"

# ──────────────────────────────────────────
# Sidebar
# ──────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem;
                letter-spacing:0.3em; color:#00ffa0; text-transform:uppercase;
                margin-bottom:20px; opacity:0.7;">
    ◈ SYSTEM STATUS
    </div>
    """, unsafe_allow_html=True)

    with st.spinner("Loading knowledge base..."):
        rag = init_engine()

    cti_count = len([e for e in rag.metadata if e.get("source_type") == "cti_summary"])
    mitre_count = len(rag.mitre_lookup)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number">{cti_count}</div>
            <div class="stat-label">CTI Entries</div>
        </div>""", unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number">{mitre_count}</div>
            <div class="stat-label">MITRE TTPs</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem;
                letter-spacing:0.3em; color:#00ffa0; text-transform:uppercase;
                margin-bottom:12px; opacity:0.7;">
    ◈ AVAILABLE GROUPS
    </div>
    """, unsafe_allow_html=True)

    all_groups = rag.get_group_names()

    for group in all_groups:
        is_active = st.session_state.selected_group == group
        if st.button(
            f"▶ {group}" if is_active else f"  {group}",
            key=f"btn_{group}",
            use_container_width=True,
        ):
            st.session_state.selected_group = group
            st.session_state.auto_run = True
            st.rerun()

    # ── Compare mode ──────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem;
                letter-spacing:0.3em; color:#00ff9d; text-transform:uppercase;
                margin-bottom:8px; opacity:0.7;">
    ◈ COMPARE MODE
    </div>
    """, unsafe_allow_html=True)

    if st.session_state.compare_groups:
        st.markdown(
            "<div style='font-family:Share Tech Mono,monospace; font-size:0.65rem; "
            "color:#2a6a4a; margin-bottom:6px;'>Selected:</div>",
            unsafe_allow_html=True
        )
        for g in list(st.session_state.compare_groups):
                st.markdown(
                    f"<div style='font-family:Share Tech Mono,monospace; font-size:0.72rem; "
                    f"color:#00ff9d; padding:2px 0; margin-bottom:2px;'>▶ {g}</div>",
                    unsafe_allow_html=True
                )
                if st.button(f"✕ Remove {g}", key=f"rm_{g}", use_container_width=True):
                    st.session_state.compare_groups.remove(g)
                    st.rerun()

    col_add, col_run = st.columns(2)
    with col_add:
        if st.button("+ ADD", use_container_width=True, key="btn_add_compare"):
            # The sidebar buttons set selected_group, but typing in the query box
            # does not — fall back to the box and resolve it to a real group.
            raw = (st.session_state.selected_group
                or st.session_state.get("query_input", "")).strip()
            g = rag.find_group(raw) if raw else None
            if not g:
                st.warning("No matching group — pick one from the list below.")
            elif g in st.session_state.compare_groups:
                st.info(f"{g} is already in the comparison list.")
            else:
                st.session_state.compare_groups.append(g)
                st.rerun()
    with col_run:
        if st.button("COMPARE", use_container_width=True, key="btn_run_compare"):
            if len(st.session_state.compare_groups) >= 2:
                st.session_state.compare_mode = True
                st.rerun()
            else:
                st.info("Add at least 2 groups to compare.")

    if st.button("✕ CLEAR", use_container_width=True, key="btn_clear_compare"):
        st.session_state.compare_groups = []
        st.session_state.compare_mode = False
        st.rerun()

    # ── Log Triage mode ──────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem;
                letter-spacing:0.3em; color:#00ff9d; text-transform:uppercase;
                margin-bottom:8px; opacity:0.7;">
    ◈ LOG TRIAGE
    </div>
    """, unsafe_allow_html=True)

    triage_scenario = st.selectbox(
        "Scenario",
        ["brute_force", "lateral_movement", "persistence",
         "defense_evasion", "kerberoasting", "full_attack"],
        index=["brute_force","lateral_movement","persistence",
               "defense_evasion","kerberoasting","full_attack"].index(
            st.session_state.triage_scenario),
        label_visibility="collapsed",
        key="triage_scenario_select",
    )
    st.session_state.triage_scenario = triage_scenario

    if st.button("⟩ RUN TRIAGE", use_container_width=True, key="btn_triage"):
        st.session_state.triage_mode = True
        st.session_state.compare_mode = False
        st.session_state.selected_group = ""
        st.rerun()

    if st.session_state.triage_mode:
        if st.button("✕ EXIT TRIAGE", use_container_width=True, key="btn_exit_triage"):
            st.session_state.triage_mode = False
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'Share Tech Mono',monospace; font-size:0.6rem;
                color:#2a4a3a; line-height:1.8;">
    THREATHUNT-GPT v2.0<br>
    MITRE ATT&CK® POWERED<br>
    RAG + 3-AGENT PIPELINE<br>
    <span style="color:#1a3a2a;">─────────────────</span><br>
    AGENTS: CTI → TTP → ANSWER<br>
    OUTPUT: YARA · KQL · SPL
    </div>
    """, unsafe_allow_html=True)


# ──────────────────────────────────────────
# Header
# ──────────────────────────────────────────
st.markdown("""
<div class="threat-header">ThreatHunt<span style="color:#ffffff;">-</span>GPT</div>
<div class="threat-subtitle">◈ MITRE ATT&CK® Intelligence Platform &nbsp;·&nbsp; 3-Agent RAG Pipeline <span class="cursor">█</span></div>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────
# Query input
# ──────────────────────────────────────────
col_input, col_btn = st.columns([5, 1])

with col_input:
    query = st.text_input(
        "query",
        value=st.session_state.selected_group,
        placeholder="Enter threat actor name — e.g. APT28, Lazarus Group, FIN7...",
        label_visibility="collapsed",
        key="query_input",
    )

with col_btn:
    run_btn = st.button("⟩ HUNT", use_container_width=True)

auto_run = st.session_state.auto_run
if auto_run:
    st.session_state.auto_run = False

if (run_btn or auto_run) and query.strip():
    with st.spinner("Running 3-agent pipeline..."):
        result = run_pipeline(group_name=query.strip(), rag=rag)

    # Error handling
    if result.get("status") == "error":
        st.markdown(f"""
        <div class="error-box">
        ⚠ QUERY FAILED<br><br>
        {result.get('message', 'Unknown error')}
        </div>
        """, unsafe_allow_html=True)
        st.stop()

    cti = result["cti"]
    ttp = result["ttp"]
    answer = result["answer"]
    group_name = result["group"]

    # ── Top summary bar ───────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number" style="font-size:1.3rem;">{group_name}</div>
            <div class="stat-label">Threat Actor</div>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number">{ttp['ttp_count']}</div>
            <div class="stat-label">Techniques</div>
        </div>""", unsafe_allow_html=True)
    with c3:
        match_badge = "EXACT"
        badge_color = "#00ffa0" if match_badge == "EXACT" else "#ffc800"
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number" style="font-size:1rem; color:{badge_color};">{match_badge}</div>
            <div class="stat-label">Match Method</div>
        </div>""", unsafe_allow_html=True)
    with c4:
        yara_count = answer["yara_rule"].count("rule ")
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number">{yara_count}</div>
            <div class="stat-label">YARA Rules</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Main tabs ─────────────────────────
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "◈ CTI SUMMARY",
        "◈ TTP MATRIX",
        "◈ YARA RULES",
        "◈ KQL QUERIES",
        "◈ SPL QUERIES",
    ])

    # ── Tab 1: CTI ────────────────────────
    with tab1:
        st.markdown('<div class="section-label">Agent 01 — CTI Intelligence Summary</div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div class="info-card">
        {cti['summary']}
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="section-label" style="margin-top:20px;">Agent 03 — Analytical Assessment</div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div class="info-card" style="border-left-color: #4a90e2;">
        {answer['hunt_summary'].replace(chr(10), '<br>')}
        </div>
        """, unsafe_allow_html=True)

    # ── Tab 2: TTP Matrix ─────────────────
    with tab2:
        st.markdown('<div class="section-label">Agent 02 — MITRE ATT&CK® Technique Mapping</div>', unsafe_allow_html=True)
        st.markdown(f"<div style='font-family:Share Tech Mono,monospace; font-size:0.7rem; color:#4a7a6a; margin-bottom:16px;'>{ttp['ttp_count']} TECHNIQUES IDENTIFIED</div>", unsafe_allow_html=True)

        for t in ttp["ttps"]:
            link = f"https://attack.mitre.org/techniques/{t['id'].replace('.', '/')}"
            domain_badge = "ENT" if "enterprise" in t["domain"] else t["domain"][:3].upper()
            st.markdown(f"""
            <div class="ttp-row">
                <div class="ttp-id">
                    <span class="badge">{domain_badge}</span><br>
                    <span style="display:block; margin-top:4px;">{t['id']}</span>
                </div>
                <div style="flex:1;">
                    <div class="ttp-name">{t['name']}</div>
                    <div class="ttp-desc">{t['description'][:300]}{'...' if len(t['description'])>300 else ''}</div>
                    <a href="https://attack.mitre.org/techniques/{t['id'].replace('.', '/')}" target="_blank" class="ttp-link">↗ MITRE ATT&CK — {t['id']}</a>
                </div>
            </div>
            """, unsafe_allow_html=True)

    # ── Tab 3: YARA ───────────────────────
    with tab3:
        st.markdown('<div class="section-label">Generated YARA Detection Rules</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="notice-box">
        ⚠ NOTICE: Rules are generated from tactic templates. Review, tune, and test before deploying to production.
        </div>
        """, unsafe_allow_html=True)
        st.code(answer["yara_rule"], language="yaml")

    # ── Tab 4: KQL ────────────────────────
    with tab4:
        st.markdown('<div class="section-label">Microsoft Sentinel / Defender — KQL Hunting Queries</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="notice-box">
        ⚠ NOTICE: Queries target Microsoft Sentinel tables. Adjust table names and time ranges to match your environment.
        </div>
        """, unsafe_allow_html=True)
        st.code(answer["kql_query"], language="sql")

    # ── Tab 5: SPL ────────────────────────
    with tab5:
        st.markdown('<div class="section-label">Splunk Enterprise Security — SPL Hunting Queries</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="notice-box">
        ⚠ NOTICE: Queries use common Splunk sourcetypes. Update index names and sourcetypes for your deployment.
        </div>
        """, unsafe_allow_html=True)
        st.code(answer["spl_query"], language="bash")

elif not query.strip() and run_btn:
    st.markdown("""
    <div class="error-box">
    Enter a threat actor name, or pick one from the sidebar.
    </div>
    """, unsafe_allow_html=True)

elif st.session_state.compare_mode and len(st.session_state.compare_groups) >= 2:
    # ── Compare Mode ──────────────────────
    rag = init_engine()
    groups_to_compare = st.session_state.compare_groups

    st.markdown("""
    <div class="threat-header" style="font-size:2rem;">GROUP COMPARISON</div>
    <div class="threat-subtitle">◈ MULTI-ACTOR THREAT ANALYSIS</div>
    """, unsafe_allow_html=True)

    with st.spinner(f"Analysing {len(groups_to_compare)} groups..."):
        compare_results = []
        for g in groups_to_compare:
            r = run_pipeline(group_name=g, rag=rag)
            if r.get("status") != "error":
                compare_results.append(r)

    if not compare_results:
        st.markdown('<div class="error-box">Comparison failed: no data found for any of the selected groups.</div>', unsafe_allow_html=True)
        st.stop()

    # ── Summary stats row ──────────────────
    cols = st.columns(len(compare_results))
    for i, r in enumerate(compare_results):
        with cols[i]:
            ttp_count = r["ttp"]["ttp_count"]
            gname = r["group"]
            st.markdown(f"""
            <div class="stat-card" style="border-top-color:#00ff9d;">
                <div class="stat-number" style="font-size:1.1rem;">{gname}</div>
                <div style="font-family:'Share Tech Mono',monospace; font-size:1.6rem;
                            color:#00ff9d; margin-top:8px;">{ttp_count}</div>
                <div class="stat-label">TTPs</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    ctab1, ctab2, ctab3 = st.tabs(["◈ TTP OVERLAP", "◈ CTI SUMMARIES", "◈ TTP BREAKDOWN"])

    # ── Tab 1: TTP Overlap ─────────────────
    with ctab1:
        st.markdown('<div class="section-label">Shared & Unique Techniques</div>', unsafe_allow_html=True)

        all_ttp_sets = {}
        for r in compare_results:
            tids = set(t["id"] for t in r["ttp"]["ttps"])
            all_ttp_sets[r["group"]] = tids

        # Shared across ALL
        shared_all = set.intersection(*all_ttp_sets.values()) if len(all_ttp_sets) > 1 else set()

        if shared_all:
            st.markdown(f"""
            <div class="section-label" style="color:#ffcc00; border-color:#ffcc00;">
            ⚠ {len(shared_all)} TECHNIQUES SHARED BY ALL GROUPS
            </div>""", unsafe_allow_html=True)
            shared_html = " &nbsp;".join(
                f'<span style="font-family:Share Tech Mono,monospace; font-size:0.75rem; '
                f'color:#ffcc00; background:rgba(255,200,0,0.1); border:1px solid rgba(255,200,0,0.3); '
                f'padding:2px 8px; border-radius:2px;">{tid}</span>'
                for tid in sorted(shared_all)
            )
            st.markdown(f"<div style='margin-bottom:20px; line-height:2.2;'>{shared_html}</div>", unsafe_allow_html=True)
        else:
            st.markdown('<div class="info-card">No techniques are shared across all selected groups.</div>', unsafe_allow_html=True)

        # Pairwise overlap
        if len(compare_results) == 2:
            g1, g2 = list(all_ttp_sets.keys())
            overlap = all_ttp_sets[g1] & all_ttp_sets[g2]
            only_g1 = all_ttp_sets[g1] - all_ttp_sets[g2]
            only_g2 = all_ttp_sets[g2] - all_ttp_sets[g1]

            col1, col2, col3 = st.columns(3)
            with col1:
                st.markdown(f'<div class="section-label">Only {g1} ({len(only_g1)})</div>', unsafe_allow_html=True)
                for tid in sorted(only_g1):
                    st.markdown(f'<div style="font-family:Share Tech Mono,monospace; font-size:0.75rem; '
                                f'color:#00ff9d; padding:2px 0;">{tid}</div>', unsafe_allow_html=True)
            with col2:
                st.markdown(f'<div class="section-label" style="color:#ffcc00; border-color:#ffcc00;">'
                            f'Shared ({len(overlap)})</div>', unsafe_allow_html=True)
                for tid in sorted(overlap):
                    st.markdown(f'<div style="font-family:Share Tech Mono,monospace; font-size:0.75rem; '
                                f'color:#ffcc00; padding:2px 0;">{tid}</div>', unsafe_allow_html=True)
            with col3:
                st.markdown(f'<div class="section-label">Only {g2} ({len(only_g2)})</div>', unsafe_allow_html=True)
                for tid in sorted(only_g2):
                    st.markdown(f'<div style="font-family:Share Tech Mono,monospace; font-size:0.75rem; '
                                f'color:#00ff9d; padding:2px 0;">{tid}</div>', unsafe_allow_html=True)

        else:
            # 3+ groups: show per-group unique
            cols = st.columns(len(compare_results))
            for i, r in enumerate(compare_results):
                gname = r["group"]
                others = set.union(*[v for k, v in all_ttp_sets.items() if k != gname])
                unique = all_ttp_sets[gname] - others
                with cols[i]:
                    st.markdown(f'<div class="section-label">Only {gname} ({len(unique)})</div>', unsafe_allow_html=True)
                    for tid in sorted(unique):
                        st.markdown(f'<div style="font-family:Share Tech Mono,monospace; font-size:0.72rem; '
                                    f'color:#00ff9d; padding:2px 0;">{tid}</div>', unsafe_allow_html=True)

    # ── Tab 2: CTI Summaries ───────────────
    with ctab2:
        for r in compare_results:
            st.markdown(f'<div class="section-label">{r["group"]}</div>', unsafe_allow_html=True)
            st.markdown(f'<div class="info-card">{r["cti"]["summary"]}</div>', unsafe_allow_html=True)

    # ── Tab 3: TTP Breakdown ───────────────
    with ctab3:
        st.markdown('<div class="section-label">Full TTP List Per Group</div>', unsafe_allow_html=True)
        cols = st.columns(len(compare_results))
        for i, r in enumerate(compare_results):
            with cols[i]:
                gname = r["group"]
                ttps  = r["ttp"]["ttps"]
                st.markdown(f'<div class="section-label">{gname} — {len(ttps)} TTPs</div>', unsafe_allow_html=True)
                for t in ttps:
                    shared_marker = " ⚠" if t["id"] in shared_all else ""
                    st.markdown(
                        f'<div style="font-family:Share Tech Mono,monospace; font-size:0.72rem; '
                        f'color:#00ff9d; padding:3px 0; border-bottom:1px solid #0f2a1a;">'
                        f'{t["id"]}{shared_marker}<br>'
                        f'<span style="color:#3a7a5a; font-size:0.65rem;">{t["name"]}</span></div>',
                        unsafe_allow_html=True
                    )

elif st.session_state.triage_mode:
    # ── Log Triage Page ───────────────────────────────────
    rag = init_engine()
    scenario = st.session_state.triage_scenario

    st.markdown(f"""
    <div class="threat-header" style="font-size:2rem;">LOG TRIAGE</div>
    <div class="threat-subtitle">◈ WINDOWS EVENT LOG ANALYSIS · SCENARIO: {scenario.upper().replace("_"," ")}</div>
    """, unsafe_allow_html=True)

    with st.spinner("Running Log Triage Agent..."):
        report = run_log_triage_pipeline(scenario=scenario, rag=rag)

    # ── Threat level banner ───────────────────────────────
    level = report["threat_level"]
    level_color = {"High": "#ff4444", "Medium": "#ffcc00", "Low": "#00ff9d"}.get(level, "#00ff9d")
    level_bg    = {"High": "rgba(255,68,68,0.1)", "Medium": "rgba(255,200,0,0.1)", "Low": "rgba(0,255,157,0.1)"}.get(level, "rgba(0,255,157,0.1)")

    st.markdown(f"""
    <div style="background:{level_bg}; border:2px solid {level_color};
                border-radius:4px; padding:20px 28px; margin-bottom:20px;
                display:flex; align-items:center; gap:24px;">
        <div style="font-family:'Rajdhani',sans-serif; font-size:3rem;
                    font-weight:700; color:{level_color};
                    text-shadow:0 0 20px {level_color}88; line-height:1;">
            {level.upper()}
        </div>
        <div>
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem;
                        color:{level_color}; letter-spacing:0.3em; opacity:0.7;">
                THREAT LEVEL · SCORE {report["threat_score"]}
            </div>
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.78rem;
                        color:#c8e0d0; margin-top:4px;">
                {report["log_count"]} events analysed · {len(report["mitre_ttps"])} unique TTPs mapped
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Stats row ─────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    stats = [
        ("EVENTS",   report["log_count"]),
        ("TTPs",     len(report["mitre_ttps"])),
        ("CHAIN",    len(report["attack_chain"])),
        ("RULES HIT",len(report["escalation_rules_triggered"])),
    ]
    for col, (label, val) in zip([c1,c2,c3,c4], stats):
        with col:
            st.markdown(f"""
            <div class="stat-card">
                <div class="stat-number">{val}</div>
                <div class="stat-label">{label}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Triage tabs ───────────────────────────────────────
    t1, t2, t3, t4, t5 = st.tabs([
        "◈ SOC REPORT",
        "◈ ATTACK CHAIN",
        "◈ TTP MAPPING",
        "◈ IOC SUMMARY",
        "◈ EVENT LOG",
    ])

    with t1:
        st.markdown('<div class="section-label">Escalation Rules Triggered</div>', unsafe_allow_html=True)
        if report["escalation_rules_triggered"]:
            for rule in report["escalation_rules_triggered"]:
                st.markdown(f"""
                <div style="font-family:'Share Tech Mono',monospace; font-size:0.75rem;
                            color:#ffcc00; padding:5px 0; border-bottom:1px solid #0f2a1a;">
                ⚠ {rule}
                </div>""", unsafe_allow_html=True)
        else:
            st.markdown('<div class="info-card">No escalation rules triggered.</div>', unsafe_allow_html=True)

        st.markdown('<div class="section-label" style="margin-top:20px;">Immediate Actions</div>', unsafe_allow_html=True)
        for action in report["soc_recommendations"]["base_actions"]:
            st.markdown(f'<div class="info-card" style="padding:10px 16px; margin-bottom:6px; font-size:0.85rem;">{action}</div>', unsafe_allow_html=True)

        if report["soc_recommendations"]["ttp_actions"]:
            st.markdown('<div class="section-label" style="margin-top:20px;">TTP-Specific Controls</div>', unsafe_allow_html=True)
            for action in report["soc_recommendations"]["ttp_actions"]:
                st.markdown(f'<div class="info-card" style="padding:10px 16px; margin-bottom:6px; font-size:0.82rem; border-left-color:#4a90e2;">{action}</div>', unsafe_allow_html=True)

    with t2:
        st.markdown('<div class="section-label">Inferred Attack Chain (Chronological)</div>', unsafe_allow_html=True)
        for i, step in enumerate(report["attack_chain"]):
            ttps_str = " · ".join(step["ttp_ids"])
            st.markdown(f"""
            <div class="ttp-row">
                <div class="ttp-id">
                    <span style="color:#2a5a3a; font-size:0.65rem;">STEP {i+1:02d}</span><br>
                    <span style="font-size:0.72rem;">EID {step["event_id"]}</span>
                </div>
                <div style="flex:1;">
                    <div class="ttp-name">{step["phase"]}</div>
                    <div class="ttp-desc">{step["action"]}</div>
                    <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem;
                                color:#00ff9d; margin-top:4px;">{ttps_str}</div>
                    <div style="font-family:'Share Tech Mono',monospace; font-size:0.6rem;
                                color:#2a5a3a; margin-top:2px;">{step["timestamp"]}</div>
                </div>
            </div>""", unsafe_allow_html=True)

    with t3:
        st.markdown('<div class="section-label">MITRE ATT&CK Techniques Identified</div>', unsafe_allow_html=True)
        for ttp in report["mitre_ttps"]:
            st.markdown(f"""
            <div class="ttp-row">
                <div class="ttp-id">{ttp["id"]}</div>
                <div style="flex:1;">
                    <div class="ttp-name">{ttp["name"] or ttp["id"]}</div>
                    <div class="ttp-desc">{ttp["description"][:250] if ttp["description"] else ""}</div>
                    <a href="{ttp["mitre_url"]}" target="_blank" class="ttp-link">↗ {ttp["mitre_url"]}</a>
                </div>
            </div>""", unsafe_allow_html=True)

    with t4:
        st.markdown('<div class="section-label">Indicators of Compromise</div>', unsafe_allow_html=True)
        iocs = report["iocs"]
        ci1, ci2, ci3 = st.columns(3)
        with ci1:
            st.markdown('<div class="section-label">Suspicious Accounts</div>', unsafe_allow_html=True)
            for a in iocs["suspicious_accounts"]:
                st.markdown(f'<div style="font-family:Share Tech Mono,monospace; font-size:0.75rem; color:#00ff9d; padding:3px 0;">{a}</div>', unsafe_allow_html=True)
        with ci2:
            st.markdown('<div class="section-label">Source IPs</div>', unsafe_allow_html=True)
            for ip in iocs["suspicious_ips"]:
                st.markdown(f'<div style="font-family:Share Tech Mono,monospace; font-size:0.75rem; color:#ffcc00; padding:3px 0;">{ip}</div>', unsafe_allow_html=True)
        with ci3:
            st.markdown('<div class="section-label">Affected Hosts</div>', unsafe_allow_html=True)
            for h in iocs["affected_hosts"]:
                st.markdown(f'<div style="font-family:Share Tech Mono,monospace; font-size:0.75rem; color:#4a90e2; padding:3px 0;">{h}</div>', unsafe_allow_html=True)

    with t5:
        st.markdown('<div class="section-label">Event Summary</div>', unsafe_allow_html=True)
        for ev in report["event_summary"]:
            sev_color = {"High": "#ff4444", "Medium": "#ffcc00", "Low": "#00ff9d"}.get(ev["severity"], "#00ff9d")
            st.markdown(f"""
            <div class="ttp-row">
                <div class="ttp-id" style="min-width:80px;">
                    EID {ev["event_id"]}
                    <div style="color:{sev_color}; font-size:0.6rem; margin-top:2px;">{ev["severity"]}</div>
                </div>
                <div style="flex:1;">
                    <div class="ttp-name">{ev["title"]}</div>
                    <div class="ttp-desc">Count: {ev["count"]}</div>
                </div>
            </div>""", unsafe_allow_html=True)

else:
    # ── Idle state ────────────────────────
    st.markdown("""
    <div style="text-align:center; padding:60px 20px; opacity:0.4;">
        <div style="font-family:'Share Tech Mono',monospace; font-size:3rem; color:#00ff9d; line-height:1;">
        ◈
        </div>
        <div style="font-family:'Share Tech Mono',monospace; font-size:0.7rem;
                    letter-spacing:0.4em; color:#2a4a3a; text-transform:uppercase; margin-top:16px;">
        AWAITING QUERY — ENTER THREAT ACTOR TO HUNT
        </div>
        <div style="font-family:'Share Tech Mono',monospace; font-size:0.6rem;
                    color:#1a3a2a; margin-top:24px; line-height:2;">
        APT28 · APT29 · Lazarus Group · FIN7 · APT32 · Cobalt Group
        </div>
    </div>
    """, unsafe_allow_html=True)
