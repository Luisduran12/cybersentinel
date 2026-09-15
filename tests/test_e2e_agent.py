"""
Pruebas de INTEGRACIÓN de extremo a extremo del agente.

Las pruebas unitarias comprueban que cada pieza funciona aislada. Estas
comprueban lo que aquellas no pueden: que las piezas están **conectadas** y que
el resultado que sale del pipeline procede de componentes reales.

Cada escenario corresponde a una capacidad que el agente dice tener. Ninguna
prueba afirma nada que no se ejecute de verdad: no hay modelos de mentira, y
donde un componente no está disponible se comprueba que el sistema lo declara en
lugar de fingir.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.governance.dataset_manager import DatasetManager  # noqa: E402
from cybersentinel.governance.feedback import HumanDecision, StructuredDecision  # noqa: E402
from cybersentinel.pipeline import Pipeline  # noqa: E402
from cybersentinel.schema import SecurityEvent  # noqa: E402

RULES_DIR = ROOT / "config" / "rules"
BASE = datetime(2025, 3, 10, 10, tzinfo=timezone.utc)


def _pipeline(**kwargs) -> Pipeline:
    """Pipeline con los datos reales del repositorio salvo que se indique otra cosa."""
    kwargs.setdefault("rules_dir", RULES_DIR)
    return Pipeline(**kwargs)


def _sysmon(seconds: int, command: str, host: str = "SRV-APP", **extra) -> SecurityEvent:
    return SecurityEvent(
        event_id="sysmon", timestamp=BASE + timedelta(seconds=seconds),
        source="sysmon", category="process", action="process_create",
        host=host, user="admin", command_line=command, **extra,
    )


@pytest.fixture(scope="module")
def agente() -> Pipeline:
    """Un único pipeline completo: construirlo indexa 222 documentos."""
    return _pipeline()


# ---------------------------------------------------------------- ESCENARIO A
def test_escenario_a_evento_benigno_no_genera_hallazgo(agente):
    """Un evento normal no puede producir una alerta."""
    evento = _sysmon(0, "chrome.exe --new-tab", host="WKS-01")
    reporte = agente.run_events([evento])

    evidencia = reporte.results[0].evidence
    assert evidencia.rule_matches == []
    assert evidencia.detection_status in ("NO_DETECTION", "ANOMALY_ONLY")
    assert reporte.total_findings == 0 or evidencia.hybrid_score <= 50.0


# ---------------------------------------------------------------- ESCENARIO B
def test_escenario_b_sigma_alimenta_la_evidencia(agente):
    """Telemetría → Sigma → DetectionEvidence, con la técnica ATT&CK resuelta."""
    evento = _sysmon(0, "powershell.exe -nop -w hidden -enc SQBFAFgA")
    evidencia = agente.run_events([evento]).results[0].evidence

    assert evidencia.rule_matches, "la regla de PowerShell ofuscado debía activarse"
    assert evidencia.detection_status in ("RULE_MATCH", "RULE_AND_ANOMALY")
    # ATT&CK conectado: la técnica sale de la regla que se disparó de verdad,
    # no de la cobertura estructural de la matriz.
    assert "T1059" in evidencia.mitre_context
    assert "execution" in evidencia.mitre_tactics
    assert evidencia.stage_status["sigma"] == "OK"


# ---------------------------------------------------------------- ESCENARIO C
def test_escenario_c_isolation_forest_produce_scores_reales(agente):
    """
    El score debe venir del modelo: eventos distintos, scores distintos.

    Una constante haría pasar cualquier prueba que solo comprobara el rango.
    """
    eventos = [
        _sysmon(i * 60, f"chrome.exe --tab {i}", host="WKS-01") for i in range(40)
    ]
    eventos.append(_sysmon(2500, "x" * 400, host="WKS-99", dst_port=4444))

    reporte = agente.run_events(eventos)
    scores = [r.evidence.anomaly_score for r in reporte.results]

    assert len(set(round(s, 4) for s in scores)) > 5, (
        "todos los eventos tienen el mismo score: el modelo no está puntuando"
    )
    assert all(0.0 <= s <= 1.0 for s in scores)
    assert all(r.evidence.stage_status["ml"] == "OK" for r in reporte.results)
    # El evento atípico debe destacar sobre la línea base.
    assert scores[-1] > sorted(scores)[len(scores) // 2]


def test_escenario_c_ml_desactivado_se_declara(agente):
    """Con ML apagado el score es 0 y la etapa queda marcada DISABLED, no OK."""
    reporte = _pipeline(enable_ml=False, enable_rag=False, enable_llm=False).run_events(
        [_sysmon(0, "powershell.exe -enc AAAA")]
    )
    evidencia = reporte.results[0].evidence
    assert evidencia.anomaly_score == 0.0
    assert evidencia.stage_status["ml"] == "DISABLED"


# ---------------------------------------------------------------- ESCENARIO D
def test_escenario_d_secuencia_temporal_se_correlaciona(agente):
    """
    Tres eventos en orden producen una cadena, no tres alertas sueltas.

    Es la diferencia entre un detector de eventos y un agente que entiende una
    progresión de ataque.
    """
    eventos = [
        SecurityEvent("auth", BASE + timedelta(seconds=i * 10), "auth",
                      "authentication", "user_login", host="SRV-APP",
                      user="admin", src_ip="203.0.113.66", outcome="failure")
        for i in range(6)
    ]
    eventos.append(_sysmon(300, "powershell.exe -nop -w hidden -enc SQBFAFgA"))
    eventos.append(_sysmon(600, "schtasks /create /tn x /tr y"))

    reporte = agente.run_events(eventos)

    nombres = {i["incident_name"] for i in reporte.correlated_incidents}
    assert nombres, "no se correlacionó ninguna secuencia"
    assert any("fuerza bruta" in n.lower() for n in nombres)

    # La señal temporal llega a la evidencia y no es una constante.
    con_secuencia = [r for r in reporte.results if r.evidence.temporal_context]
    assert con_secuencia
    etiquetas = {t for r in con_secuencia for t in r.evidence.temporal_context}
    assert not any(t == "seq1" for t in etiquetas), "la señal temporal es un literal"
    assert any("->" in t for t in etiquetas)


def test_escenario_d_la_agregacion_temporal_de_sigma_participa(agente):
    """
    La fuerza bruta exige varios fallos en una ventana: si el pipeline evaluara
    evento a evento, esa regla no podría dispararse nunca.
    """
    eventos = [
        SecurityEvent("auth", BASE + timedelta(seconds=i * 10), "auth",
                      "authentication", "user_login", host="SRV-APP",
                      user="admin", src_ip="10.0.0.9", outcome="failure")
        for i in range(8)
    ]
    reporte = agente.run_events(eventos)
    reglas = {h.rule.id for r in reporte.results for h in r.evidence.rule_matches}
    assert "RULE-0001" in reglas


# ---------------------------------------------------------------- ESCENARIO E
def test_escenario_e_cti_enriquece_con_indicadores_reales(agente):
    """observable → indicador STIX → actor, cargado desde data/cti/."""
    evento = SecurityEvent(
        "fw", BASE, "firewall", "network", "connection", host="SRV-APP",
        src_ip="10.0.0.50", dst_ip="203.0.113.66", dst_port=4444,
    )
    evidencia = agente.run_events([evento]).results[0].evidence

    assert evidencia.cti_hits, "el indicador del bundle de laboratorio debía coincidir"
    hit = evidencia.cti_hits[0]
    assert hit.observable_value == "203.0.113.66"
    assert "c2" in hit.indicator.labels
    assert [a.name for a in hit.related_actors] == ["LAB-ACTOR-01"]
    assert evidencia.stage_status["cti"] == "OK"


def test_escenario_e_sin_coincidencia_cti_se_declara(agente):
    """No hay coincidencia: NO_DATA explícito, nunca una coincidencia inventada."""
    evento = SecurityEvent(
        "fw", BASE, "firewall", "network", "connection", host="WKS-01",
        src_ip="10.0.0.5", dst_ip="10.0.0.6", dst_port=445,
    )
    evidencia = agente.run_events([evento]).results[0].evidence
    assert evidencia.cti_hits == []
    assert evidencia.stage_status["cti"] == "NO_DATA"
    assert evidencia.to_dict()["cti_hits"] == "not_available"


def test_escenario_e_indicadores_caducados_y_revocados_no_coinciden(agente):
    """El ciclo de vida del indicador se respeta: si expiró, no es una coincidencia."""
    for ip in ("198.51.100.23", "198.51.100.24"):     # caducado y revocado
        evento = SecurityEvent("fw", BASE, "firewall", "network", "connection",
                               host="WKS-01", dst_ip=ip)
        assert agente.run_events([evento]).results[0].evidence.cti_hits == [], ip


# ---------------------------------------------------------------- ESCENARIO F
def test_escenario_f_rag_recupera_contexto_con_procedencia(agente):
    """
    DetectionEvidence → recuperación → procedencia → explicación.

    Lo que importa no es que se recupere algo, sino poder decir de dónde salió.
    """
    evento = _sysmon(0, "powershell.exe -nop -w hidden -enc SQBFAFgA")
    evidencia = agente.run_events([evento]).results[0].evidence

    assert evidencia.rag_context, "no se recuperó ningún fragmento"
    for fragmento in evidencia.rag_context:
        assert fragmento.source_uri and fragmento.source_uri != "desconocida"
        assert fragmento.excerpt.strip()
    # Anclaje: el documento de la técnica detectada tiene que estar presente.
    assert any("T1059" in c.filename for c in evidencia.rag_context)
    assert evidencia.stage_status["rag"] == "OK"


def test_escenario_f_los_embeddings_no_son_aleatorios():
    """
    Una recuperación con embeddings falsos es indistinguible del azar.

    Se comprueba que la consulta por una técnica recupera su propio documento,
    que es imposible con vectores aleatorios.
    """
    from cybersentinel.rag.embeddings import LocalLSAEmbeddings
    from cybersentinel.rag.vector_store import RAGStore

    corpus = ROOT / "data" / "knowledge"
    if not corpus.exists():
        pytest.skip("no hay corpus de conocimiento")

    store = RAGStore(LocalLSAEmbeddings())
    store.ingest_directory(corpus, ext="*.md")
    recuperados = [
        d.metadata["filename"]
        for d in store.retrieve("T1110 Brute Force password guessing", k=3)
    ]
    assert "T1110.md" in recuperados


def test_escenario_f_explicacion_declara_su_procedencia(agente):
    """Toda explicación dice quién la escribió; un respaldo nunca se disfraza."""
    evidencia = agente.run_events([_sysmon(0, "powershell.exe -enc AAAA")]).results[0].evidence

    assert evidencia.llm_status in ("OK", "UNAVAILABLE", "ERROR", "DISABLED")
    assert evidencia.explanation
    if evidencia.llm_status != "OK":
        assert evidencia.fallback_used is True
        assert "determinista" in evidencia.explanation


def test_escenario_f_explicacion_con_modelo_inyectado():
    """Con un modelo disponible, la explicación es suya y se marca OK."""
    from langchain_community.chat_models.fake import FakeListChatModel

    # El doble vive SOLO en la prueba: el pipeline nunca lo construye por su
    # cuenta. Verifica la ruta "modelo disponible", que sin credenciales no se
    # podría ejercitar.
    modelo = FakeListChatModel(responses=["Resumen del incidente redactado por el modelo."])
    pipeline = _pipeline(chat_model=modelo, enable_rag=False)
    evidencia = pipeline.run_events([_sysmon(0, "powershell.exe -enc AAAA")]).results[0].evidence

    assert evidencia.llm_status == "OK"
    assert evidencia.fallback_used is False
    assert "redactado por el modelo" in evidencia.explanation


# ---------------------------------------------------------------- ESCENARIO G
def test_escenario_g_la_decision_humana_llega_al_dataset(agente, tmp_path):
    """DetectionEvidence → decisión del analista → DatasetManager, persistida."""
    evento = _sysmon(0, "powershell.exe -nop -w hidden -enc SQBFAFgA")
    evidencia = agente.run_events([evento]).results[0].evidence

    almacen = tmp_path / "decisions.jsonl"
    manager = DatasetManager(store_path=almacen)
    decision = StructuredDecision(
        detection_id=f"{evidencia.run_id}:{evidencia.event_ref}",
        event_id=evidencia.event_ref,
        timestamp=evento.timestamp,
        analyst_decision=HumanDecision.TRUE_POSITIVE,
        confidence=0.9,
        reason="PowerShell codificado confirmado",
        selected_evidence=evidencia.to_dict(),
        analyst_id="analista.lab",
        model_version="iforest",
        rule_version="config/rules",
        data_source="prueba",
        created_at=datetime.now(tz=timezone.utc),
    )
    assert manager.submit_decision(decision) is True

    metricas = manager.get_metrics()
    assert metricas["total_decisions_submitted"] == 1
    assert metricas["resolved_distribution"]["TRUE_POSITIVE"] == 1

    # Persistencia: el feedback sobrevive al proceso.
    assert almacen.exists()
    guardada = json.loads(almacen.read_text(encoding="utf-8").splitlines()[0])
    assert guardada["analyst_decision"] == "TRUE_POSITIVE"
    assert guardada["selected_evidence"]["event_ref"] == evidencia.event_ref

    recargado = DatasetManager(store_path=almacen)
    assert recargado.get_metrics()["total_decisions_submitted"] == 1


def test_escenario_g_la_evidencia_sellada_no_cambia_si_cambia_el_analisis(agente, tmp_path):
    """
    Lo que el analista vio al decidir queda congelado.

    Si la evidencia pudiera reescribirse, una etiqueta histórica dejaría de
    corresponder a lo que se etiquetó.
    """
    evidencia = agente.run_events([_sysmon(0, "powershell.exe -enc AAAA")]).results[0].evidence
    sellada = evidencia.to_dict()

    manager = DatasetManager(store_path=tmp_path / "d.jsonl")
    manager.submit_decision(StructuredDecision(
        detection_id="det-1", event_id=evidencia.event_ref, timestamp=BASE,
        analyst_decision=HumanDecision.TRUE_POSITIVE, confidence=1.0, reason="",
        selected_evidence=sellada, analyst_id="ana", model_version="v1",
        rule_version="v1", data_source="prueba", created_at=datetime.now(tz=timezone.utc),
    ))

    evidencia.anomaly_score = 0.999          # el análisis cambia después
    almacenada = manager._decisions["det-1"]["ana"].selected_evidence
    assert almacenada["anomaly_score"] == sellada["anomaly_score"]


# ------------------------------------------------------------- TRAZABILIDAD
def test_toda_la_ejecucion_comparte_un_run_id(agente):
    """Un run_id por ejecución, presente en el reporte, la traza y la evidencia."""
    eventos = [_sysmon(i * 60, f"chrome.exe --tab {i}") for i in range(5)]
    reporte = agente.run_events(eventos)

    assert reporte.run_id
    assert {r.trace.run_id for r in reporte.results} == {reporte.run_id}
    assert {r.evidence.run_id for r in reporte.results} == {reporte.run_id}


def test_cada_evento_es_identificable_de_forma_unica(agente):
    """
    `event_id` se repite entre eventos del mismo tipo ("sysmon"); `event_ref` no.

    Sin una referencia única no se puede reconstruir de qué evento salió una
    conclusión, que es el requisito mínimo de trazabilidad.
    """
    eventos = [_sysmon(i * 60, f"chrome.exe --tab {i}") for i in range(5)]
    reporte = agente.run_events(eventos)

    assert len({r.evidence.event_id for r in reporte.results}) == 1      # todos "sysmon"
    assert len({r.evidence.event_ref for r in reporte.results}) == 5     # únicos


def test_la_traza_registra_el_estado_de_todas_las_etapas(agente):
    """Ninguna etapa puede quedar sin registro: una etapa muda es una etapa opaca."""
    reporte = agente.run_events([_sysmon(0, "powershell.exe -enc AAAA")])
    traza = reporte.results[0].trace

    registradas = {s.name for s in traza.stages}
    assert {"sigma", "ml", "temporal", "cti", "rag", "llm"} <= registradas
    for etapa in traza.stages:
        assert etapa.status.value in ("OK", "NO_DATA", "DISABLED", "UNAVAILABLE", "ERROR")


def test_el_estado_de_componentes_refleja_la_realidad(agente):
    """El reporte declara con qué datos se ejecutó realmente cada componente."""
    estado = agente.run_events([_sysmon(0, "chrome.exe")]).component_status

    assert estado["sigma"].startswith("OK")
    assert estado["cti"].startswith(("OK", "NO_DATA"))
    assert estado["rag"].startswith(("OK", "NO_DATA"))
    assert estado["llm"].startswith(("OK", "UNAVAILABLE"))


def test_el_pipeline_no_construye_modelos_de_mentira():
    """
    Regresión del defecto principal de la auditoría: el pipeline instanciaba
    `FakeEmbeddings` y `FakeListChatModel`, y la cadena constante del segundo
    llegaba a la salida del usuario como si fuera una explicación.
    """
    fuente = (ROOT / "src" / "cybersentinel" / "pipeline.py").read_text(encoding="utf-8")
    for prohibido in ("FakeEmbeddings", "FakeListChatModel", "FakeChatModel"):
        assert prohibido not in fuente, f"{prohibido} no puede estar en el pipeline"


def test_la_ablacion_apaga_componentes_sin_falsear_resultados():
    """Con todo apagado, cada etapa se declara DISABLED en vez de devolver datos."""
    pipeline = _pipeline(enable_ml=False, enable_temporal=False,
                         enable_cti=False, enable_rag=False, enable_llm=False)
    evidencia = pipeline.run_events([_sysmon(0, "powershell.exe -enc AAAA")]).results[0].evidence

    assert evidencia.rule_matches                      # Sigma sigue activo
    assert evidencia.anomaly_score == 0.0
    assert evidencia.cti_hits == []
    assert evidencia.rag_context == []
    assert evidencia.llm_status == "DISABLED"
    for etapa in ("ml", "temporal", "cti", "rag", "llm"):
        assert evidencia.stage_status[etapa] == "DISABLED"
