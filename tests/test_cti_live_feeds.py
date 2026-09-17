"""
Pruebas de Threat Intelligence en vivo (Fase 4-C).

No dependen de Internet: en vez de mockear las clases de feed, se usa
`httpx.MockTransport` para interceptar la red y devolver respuestas
sintéticas, de modo que se prueba el código real (URL, headers, parseo,
manejo de errores) sin salir a Internet — lo que pide el prompt
("Test con API mock para no depender de internet"), sin sustituir el
cliente entero por un doble.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.cti.abuseipdb import MALICIOUS_THRESHOLD, AbuseIPDBFeed  # noqa: E402
from cybersentinel.cti.cache import CTICache  # noqa: E402
from cybersentinel.cti.cisa_kev import CisaKevFeed  # noqa: E402
from cybersentinel.cti.enricher import LiveCTIEnricher, _es_ip_publica  # noqa: E402
from cybersentinel.cti.feeds import (  # noqa: E402
    STATUS_ERROR, STATUS_NOT_CONFIGURED, STATUS_NOT_FOUND, STATUS_OK,
    STATUS_RATE_LIMITED, CTIFeed, FeedResult,
)
from cybersentinel.cti.otx import OTXFeed  # noqa: E402


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# ------------------------------- AbuseIPDB ----------------------------------
def test_abuseipdb_sin_key_declara_not_configured():
    feed = AbuseIPDBFeed(api_key=None)
    resultado = feed.query_ip("185.220.101.5")
    assert resultado.status == STATUS_NOT_CONFIGURED
    assert resultado.malicious is False
    assert "CYBERSENTINEL_ABUSEIPDB_KEY" in resultado.detail


def test_abuseipdb_con_key_parsea_respuesta_real():
    llamadas = []

    def handler(request: httpx.Request) -> httpx.Response:
        llamadas.append(request)
        assert request.headers["Key"] == "test-key-123"
        assert "ipAddress=185.220.101.5" in str(request.url)
        return httpx.Response(200, json={"data": {
            "ipAddress": "185.220.101.5", "abuseConfidenceScore": 95,
            "totalReports": 847, "countryCode": "RU",
        }})

    feed = AbuseIPDBFeed(api_key="test-key-123", client=_client(handler))
    resultado = feed.query_ip("185.220.101.5")

    assert len(llamadas) == 1
    assert resultado.status == STATUS_OK
    assert resultado.malicious is True
    assert resultado.score == 95.0
    assert resultado.found is True
    assert "847" in resultado.detail
    assert resultado.raw["countryCode"] == "RU"


def test_abuseipdb_score_bajo_el_umbral_no_es_malicioso():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {
            "abuseConfidenceScore": MALICIOUS_THRESHOLD - 1, "totalReports": 1,
        }})

    feed = AbuseIPDBFeed(api_key="k", client=_client(handler))
    resultado = feed.query_ip("1.2.3.4")
    assert resultado.status == STATUS_OK
    assert resultado.malicious is False


def test_abuseipdb_429_es_rate_limited_no_excepcion():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="Too Many Requests")

    feed = AbuseIPDBFeed(api_key="k", client=_client(handler))
    resultado = feed.query_ip("1.2.3.4")
    assert resultado.status == STATUS_RATE_LIMITED


def test_abuseipdb_error_de_red_no_lanza_excepcion():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("DNS resolution failed", request=request)

    feed = AbuseIPDBFeed(api_key="k", client=_client(handler))
    resultado = feed.query_ip("1.2.3.4")
    assert resultado.status == STATUS_ERROR
    assert "DNS resolution failed" in resultado.detail


# ---------------------------------- OTX -------------------------------------
def test_otx_sin_key_declara_not_configured():
    feed = OTXFeed(api_key=None)
    assert feed.query_ip("1.2.3.4").status == STATUS_NOT_CONFIGURED


def test_otx_con_key_cuenta_pulses():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-OTX-API-KEY"] == "otx-key"
        assert "IPv4/8.8.8.8/general" in str(request.url)
        return httpx.Response(200, json={"pulse_info": {
            "count": 3, "pulses": [{"name": "APT28 infra"}, {"name": "C2 tracker"}],
        }})

    feed = OTXFeed(api_key="otx-key", client=_client(handler))
    resultado = feed.query_ip("8.8.8.8")
    assert resultado.status == STATUS_OK
    assert resultado.malicious is True
    assert resultado.score == 30.0
    assert "APT28 infra" in resultado.categories


def test_otx_sin_pulses_no_es_malicioso():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}})

    feed = OTXFeed(api_key="otx-key", client=_client(handler))
    resultado = feed.query_ip("8.8.8.8")
    assert resultado.status == STATUS_OK
    assert resultado.malicious is False
    assert resultado.found is False


def test_otx_query_domain_y_hash_usan_endpoints_distintos():
    vistos = []

    def handler(request: httpx.Request) -> httpx.Response:
        vistos.append(str(request.url))
        return httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}})

    feed = OTXFeed(api_key="k", client=_client(handler))
    feed.query_domain("evil.com")
    feed.query_hash("d41d8cd98f00b204e9800998ecf8427e")
    assert any("domain/evil.com" in u for u in vistos)
    assert any("file/d41d8cd98f00b204e9800998ecf8427e" in u for u in vistos)


# ------------------------------- CISA KEV -----------------------------------
def test_cisa_kev_refresh_carga_catalogo_y_consulta_localmente():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulnerabilities": [
            {"cveID": "CVE-2021-44228", "vulnerabilityName": "Log4Shell"},
        ]})

    feed = CisaKevFeed(client=_client(handler))
    assert feed.refresh() == "OK"
    assert feed.is_known_exploited("cve-2021-44228")  # case-insensitive
    assert not feed.is_known_exploited("CVE-1999-0001")
    assert feed.detail_for("CVE-2021-44228")["vulnerabilityName"] == "Log4Shell"


def test_cisa_kev_no_refresca_dos_veces_sin_forzar():
    llamadas = []

    def handler(request: httpx.Request) -> httpx.Response:
        llamadas.append(1)
        return httpx.Response(200, json={"vulnerabilities": []})

    feed = CisaKevFeed(client=_client(handler))
    feed.refresh()
    feed.refresh()  # todavía vigente: no debe volver a pegarle a la red
    assert len(llamadas) == 1
    feed.refresh(force=True)
    assert len(llamadas) == 2


def test_cisa_kev_error_de_red_no_lanza_excepcion():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("timeout", request=request)

    feed = CisaKevFeed(client=_client(handler))
    assert feed.refresh() == "ERROR"
    assert not feed.loaded


def test_cisa_kev_persiste_y_recarga_desde_disco(tmp_path):
    ruta = tmp_path / "kev.json"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulnerabilities": [
            {"cveID": "CVE-2023-1234", "vulnerabilityName": "Test"},
        ]})

    feed = CisaKevFeed(cache_path=ruta, client=_client(handler))
    feed.refresh()
    assert ruta.exists()

    recargado = CisaKevFeed(cache_path=ruta)
    assert recargado.is_known_exploited("CVE-2023-1234")


# -------------------------------- CTICache -----------------------------------
def test_cache_evita_segunda_consulta_dentro_de_una_hora():
    llamadas = []

    def handler(request: httpx.Request) -> httpx.Response:
        llamadas.append(1)
        return httpx.Response(200, json={"data": {"abuseConfidenceScore": 90, "totalReports": 5}})

    feed = AbuseIPDBFeed(api_key="k", client=_client(handler))
    cache = CTICache(ttl_seconds=3600)
    enricher = LiveCTIEnricher(feeds=[feed], cache=cache)

    evento_1 = _evento(dst_ip="185.220.101.5")
    evento_2 = _evento(dst_ip="185.220.101.5")
    enricher.enrich_event(evento_1)
    enricher.enrich_event(evento_2)

    assert len(llamadas) == 1, "la misma IP se consultó dos veces en menos de una hora"
    stats = cache.stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 1


def test_cache_expira_pasado_el_ttl():
    cache = CTICache(ttl_seconds=0)  # expira inmediatamente
    resultado = FeedResult(feed="abuseipdb", observable="1.2.3.4", observable_type="ip",
                          status=STATUS_OK, malicious=True, score=90.0)
    cache.put(resultado)
    time.sleep(0.01)
    assert cache.get("abuseipdb", "1.2.3.4") is None


def test_cache_persiste_a_disco_y_se_recarga(tmp_path):
    ruta = tmp_path / "cti_cache.json"
    cache = CTICache(ttl_seconds=3600, path=ruta)
    resultado = FeedResult(feed="abuseipdb", observable="9.9.9.9", observable_type="ip",
                          status=STATUS_OK, malicious=True, score=80.0,
                          raw={"abuseConfidenceScore": 80})
    cache.put(resultado)

    recargado = CTICache(ttl_seconds=3600, path=ruta)
    recuperado = recargado.get("abuseipdb", "9.9.9.9")
    assert recuperado is not None
    assert recuperado.cached is True
    assert recuperado.score == 80.0
    assert recuperado.raw["abuseConfidenceScore"] == 80


# ------------------------------ LiveCTIEnricher ------------------------------
from datetime import datetime, timezone  # noqa: E402

from cybersentinel.schema import SecurityEvent  # noqa: E402


def _evento(**kw) -> SecurityEvent:
    base = dict(event_id="e1", timestamp=datetime.now(tz=timezone.utc), source="firewall",
               category="network", action="connection", src_ip="10.0.0.5")
    base.update(kw)
    return SecurityEvent(**base)


def test_no_consulta_ips_privadas():
    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail(f"no debería consultarse una IP privada: {request.url}")

    feed = AbuseIPDBFeed(api_key="k", client=_client(handler))
    enricher = LiveCTIEnricher(feeds=[feed])
    evento = _evento(src_ip="10.0.0.5", dst_ip="192.168.1.1")
    resultado = enricher.enrich_event(evento)
    assert resultado.results == []


@pytest.mark.parametrize("ip,publica", [
    ("8.8.8.8", True), ("185.220.101.5", True),
    ("10.0.0.1", False), ("172.16.0.1", False), ("192.168.1.1", False),
    ("127.0.0.1", False), ("", False), (None, False), ("no-es-una-ip", False),
])
def test_es_ip_publica(ip, publica):
    assert _es_ip_publica(ip) is publica


def test_narrativa_describe_el_hallazgo_como_pide_el_prompt():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {
            "abuseConfidenceScore": 95, "totalReports": 847, "countryCode": "?",
        }})

    feed = AbuseIPDBFeed(api_key="k", client=_client(handler))
    enricher = LiveCTIEnricher(feeds=[feed])
    evento = _evento(dst_ip="185.220.101.5")
    resultado = enricher.enrich_event(evento)

    assert "185.220.101.5" in resultado.narrative
    assert "abuseipdb" in resultado.narrative
    assert "95" in resultado.narrative


def test_feed_no_configurado_no_bloquea_a_los_demas():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"pulse_info": {"count": 1, "pulses": [{"name": "x"}]}})

    sin_key = AbuseIPDBFeed(api_key=None)
    con_key = OTXFeed(api_key="k", client=_client(handler))
    enricher = LiveCTIEnricher(feeds=[sin_key, con_key])
    resultado = enricher.enrich_event(_evento(dst_ip="8.8.8.8"))

    estados = {r.feed: r.status for r in resultado.results}
    assert estados["abuseipdb"] == STATUS_NOT_CONFIGURED
    assert estados["otx"] == STATUS_OK


# --------------------- integración con el pipeline real ---------------------
from cybersentinel.config import DEFAULT_RULES_DIR  # noqa: E402
from cybersentinel.pipeline import Pipeline  # noqa: E402


class _FeedFalsoMalicioso(CTIFeed):
    """Doble de red controlado: siempre 'configured', cuenta sus llamadas."""

    name = "fake_intel"

    def __init__(self) -> None:
        self.llamadas: list[str] = []

    @property
    def configured(self) -> bool:
        return True

    def query_ip(self, ip: str) -> FeedResult:
        self.llamadas.append(ip)
        return FeedResult(feed=self.name, observable=ip, observable_type="ip",
                          status=STATUS_OK, found=True, malicious=True, score=90.0,
                          detail="IP conocida como C2 en la base de prueba.")


def test_evento_benigno_no_consulta_cti_en_vivo():
    """Sin señal previa (sin regla, sin ML, sin desviación), no se gasta cuota."""
    feed = _FeedFalsoMalicioso()
    pipeline = Pipeline(
        rules_dir=DEFAULT_RULES_DIR, enable_rag=False, enable_llm=False,
        enable_ml=False, enable_temporal=False, enable_cti=False,
        enable_behavior=False, enable_live_cti=True, live_cti_feeds=[feed],
    )
    benigno = SecurityEvent(
        event_id="benigno-1", timestamp=datetime.now(tz=timezone.utc),
        source="sysmon", category="process", action="process_create",
        host="WKS-01", user="ana", process_name="chrome.exe",
        command_line="chrome.exe --tab 1", dst_ip="185.220.101.5", outcome="success",
    )
    reporte = pipeline.run_events([benigno])
    assert feed.llamadas == [], "se consultó CTI en vivo sin ninguna señal previa"
    assert reporte.results[0].evidence.live_cti_hits == []


def test_evento_con_regla_activada_si_consulta_cti_y_sube_el_score():
    """Con señal previa (una regla Sigma disparó), sí se consulta y enriquece."""
    feed = _FeedFalsoMalicioso()
    pipeline = Pipeline(
        rules_dir=DEFAULT_RULES_DIR, enable_rag=False, enable_llm=False,
        enable_ml=False, enable_temporal=False, enable_cti=False,
        enable_behavior=False, enable_live_cti=True, live_cti_feeds=[feed],
    )
    sospechoso = SecurityEvent(
        event_id="sospechoso-1", timestamp=datetime.now(tz=timezone.utc),
        source="sysmon", category="process", action="process_create",
        host="WKS-01", user="ana", process_name="powershell.exe",
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgA",
        dst_ip="185.220.101.5", outcome="success",
    )
    reporte = pipeline.run_events([sospechoso])
    evidencia = reporte.results[0].evidence

    assert feed.llamadas == ["185.220.101.5"]
    assert evidencia.live_cti_hits, "el evento con regla activada no se enriqueció con CTI"
    assert evidencia.live_cti_hits[0].malicious is True
    # 50 (regla) + 90/100 * 40 (CTI en vivo) = 86.0
    assert evidencia.hybrid_score == 86.0
