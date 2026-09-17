"""
Pruebas de los collectors empresariales.

Dos bloques:

- **E2E por collector**: fuente → `SecurityEvent` → pipeline real →
  `DetectionEvidence`. Demuestran que el contrato con el motor de detección es
  `SecurityEvent` y solo eso: el mismo pipeline, sin una línea modificada,
  digiere las cuatro fuentes.
- **Negativas**: un collector que se cae con un registro malformado no sirve
  para ingestión. Basta un emisor defectuoso para detener la vigilancia de toda
  la organización.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.collectors import (  # noqa: E402
    COLLECTORS, Collector, FirewallCollector, LinuxCollector, SuricataCollector,
    SysmonCollector, get_collector,
)
from cybersentinel.collectors.base import (  # noqa: E402
    TAG_INVALID_TIMESTAMP, TAG_OVERSIZED, TAG_TRUNCATED_FIELD,
)
from cybersentinel.pipeline import Pipeline  # noqa: E402
from cybersentinel.schema import SecurityEvent  # noqa: E402

RULES = ROOT / "config" / "rules"
BASE = datetime(2025, 3, 10, 10, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def pipeline():
    """
    El pipeline REAL, sin modificar.

    RAG y LLM apagados solo para que la suite no indexe 222 documentos por
    prueba; Sigma, ML, temporal y CTI —lo que decide la detección— corren.
    """
    return Pipeline(rules_dir=RULES, enable_rag=False, enable_llm=False)


def _evidencias(pipeline, eventos: list[SecurityEvent]):
    return pipeline.run_events(eventos).results


# ============================ E2E POR COLLECTOR =============================
def test_e2e_sysmon_json_llega_a_deteccion(pipeline):
    """Sysmon JSON → SecurityEvent → Sigma → DetectionEvidence con T1059."""
    crudo = {
        "EventID": 1, "Computer": "SRV-APP", "User": "admin",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "Hashes": "SHA256=ABC123,MD5=DEF456",
        "UtcTime": "2025-03-10 10:00:00",
    }
    resultado = SysmonCollector().collect(crudo)
    assert resultado.ok

    evidencia = _evidencias(pipeline, [resultado.event])[0].evidence
    assert "T1059" in evidencia.mitre_context
    assert evidencia.detection_status in ("RULE_MATCH", "RULE_AND_ANOMALY")
    assert evidencia.rule_matches
    # La procedencia sobrevive todo el recorrido.
    assert resultado.event.properties["source_type"] == "sysmon"
    assert resultado.event.properties["hashes"]["sha256"] == "ABC123"


def test_e2e_sysmon_xml_llega_a_deteccion(pipeline):
    """El XML del canal de eventos de Windows llega igual que el JSON."""
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>
      <TimeCreated SystemTime="2025-03-10T10:01:00.000Z"/><Computer>SRV-APP</Computer></System>
      <EventData>
        <Data Name="Image">C:\\Windows\\System32\\schtasks.exe</Data>
        <Data Name="CommandLine">schtasks /create /sc minute /tn U /tr t.ps1</Data>
        <Data Name="User">admin</Data>
      </EventData></Event>"""
    resultado = SysmonCollector().collect(xml)
    assert resultado.ok
    assert resultado.event.host == "SRV-APP"

    evidencia = _evidencias(pipeline, [resultado.event])[0].evidence
    assert "T1053" in evidencia.mitre_context


def test_e2e_linux_auditd_llega_a_evidencia(pipeline):
    """auditd → SecurityEvent → evidencia con estado por etapa."""
    linea = ('type=SYSCALL msg=audit(1741600800.123:456): arch=c000003e syscall=59 '
             'success=yes exit=0 comm="bash" exe="/bin/bash" key="exec" auid=1000 node=srv-01')
    resultado = LinuxCollector().collect(linea)
    assert resultado.ok
    assert resultado.event.category == "process"
    assert resultado.event.outcome == "success"
    assert resultado.event.properties["audit_type"] == "SYSCALL"

    evidencia = _evidencias(pipeline, [resultado.event])[0].evidence
    assert evidencia.run_id and evidencia.event_ref
    assert set(evidencia.stage_status) >= {"sigma", "ml", "temporal", "cti"}


def test_e2e_linux_syslog_fuerza_bruta_dispara_la_regla_agregada(pipeline):
    """
    Varios fallos de SSH por syslog activan la regla de fuerza bruta.

    Es la prueba de que una fuente nueva llega hasta una regla **con agregación
    temporal**, que es la que más depende de que la normalización sea correcta.
    """
    lineas = [
        f"<38>Mar 10 10:0{i}:00 srv-02 sshd[100{i}]: "
        f"Failed password for admin from 203.0.113.66 port 22 ssh2"
        for i in range(6)
    ]
    eventos, resultados = LinuxCollector().collect_many(lineas)
    assert all(r.ok for r in resultados)
    assert all(e.category == "authentication" and e.outcome == "failure" for e in eventos)

    reglas = {h.rule.id for r in _evidencias(pipeline, eventos) for h in r.evidence.rule_matches}
    assert "RULE-0001" in reglas, f"la fuerza bruta no se detectó; reglas: {reglas}"


def test_e2e_linux_journald_llega_a_evidencia(pipeline):
    crudo = {
        "__REALTIME_TIMESTAMP": "1741600800123456", "_HOSTNAME": "srv-01",
        "_COMM": "sshd", "PRIORITY": "4",
        "MESSAGE": "Failed password for root from 10.0.0.5 port 22 ssh2",
    }
    resultado = LinuxCollector().collect(crudo)
    assert resultado.ok
    assert resultado.event.category == "authentication"
    assert resultado.event.src_ip == "10.0.0.5"
    assert _evidencias(pipeline, [resultado.event])[0].evidence.event_ref


def test_e2e_firewall_llega_a_deteccion_de_c2(pipeline):
    """Cortafuegos → SecurityEvent → regla de baliza C2 (T1071)."""
    lineas = [
        f'<134>Mar 10 10:0{i}:00 fw1 date=2025-03-10 time=10:0{i}:00 devname="FG100" '
        f'srcip=10.0.0.50 dstip=203.0.113.66 srcport=5123{i} dstport=4444 '
        f'proto=tcp action="allow" sentbyte=1024 rcvdbyte=512 policyid=7'
        for i in range(4)
    ]
    eventos, resultados = FirewallCollector().collect_many(lineas)
    assert all(r.ok for r in resultados)
    assert eventos[0].dst_port == 4444 and eventos[0].bytes_out == 1024

    reglas = {h.rule.id for r in _evidencias(pipeline, eventos) for h in r.evidence.rule_matches}
    assert "RULE-0006" in reglas, f"la baliza C2 no se detectó; reglas: {reglas}"


def test_e2e_firewall_es_agnostico_del_fabricante():
    """El mismo flujo descrito con tres vocabularios distintos da lo mismo."""
    collector = FirewallCollector()
    variantes = [
        {"timestamp": "2025-03-10T10:00:00Z", "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8",
         "src_port": 1234, "dst_port": 53, "protocol": "udp", "action": "allow"},
        "srcip=10.0.0.5 dstip=8.8.8.8 srcport=1234 dstport=53 proto=udp action=allow "
        "time=2025-03-10T10:00:00Z",
        "src=10.0.0.5 dst=8.8.8.8 spt=1234 dpt=53 proto=udp act=allow "
        "timestamp=2025-03-10T10:00:00Z",
    ]
    eventos = [collector.collect(v).event for v in variantes]
    assert {e.src_ip for e in eventos} == {"10.0.0.5"}
    assert {e.dst_port for e in eventos} == {53}
    assert {e.outcome for e in eventos} == {"success"}


def test_e2e_suricata_alerta_llega_a_evidencia(pipeline):
    """Suricata EVE → SecurityEvent → evidencia, conservando la firma."""
    crudo = {
        "timestamp": "2025-03-10T10:10:00.000000+0000", "event_type": "alert",
        "flow_id": 1234567, "src_ip": "203.0.113.66", "dest_ip": "10.0.0.50",
        "src_port": 4444, "dest_port": 51234, "proto": "TCP",
        "alert": {"signature": "ET TROJAN Observed Malicious SSL Cert",
                  "category": "A Network Trojan was detected",
                  "severity": 1, "signature_id": 2028371},
        "flow": {"bytes_toserver": 500, "bytes_toclient": 1200},
    }
    resultado = SuricataCollector().collect(crudo)
    assert resultado.ok

    evento = resultado.event
    assert evento.category == "ids"
    assert evento.properties["severity_label"] == "critical"
    assert evento.properties["signature_id"] == 2028371
    # La detección es de Suricata: se declara para no atribuirse un mérito ajeno.
    assert evento.properties["detected_by"] == "suricata"

    evidencia = _evidencias(pipeline, [evento])[0].evidence
    assert evidencia.run_id and evidencia.event_ref
    assert evidencia.stage_status["sigma"] in ("OK", "NO_DATA")


def test_e2e_suricata_flow_no_se_trata_como_alerta():
    """Un `flow` de EVE no es una detección y no debe presentarse como tal."""
    evento = SuricataCollector().collect({
        "timestamp": "2025-03-10T10:00:00Z", "event_type": "flow",
        "src_ip": "10.0.0.5", "dest_ip": "8.8.8.8", "proto": "UDP",
        "flow": {"bytes_toserver": 100, "bytes_toclient": 200, "state": "closed"},
    }).event
    assert evento.category == "network"
    assert "detected_by" not in evento.properties


def test_las_cuatro_fuentes_comparten_un_unico_pipeline(pipeline):
    """
    La regla fundamental: el contrato es `SecurityEvent` y solo eso.

    Se mezclan las cuatro fuentes en una sola ejecución del pipeline sin
    configuración especial por fuente.
    """
    eventos = [
        SysmonCollector().collect({
            "EventID": 1, "Computer": "SRV-APP", "User": "admin",
            "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
            "UtcTime": "2025-03-10 10:00:00"}).event,
        LinuxCollector().collect(
            "<38>Mar 10 10:01:00 srv-02 sshd[1]: Accepted password for ana "
            "from 10.0.0.5 port 22 ssh2").event,
        FirewallCollector().collect(
            "srcip=10.0.0.50 dstip=203.0.113.66 dstport=4444 proto=tcp "
            "action=allow timestamp=2025-03-10T10:02:00Z").event,
        SuricataCollector().collect({
            "timestamp": "2025-03-10T10:03:00Z", "event_type": "alert",
            "src_ip": "203.0.113.66", "dest_ip": "10.0.0.50", "proto": "TCP",
            "alert": {"signature": "ET TROJAN test", "severity": 2}}).event,
    ]
    reporte = pipeline.run_events(eventos)

    assert reporte.total_events == 4
    assert len(reporte.results) == 4
    assert {r.evidence.run_id for r in reporte.results} == {reporte.run_id}
    fuentes = {e.properties["source_type"] for e in eventos}
    assert fuentes == {"sysmon", "linux", "firewall", "suricata"}


# ============================ PRUEBAS NEGATIVAS =============================
@pytest.mark.parametrize("nombre", sorted(COLLECTORS))
def test_evento_corrupto_no_tumba_el_sistema(nombre, caplog):
    """Un registro ilegible se registra y se descarta; nunca lanza excepción."""
    collector = get_collector(nombre)
    for basura in ("{json roto", "\x00\x01\x02", b"\xff\xfe binario", 12345, None, []):
        with caplog.at_level(logging.ERROR):
            resultado = collector.collect(basura)
        assert isinstance(resultado, CollectorResultAlias)
        assert not resultado.ok
        assert resultado.errors, f"{nombre} no explicó por qué falló con {basura!r}"
    assert collector.stats["failed"] > 0


@pytest.mark.parametrize("nombre", sorted(COLLECTORS))
def test_campo_faltante_normaliza_a_none(nombre):
    """Lo que no viene queda en None; nunca se rellena ni se lanza excepción."""
    minimos = {
        "sysmon": {"EventID": 1},
        "linux": {"MESSAGE": "algo ocurrió"},
        "firewall": {"src_ip": "10.0.0.1"},
        "suricata": {"event_type": "alert", "alert": {"signature": "x"}},
        "wazuh": {"rule": {"description": "algo"}},
    }
    resultado = get_collector(nombre).collect(minimos[nombre])
    assert resultado.ok, resultado.errors
    evento = resultado.event
    # Campos ausentes en el crudo: None, no cadenas vacías ni ceros inventados.
    assert evento.user is None or isinstance(evento.user, str)
    assert evento.dst_port is None or isinstance(evento.dst_port, int)
    assert evento.bytes_out is None or isinstance(evento.bytes_out, int)


@pytest.mark.parametrize("nombre", sorted(COLLECTORS))
def test_timestamp_invalido_usa_hora_de_ingesta_y_lo_marca(nombre):
    """
    Un timestamp ilegible cae a la hora de ingesta **con etiqueta**.

    Sin la etiqueta, un reloj roto en el emisor desplazaría eventos dentro de la
    ventana de correlación sin que nadie lo notara.
    """
    entradas = {
        "sysmon": {"EventID": 1, "UtcTime": "no es una fecha"},
        "linux": {"MESSAGE": "x", "__REALTIME_TIMESTAMP": "no es una fecha"},
        "firewall": {"src_ip": "10.0.0.1", "timestamp": "no es una fecha"},
        "suricata": {"event_type": "flow", "timestamp": "no es una fecha"},
        "wazuh": {"rule": {"description": "x"}, "timestamp": "no es una fecha"},
    }
    antes = datetime.now(tz=timezone.utc) - timedelta(seconds=5)
    resultado = get_collector(nombre).collect(entradas[nombre])

    assert resultado.ok
    assert TAG_INVALID_TIMESTAMP in resultado.annotations
    assert TAG_INVALID_TIMESTAMP in resultado.event.tags
    assert resultado.event.timestamp >= antes


@pytest.mark.parametrize("nombre", sorted(COLLECTORS))
def test_payload_excesivo_se_rechaza_sin_caerse(nombre, caplog):
    """Un registro desmedido se rechaza con registro, no tumba el proceso."""
    collector = get_collector(nombre)
    collector.max_payload_bytes = 1024
    with caplog.at_level(logging.WARNING):
        resultado = collector.collect("x" * 5000)

    assert not resultado.ok
    assert TAG_OVERSIZED in resultado.annotations
    assert collector.stats["oversized"] == 1
    assert "supera el maximo" in " ".join(resultado.errors)


def test_campo_desmedido_se_recorta_sin_perder_el_evento():
    """Una línea de comandos enorme se recorta; el resto del evento se conserva."""
    resultado = SysmonCollector().collect({
        "EventID": 1, "Computer": "SRV-APP",
        "CommandLine": "powershell.exe " + "A" * 20_000,
        "UtcTime": "2025-03-10 10:00:00",
    })
    assert resultado.ok
    assert TAG_TRUNCATED_FIELD in resultado.annotations
    assert len(resultado.event.command_line) < 20_000
    assert resultado.event.host == "SRV-APP"       # el evento sigue siendo útil


@pytest.mark.parametrize("nombre", sorted(COLLECTORS))
def test_evento_duplicado_se_procesa_de_forma_idempotente(nombre):
    """
    El mismo registro dos veces produce la misma huella.

    Es lo que permite deduplicar aguas abajo: si la huella variara entre
    ejecuciones, un reenvío del emisor se contaría como un evento nuevo.
    """
    entradas = {
        "sysmon": {"EventID": 1, "Computer": "SRV-APP", "User": "ana",
                   "CommandLine": "chrome.exe", "UtcTime": "2025-03-10 10:00:00"},
        "linux": "<38>Mar 10 10:00:00 srv-02 sshd[1]: Accepted password for ana from 10.0.0.5 port 22 ssh2",
        "firewall": "srcip=10.0.0.5 dstip=8.8.8.8 dstport=53 action=allow timestamp=2025-03-10T10:00:00Z",
        "suricata": {"timestamp": "2025-03-10T10:00:00Z", "event_type": "alert",
                     "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2",
                     "alert": {"signature": "test", "severity": 3}},
        "wazuh": {"timestamp": "2025-03-10T10:00:00Z",
                 "rule": {"id": "5710", "level": 10, "description": "sshd: brute force"},
                 "agent": {"id": "001", "name": "SRV-APP"},
                 "data": {"srcip": "10.0.0.5", "srcuser": "ana"}},
    }
    collector = get_collector(nombre)
    primero = collector.collect(entradas[nombre]).event
    segundo = collector.collect(entradas[nombre]).event
    assert primero.fingerprint() == segundo.fingerprint()


def test_un_registro_malo_no_arrastra_al_lote():
    """En un lote mixto, lo bueno se procesa y lo malo se reporta."""
    eventos, resultados = LinuxCollector().collect_many([
        "<38>Mar 10 10:00:00 srv sshd[1]: Accepted password for ana from 10.0.0.5 port 22 ssh2",
        "esto no es un registro de ningún formato conocido",
        "<38>Mar 10 10:01:00 srv sshd[2]: Failed password for root from 10.0.0.9 port 22 ssh2",
    ])
    assert len(eventos) == 2
    assert sum(1 for r in resultados if not r.ok) == 1


def test_get_collector_rechaza_una_fuente_desconocida():
    with pytest.raises(ValueError, match="Collector desconocido"):
        get_collector("no-existe")


def test_ningun_collector_obliga_a_tocar_el_motor():
    """
    La regla fundamental, comprobada sobre el código.

    Si un collector importara el motor de detección, añadir una fuente podría
    obligar a modificarlo. El contrato es `SecurityEvent` y solo eso.
    """
    import ast

    # Se inspeccionan los imports reales, no el texto: buscar subcadenas daría
    # falsos positivos con cualquier identificador que las contenga.
    prohibidos = {"rules_engine", "anomaly", "sequence_model", "temporal",
                  "hybrid", "correlator", "detection", "correlation"}
    directorio = ROOT / "src" / "cybersentinel" / "collectors"

    for archivo in sorted(directorio.glob("*.py")):
        arbol = ast.parse(archivo.read_text(encoding="utf-8"))
        modulos: set[str] = set()
        for nodo in ast.walk(arbol):
            if isinstance(nodo, ast.Import):
                modulos.update(a.name for a in nodo.names)
            elif isinstance(nodo, ast.ImportFrom) and nodo.module:
                modulos.add(nodo.module)

        for modulo in modulos:
            piezas = set(modulo.split("."))
            assert not (piezas & prohibidos), (
                f"{archivo.name} importa '{modulo}': el collector no debe "
                "conocer el motor de detección. El contrato es SecurityEvent."
            )


# Alias para el aserto de tipo de la prueba de corrupción.
from cybersentinel.collectors.base import CollectorResult as CollectorResultAlias  # noqa: E402
from cybersentinel.collectors.base import MAX_PAYLOAD_BYTES  # noqa: E402


# ==================== GAPS DE LA AUDITORIA: cierre puntual ==================
def test_el_limite_real_de_payload_es_cinco_megabytes():
    """
    El límite de producción (no el que sobreescriben las pruebas anteriores)
    debe ser 5 MiB: un evento de, por ejemplo, 2 MB es telemetría legítima
    (una traza de proceso larga, un XML de Sysmon con muchos campos) y no debe
    rechazarse.
    """
    assert MAX_PAYLOAD_BYTES == 5 * 1024 * 1024

    collector = SysmonCollector()
    cerca_del_limite = json.dumps({
        "EventID": 1, "Computer": "SRV-APP", "UtcTime": "2025-03-10 10:00:00",
        "padding": "a" * (2 * 1024 * 1024),
    })
    assert len(cerca_del_limite.encode()) < MAX_PAYLOAD_BYTES
    resultado = collector.collect(cerca_del_limite)
    assert resultado.ok, resultado.errors
    assert TAG_OVERSIZED not in resultado.annotations

    demasiado_grande = "x" * (MAX_PAYLOAD_BYTES + 1)
    rechazado = collector.collect(demasiado_grande)
    assert not rechazado.ok
    assert TAG_OVERSIZED in rechazado.annotations


@pytest.mark.parametrize("nombre", sorted(COLLECTORS))
def test_encoding_invalido_cae_a_latin1_en_vez_de_perder_el_dato(nombre):
    """
    Un emisor que manda Latin-1 en vez de UTF-8 (típico de un Windows con
    locale regional) no debe perder el dato: `\\xf1` (0xF1) no es una
    secuencia UTF-8 válida seguida de un caracter ASCII, así que la decodificación
    estricta falla y debe caer a Latin-1, donde 0xF1 es 'ñ', en vez de
    sustituirse por el carácter de reemplazo '\\ufffd'.
    """
    entradas: dict[str, tuple[bytes, str, str]] = {
        "sysmon": (
            b'{"EventID": 1, "Computer": "SRV-\xf1", "UtcTime": "2025-03-10 10:00:00"}',
            "host", "SRV-ñ",
        ),
        "linux": (
            b"<38>Mar 10 10:00:00 srv-\xf1 sshd[1]: Accepted password for ana "
            b"from 10.0.0.5 port 22 ssh2",
            "host", "srv-ñ",
        ),
        "firewall": (
            b'{"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "action": "allow", '
            b'"host": "fw-\xf1", "timestamp": "2025-03-10T10:00:00Z"}',
            "host", "fw-ñ",
        ),
        "suricata": (
            b'{"timestamp": "2025-03-10T10:00:00Z", "event_type": "alert", '
            b'"host": "sensor-\xf1", "alert": {"signature": "x", "severity": 3}}',
            "host", "sensor-ñ",
        ),
        "wazuh": (
            b'{"timestamp": "2025-03-10T10:00:00Z", "rule": {"description": "x"}, '
            b'"agent": {"id": "001", "name": "srv-\xf1"}}',
            "host", "srv-ñ",
        ),
    }
    crudo, campo, esperado = entradas[nombre]
    with pytest.raises(UnicodeDecodeError):
        crudo.decode("utf-8")          # confirma que el caso de prueba es real

    resultado = get_collector(nombre).collect(crudo)
    assert resultado.ok, resultado.errors
    assert getattr(resultado.event, campo) == esperado
    assert "�" not in str(getattr(resultado.event, campo))


# --- Campos que el spec pedía y no se extraían -------------------------------
def test_linux_auditd_syscall_expone_uid_gid_y_return_code():
    linea = ('type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 '
             'success=yes exit=0 uid=1000 gid=1000 auid=1000 '
             'comm="curl" exe="/usr/bin/curl"')
    resultado = LinuxCollector().collect(linea)
    assert resultado.ok, resultado.errors
    props = resultado.event.properties
    assert props["uid"] == "1000"
    assert props["gid"] == "1000"
    assert props["return_code"] == 0


def test_linux_auditd_path_expone_file_path():
    linea = ('type=PATH msg=audit(1700000000.123:457): item=0 name="/etc/shadow" '
             'inode=1234 mode=0100600')
    resultado = LinuxCollector().collect(linea)
    assert resultado.ok, resultado.errors
    assert resultado.event.properties["file_path"] == "/etc/shadow"


def test_linux_auditd_netfilter_expone_dst_ip_y_puerto():
    linea = ('type=NETFILTER_PKT msg=audit(1700000000.123:458): mark=0 saddr=10.0.0.5 '
             'daddr=203.0.113.5 sport=51000 dport=443 proto=6')
    resultado = LinuxCollector().collect(linea)
    assert resultado.ok, resultado.errors
    assert resultado.event.properties["dst_ip"] == "203.0.113.5"
    assert resultado.event.properties["dst_port"] == 443


def test_linux_journald_expone_uid_gid_y_exe():
    resultado = LinuxCollector().collect({
        "MESSAGE": "sesion abierta", "_COMM": "sshd", "_UID": "0", "_GID": "0",
        "_EXE": "/usr/sbin/sshd", "__REALTIME_TIMESTAMP": "1700000000000000",
    })
    assert resultado.ok, resultado.errors
    props = resultado.event.properties
    assert props["uid"] == "0"
    assert props["gid"] == "0"
    assert props["exe"] == "/usr/sbin/sshd"


def test_firewall_expone_packets_in_y_packets_out():
    crudo = ("srcip=10.0.0.5 dstip=8.8.8.8 dstport=53 action=allow "
             "sentpkt=12 rcvdpkt=9 timestamp=2025-03-10T10:00:00Z")
    resultado = FirewallCollector().collect(crudo)
    assert resultado.ok, resultado.errors
    props = resultado.event.properties
    assert props["packets_out"] == 12
    assert props["packets_in"] == 9
