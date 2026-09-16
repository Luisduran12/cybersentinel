"""
Banco de pruebas empresarial: rendimiento medido y ablación con verdad-terreno.

    python scripts/benchmark_enterprise.py --seconds 10
    python scripts/benchmark_enterprise.py --only-ablation

Todo lo que reporta procede de una ejecución real. **No hay ningún número
escrito a mano**: si algo no puede medirse, se registra como `NOT EVALUABLE` en
lugar de rellenarse.

Dos experimentos independientes, y conviene no confundirlos:

- **Carga**: mide caudal, latencia por componente y consumo de recursos a cinco
  intensidades. No dice nada sobre la calidad de la detección.
- **Ablación**: mide la calidad de la detección de siete configuraciones sobre
  **el mismo conjunto etiquetado**. No dice nada sobre el rendimiento.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.observability import new_run_id  # noqa: E402
from cybersentinel.pipeline import ALERT_THRESHOLD, Pipeline  # noqa: E402
from cybersentinel.schema import SecurityEvent  # noqa: E402

RULES = ROOT / "config" / "rules"
RESULTS = ROOT / "results"

#: Intensidades del experimento de carga.
ESCENARIOS = [100, 500, 1_000, 5_000, 10_000]

#: Las siete configuraciones de la ablación.
CONFIGURACIONES: dict[str, dict[str, bool]] = {
    "A_solo_sigma":     {"enable_ml": False, "enable_temporal": False},
    "B_solo_ml":        {"enable_ml": True,  "enable_temporal": False, "sin_sigma": True},
    "C_solo_temporal":  {"enable_ml": False, "enable_temporal": True,  "sin_sigma": True},
    "D_sigma_ml":       {"enable_ml": True,  "enable_temporal": False},
    "E_sigma_temporal": {"enable_ml": False, "enable_temporal": True},
    "F_ml_temporal":    {"enable_ml": True,  "enable_temporal": True,  "sin_sigma": True},
    "G_completo":       {"enable_ml": True,  "enable_temporal": True},
}


# ===================== Conjunto etiquetado con verdad-terreno ===============
@dataclass
class EtiquetadoEvento:
    """Un evento con su etiqueta real y el motivo por el que la tiene."""

    event: SecurityEvent
    label: int              # 1 = malicioso, 0 = benigno
    scenario: str           # qué representa: por qué es lo que es


def construye_conjunto(n_benignos: int = 2000, seed: int = 42) -> list[EtiquetadoEvento]:
    """
    Construye telemetría sintética **con verdad-terreno conocida por diseño**.

    La etiqueta no sale de ningún detector: la fija el generador. Es la única
    forma de medir falsos positivos sin circularidad — usar la salida de un
    componente como etiqueta de otro produce números que solo miden el acuerdo
    entre ambos.

    Los escenarios maliciosos reproducen las técnicas que las reglas cubren; los
    benignos incluyen **casos difíciles** deliberados (administración legítima,
    transferencias grandes, puertos altos), porque un conjunto benigno trivial
    daría un recuento de falsos positivos engañosamente bueno.
    """
    rng = random.Random(seed)
    base = datetime(2025, 3, 10, 9, 0, tzinfo=timezone.utc)
    conjunto: list[EtiquetadoEvento] = []
    t = 0

    def ev(**kw) -> SecurityEvent:
        nonlocal t
        t += 1
        datos = dict(event_id=f"bench-{t:06d}", timestamp=base + timedelta(seconds=t),
                     source="sysmon", category="process", action="process_create")
        datos.update(kw)
        return SecurityEvent(**datos)

    # --- Benignos ordinarios ---
    for i in range(n_benignos):
        if i % 3 == 0:
            e = ev(host=rng.choice(["WKS-01", "WKS-02", "WKS-03"]),
                   user=rng.choice(["ana", "carlos", "sofia"]),
                   command_line=f"chrome.exe --tab {rng.randint(1, 999)}",
                   process_name="chrome.exe", outcome="success")
        elif i % 3 == 1:
            e = ev(source="firewall", category="network", action="connection",
                   host=rng.choice(["WKS-01", "WKS-02"]),
                   src_ip=f"10.0.0.{rng.randint(10, 60)}",
                   dst_ip=f"93.184.216.{rng.randint(1, 250)}",
                   dst_port=rng.choice([443, 443, 80, 53]), protocol="tcp",
                   bytes_out=rng.randint(200, 50_000), bytes_in=rng.randint(500, 900_000))
        else:
            e = ev(source="auth", category="authentication", action="user_login",
                   host=rng.choice(["SRV-APP", "WKS-01"]),
                   user=rng.choice(["ana", "carlos"]),
                   src_ip=f"10.0.0.{rng.randint(10, 60)}", outcome="success")
        conjunto.append(EtiquetadoEvento(e, 0, "benigno_ordinario"))

    # --- Benignos DIFÍCILES: lo que un detector ingenuo marcaría mal ---
    for i in range(60):
        conjunto.append(EtiquetadoEvento(
            ev(host="SRV-BACKUP", user="svc_backup",
               command_line=f"robocopy.exe D:\\datos \\\\nas\\backup{i} /MIR",
               process_name="robocopy.exe", outcome="success"),
            0, "benigno_dificil_administracion"))
    for i in range(40):
        conjunto.append(EtiquetadoEvento(
            ev(source="firewall", category="network", action="connection",
               host="SRV-BACKUP", src_ip="10.0.0.20", dst_ip="10.0.0.99",
               dst_port=445, protocol="tcp",
               bytes_out=rng.randint(50_000_000, 99_000_000), bytes_in=2000),
            0, "benigno_dificil_transferencia_grande"))
    # Fallos de autenticación *genuinamente* aislados: usuario, host e IP
    # distintos en cada uno, de modo que ninguna clave de agrupación acumula.
    # Si se generaran 30 fallos seguidos del mismo usuario desde la misma IP,
    # la regla de fuerza bruta acertaría al dispararse y el "falso positivo"
    # resultante sería un error de etiquetado, no del detector.
    for i in range(30):
        conjunto.append(EtiquetadoEvento(
            ev(source="auth", category="authentication", action="user_login",
               host=f"WKS-{i % 12:02d}", user=f"empleado{i}",
               src_ip=f"10.0.{i}.{10 + i}", outcome="failure"),
            0, "benigno_dificil_fallo_aislado"))

    # --- Maliciosos: las técnicas que las reglas cubren ---
    for i in range(8):     # fuerza bruta (regla agregada)
        conjunto.append(EtiquetadoEvento(
            ev(source="auth", category="authentication", action="user_login",
               host="SRV-APP", user="admin", src_ip="203.0.113.66", outcome="failure"),
            1, "ataque_fuerza_bruta_T1110"))
    for i in range(12):    # PowerShell ofuscado
        conjunto.append(EtiquetadoEvento(
            ev(host="SRV-APP", user="admin", process_name="powershell.exe",
               command_line="powershell.exe -nop -w hidden -enc SQBFAFgAKAAuAC4A",
               outcome="success"),
            1, "ataque_powershell_T1059"))
    for i in range(10):    # persistencia
        conjunto.append(EtiquetadoEvento(
            ev(host="SRV-APP", user="admin", process_name="schtasks.exe",
               command_line="schtasks /create /sc minute /tn Updater /tr backdoor.ps1",
               outcome="success"),
            1, "ataque_persistencia_T1053"))
    for i in range(8):     # descubrimiento
        conjunto.append(EtiquetadoEvento(
            ev(host="SRV-APP", user="admin", process_name="nmap.exe",
               command_line="nmap -sS -p- 10.0.0.0/24", outcome="success"),
            1, "ataque_descubrimiento_T1046"))
    for i in range(12):    # baliza C2 (regla agregada)
        conjunto.append(EtiquetadoEvento(
            ev(source="firewall", category="network", action="connection",
               host="SRV-APP", src_ip="10.0.0.50", dst_ip="203.0.113.66",
               dst_port=4444, protocol="tcp", bytes_out=2048, bytes_in=512),
            1, "ataque_c2_T1071"))
    for i in range(6):     # exfiltración
        conjunto.append(EtiquetadoEvento(
            ev(source="firewall", category="network", action="connection",
               host="SRV-APP", src_ip="10.0.0.50", dst_ip="203.0.113.66",
               dst_port=443, protocol="tcp", bytes_out=524_288_000, bytes_in=1000),
            1, "ataque_exfiltracion_T1048"))
    for i in range(6):     # movimiento lateral
        conjunto.append(EtiquetadoEvento(
            ev(source="firewall", category="network", action="connection",
               host="SRV-APP", src_ip="10.0.0.50", dst_ip="10.0.0.60",
               dst_port=3389, protocol="tcp", bytes_out=5000, bytes_in=8000),
            1, "ataque_lateral_T1021"))

    conjunto.sort(key=lambda x: x.event.timestamp)
    return conjunto


# ============================== Recursos ====================================
class MonitorRecursos:
    """
    Muestrea CPU y memoria del proceso durante el experimento.

    Con `psutil` se muestrea de forma periódica y se obtienen media y máximo.
    Sin él se recurre a `resource.getrusage`, de la biblioteca estándar, que da
    tiempo de CPU consumido y pico de memoria residente pero **no** una serie
    temporal. Se degrada, no se inventa: el informe declara con qué se midió.
    """

    def __init__(self, intervalo: float = 0.25) -> None:
        self.intervalo = intervalo
        self._parar = threading.Event()
        self._hilo: threading.Thread | None = None
        self.cpu: list[float] = []
        self.rss_mb: list[float] = []
        self.backend = "resource"
        try:
            import psutil  # noqa: F401
            self.backend = "psutil"
        except ImportError:
            pass
        self._t0 = 0.0
        self._cpu0 = 0.0

    def _muestrea(self) -> None:
        import psutil
        proceso = psutil.Process(os.getpid())
        proceso.cpu_percent(None)
        while not self._parar.is_set():
            self.cpu.append(proceso.cpu_percent(None))
            self.rss_mb.append(proceso.memory_info().rss / 1_048_576)
            self._parar.wait(self.intervalo)

    def __enter__(self) -> "MonitorRecursos":
        self._t0 = time.perf_counter()
        if self.backend == "psutil":
            self._hilo = threading.Thread(target=self._muestrea, daemon=True)
            self._hilo.start()
        else:
            import resource
            uso = resource.getrusage(resource.RUSAGE_SELF)
            self._cpu0 = uso.ru_utime + uso.ru_stime
        return self

    def __exit__(self, *_: Any) -> None:
        self._parar.set()
        if self._hilo:
            self._hilo.join(timeout=2)
        self._elapsed = max(time.perf_counter() - self._t0, 1e-9)

    def resumen(self) -> dict[str, Any]:
        if self.backend == "psutil":
            if not self.cpu:
                return {"status": "NOT EVALUABLE", "backend": "psutil",
                        "reason": "el experimento terminó antes de la primera muestra"}
            return {
                "status": "OK", "backend": "psutil", "samples": len(self.cpu),
                "cpu_percent": {"mean": round(statistics.mean(self.cpu), 1),
                                "max": round(max(self.cpu), 1)},
                "rss_mb": {"mean": round(statistics.mean(self.rss_mb), 1),
                           "max": round(max(self.rss_mb), 1)},
            }
        import resource as _r
        uso = _r.getrusage(_r.RUSAGE_SELF)
        cpu_s = (uso.ru_utime + uso.ru_stime) - self._cpu0
        # macOS reporta ru_maxrss en bytes; Linux en kilobytes.
        divisor = 1_048_576 if sys.platform == "darwin" else 1024
        return {
            "status": "OK", "backend": "resource",
            "cpu_percent": {"mean": round(100 * cpu_s / self._elapsed, 1),
                            "max": "NOT EVALUABLE"},
            "rss_mb": {"mean": "NOT EVALUABLE",
                       "max": round(uso.ru_maxrss / divisor, 1)},
            "note": ("sin psutil no hay serie temporal: la CPU es la media del "
                     "intervalo y la RAM el pico del proceso desde su arranque"),
        }


def _pct(valores: list[float], p: float) -> float:
    if not valores:
        return 0.0
    orden = sorted(valores)
    k = (len(orden) - 1) * p / 100
    b, a = int(k), min(int(k) + 1, len(orden) - 1)
    return orden[b] + (orden[a] - orden[b]) * (k - b)


def _estadisticas(valores: list[float]) -> dict[str, float]:
    if not valores:
        return {"status": "NOT EVALUABLE"}
    return {
        "mean": round(statistics.mean(valores), 4),
        "p50": round(_pct(valores, 50), 4),
        "p95": round(_pct(valores, 95), 4),
        "p99": round(_pct(valores, 99), 4),
        "max": round(max(valores), 4),
        "samples": len(valores),
    }


def _atribucion(por_lote: dict[str, list[float]],
                servicio: list[float]) -> dict[str, Any]:
    """
    Cuánto del tiempo de servicio explican las fases medidas.

    Un desglose que no suma el total no es un desglose: es una selección. Si
    queda un resto sin atribuir, se dice cuánto y no se reparte a ojo entre las
    fases conocidas.
    """
    if not servicio:
        return {"status": "NOT EVALUABLE"}
    medido = statistics.mean(servicio)
    fases = {k: statistics.mean(v) for k, v in por_lote.items() if k != "total"}
    atribuido = sum(fases.values())
    return {
        "service_mean_ms": round(medido, 4),
        "attributed_ms": round(atribuido, 4),
        "unattributed_ms": round(max(0.0, medido - atribuido), 4),
        "coverage": round(min(1.0, atribuido / medido), 4) if medido else "NOT EVALUABLE",
        "share_by_phase": {k: round(v / atribuido, 4) if atribuido else 0.0
                           for k, v in sorted(fases.items(),
                                              key=lambda kv: -kv[1])},
    }


# ============================== Carga =======================================
def experimento_carga(conjunto: list[EtiquetadoEvento], objetivo: int,
                      segundos: int, batch: int | None = None) -> dict[str, Any]:
    """
    Alimenta el pipeline a un caudal objetivo y mide qué ocurre de verdad.

    Hay dos latencias distintas y confundirlas maquilla el resultado:

    - **Servicio**: lo que el pipeline tarda en procesar un evento. Apenas
      cambia con la carga.
    - **Respuesta**: desde que el evento *debería* haber entrado, al ritmo
      objetivo, hasta que su detección está lista. Incluye la espera en cola.

    Bajo saturación la primera se mantiene plana mientras la segunda crece sin
    techo, así que reportar solo la de servicio haría parecer que el sistema
    aguanta 10.000 ev/s cuando en realidad acumula un atraso creciente. Se
    miden y se reportan las dos.
    """
    pipeline = Pipeline(rules_dir=RULES, enable_rag=False, enable_llm=False)
    eventos = [x.event for x in conjunto]
    total_objetivo = objetivo * segundos

    # El lote representa ~100 ms de llegadas. Un lote fijo de 200 a 100 ev/s
    # impondría 2 s de espera por construcción y se mediría el tamaño del lote,
    # no el sistema.
    if batch is None:
        batch = max(10, min(500, objetivo // 10))

    # Calentamiento excluido de la medición: cargar reglas y ajustar la línea
    # base del detector es un coste de arranque que ocurre una vez, no parte
    # del caudal en régimen. Se declara en el informe.
    calentamiento = eventos[:min(len(eventos), 200)]
    t_cal = time.perf_counter()
    pipeline.run_events(calentamiento)
    ms_calentamiento = (time.perf_counter() - t_cal) * 1000.0

    servicio: list[float] = []
    respuesta: list[float] = []
    por_componente: dict[str, list[float]] = {
        k: [] for k in ("normalization", "sigma", "ml", "temporal", "cti", "total")
    }
    # Fases por lote, en ms por evento. Son las que hacen el trabajo de verdad:
    # la traza por evento solo cronometra la consulta a un resultado ya
    # calculado, de modo que sin esto el desglose atribuiría el 3 % del tiempo.
    por_lote: dict[str, list[float]] = {}
    errores: dict[str, int] = {}
    recibidos = procesados = 0
    atraso_max = 0.0

    with MonitorRecursos() as recursos:
        inicio = time.perf_counter()
        while procesados < total_objetivo:
            cuantos = min(batch, total_objetivo - procesados)
            lote = [eventos[(procesados + i) % len(eventos)] for i in range(cuantos)]

            # Momento en que cada evento del lote *debería* haber llegado.
            llegada_primero = procesados / objetivo
            llegada_ultimo = (procesados + cuantos - 1) / objetivo

            # Si el generador va por delante del reloj, se espera: emitir más
            # rápido que el caudal objetivo mediría otro experimento.
            adelanto = llegada_ultimo - (time.perf_counter() - inicio)
            if adelanto > 0:
                time.sleep(adelanto)
            recibidos += cuantos

            t0 = time.perf_counter()
            try:
                reporte = pipeline.run_events(lote)
                fin_lote = time.perf_counter()
                transcurrido = (fin_lote - t0) * 1000.0
                procesados += len(reporte.results)

                # Servicio: el lote se procesa como una unidad, así que el
                # reparto por evento es uniforme.
                servicio.extend([transcurrido / max(len(lote), 1)] * len(lote))

                # Respuesta: cada evento se completa al terminar el lote.
                completado = fin_lote - inicio
                for i in range(len(reporte.results)):
                    llegada = (procesados - len(reporte.results) + i) / objetivo
                    respuesta.append(max(0.0, completado - llegada) * 1000.0)
                atraso_max = max(atraso_max, completado - llegada_primero)

                for r in reporte.results:
                    lat = r.trace.to_dict()["latencies_ms"]
                    for comp in por_componente:
                        if comp in lat:
                            por_componente[comp].append(lat[comp])
                for fase, ms in reporte.batch_timings_ms.items():
                    por_lote.setdefault(fase, []).append(ms / max(len(lote), 1))
            except Exception as exc:
                clave = type(exc).__name__
                errores[clave] = errores.get(clave, 0) + 1
                procesados += cuantos       # no se reintenta: se contabiliza
        duracion = time.perf_counter() - inicio

    logrado = procesados / duracion
    return {
        "target_eps": objetivo,
        "batch_size": batch,
        "warmup_events": len(calentamiento),
        "warmup_ms": round(ms_calentamiento, 1),
        "duration_s": round(duracion, 3),
        "events_received": recibidos,
        "events_accepted": recibidos,
        "events_processed": procesados - sum(errores.values()),
        "events_rejected": sum(errores.values()),
        # Nada se descarta: el bucle es síncrono y sin cola acotada. Lo que la
        # saturación produce aquí no es pérdida, es atraso.
        "events_lost": 0,
        "achieved_eps": round(logrado, 1),
        "target_met": logrado >= objetivo * 0.95,
        "saturated": logrado < objetivo * 0.95,
        "max_backlog_s": round(atraso_max, 3),
        "service_latency_ms": _estadisticas(servicio),
        "response_latency_ms": _estadisticas(respuesta),
        "latency_by_component_ms": {k: _estadisticas(v) for k, v in por_componente.items()},
        "latency_by_batch_phase_ms_per_event": {
            k: _estadisticas(v) for k, v in por_lote.items()},
        "attribution": _atribucion(por_lote, servicio),
        "errors_by_type": errores or {},
        "resources": recursos.resumen(),
    }


# ============================== Ablación ====================================
def experimento_ablacion(conjunto: list[EtiquetadoEvento]) -> dict[str, Any]:
    """
    Las siete configuraciones sobre **los mismos** eventos etiquetados.

    Se considera detección que el evento supere el umbral de alerta, que es la
    decisión que el sistema toma de verdad. Medir sobre una señal intermedia
    daría un número que el producto no produce.
    """
    eventos = [x.event for x in conjunto]
    y = [x.label for x in conjunto]
    resultados: dict[str, Any] = {}

    for nombre, definicion in CONFIGURACIONES.items():
        banderas = dict(definicion)
        sin_sigma = banderas.pop("sin_sigma", False)
        # "Sin Sigma" se consigue con un directorio de reglas vacío: el motor
        # sigue ahí, simplemente no tiene reglas que aplicar. Es más honesto que
        # desactivar el componente, porque replica el caso real de una
        # telemetría que ninguna regla cubre.
        with tempfile.TemporaryDirectory() as vacio:
            pipeline = Pipeline(
                rules_dir=(vacio if sin_sigma else RULES),
                enable_rag=False, enable_llm=False,
                enable_cti=False, **banderas,
            )
            reporte = pipeline.run_events(eventos)

        pred = [1 if r.evidence.hybrid_score >= ALERT_THRESHOLD else 0
                for r in reporte.results]
        tp = sum(1 for p, real in zip(pred, y) if p == 1 and real == 1)
        fp = sum(1 for p, real in zip(pred, y) if p == 1 and real == 0)
        tn = sum(1 for p, real in zip(pred, y) if p == 0 and real == 0)
        fn = sum(1 for p, real in zip(pred, y) if p == 0 and real == 1)

        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / (tp + fn) if (tp + fn) else None
        f1 = (2 * precision * recall / (precision + recall)
              if (precision and recall) else (0.0 if precision is not None else None))

        # La distribución de puntuaciones explica los ceros estructurales: una
        # configuración cuyo máximo observado no llega al umbral no puede
        # producir una detección por construcción, y su recall de 0 no dice
        # nada sobre la calidad de la señal, solo sobre la capa de puntuación.
        scores = [r.evidence.hybrid_score for r in reporte.results]
        # Recall y FP desglosados por escenario: dónde acierta y dónde falla.
        por_escenario: dict[str, dict[str, int]] = {}
        for etiquetado, prediccion in zip(conjunto, pred):
            celda = por_escenario.setdefault(
                etiquetado.scenario, {"total": 0, "detected": 0})
            celda["total"] += 1
            celda["detected"] += prediccion

        resultados[nombre] = {
            "config": dict(definicion),
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "precision": round(precision, 4) if precision is not None else "NOT EVALUABLE",
            "recall": round(recall, 4) if recall is not None else "NOT EVALUABLE",
            "f1": round(f1, 4) if f1 is not None else "NOT EVALUABLE",
            "fpr": round(fp / (fp + tn), 4) if (fp + tn) else "NOT EVALUABLE",
            "detections": sum(pred),
            "score_distribution": {
                "max_observed": round(max(scores), 2) if scores else "NOT EVALUABLE",
                "mean": round(statistics.mean(scores), 3) if scores else "NOT EVALUABLE",
                "above_threshold": sum(1 for x in scores if x >= ALERT_THRESHOLD),
                "above_half_threshold": sum(1 for x in scores
                                            if x >= ALERT_THRESHOLD / 2),
                "structurally_blind": (bool(scores)
                                       and max(scores) < ALERT_THRESHOLD),
            },
            "by_scenario": por_escenario,
            # Recall por incidente, no por evento. Una regla agregada —fuerza
            # bruta, baliza C2— detecta *la secuencia* cuando se completa el
            # recuento, no cada evento que la compone. Contar por evento
            # penaliza a esas reglas por hacer justo lo que deben hacer, así
            # que se reportan las dos unidades y se dice cuál es cuál.
            "incident_level": {
                "detected": sum(1 for esc, v in por_escenario.items()
                                if esc.startswith("ataque") and v["detected"] > 0),
                "total": sum(1 for esc in por_escenario if esc.startswith("ataque")),
                "missed_scenarios": sorted(
                    esc for esc, v in por_escenario.items()
                    if esc.startswith("ataque") and v["detected"] == 0),
            },
            # Se guarda la predicción para el análisis de falsos positivos.
            "_pred": pred,
        }
    return resultados


def analiza_falsos_positivos(conjunto: list[EtiquetadoEvento],
                             ablacion: dict[str, Any]) -> dict[str, Any]:
    """
    ¿Qué genera los falsos positivos? ¿La regla, el umbral, la feature o el dato?

    Se atribuye cada FP a la señal que lo empujó por encima del umbral, usando
    la evidencia del sistema completo.
    """
    eventos = [x.event for x in conjunto]
    pipeline = Pipeline(rules_dir=RULES, enable_rag=False, enable_llm=False,
                        enable_cti=False)
    reporte = pipeline.run_events(eventos)

    analisis: dict[str, Any] = {
        "threshold": ALERT_THRESHOLD,
        "by_scenario": {}, "by_cause": {}, "examples": [],
    }

    for etiquetado, resultado in zip(conjunto, reporte.results):
        e = resultado.evidence
        if etiquetado.label == 1 or e.hybrid_score < ALERT_THRESHOLD:
            continue      # solo interesan los falsos positivos

        escenario = etiquetado.scenario
        analisis["by_scenario"][escenario] = analisis["by_scenario"].get(escenario, 0) + 1

        # Atribución: qué señal aportó los puntos que cruzaron el umbral.
        if e.rule_matches:
            causa = f"regla:{e.rule_matches[0].rule.id}"
        elif e.temporal_context:
            causa = "correlacion_temporal"
        elif e.anomaly_score >= 0.5:
            causa = "umbral_del_modelo"
        else:
            causa = "sin_atribucion_clara"
        analisis["by_cause"][causa] = analisis["by_cause"].get(causa, 0) + 1

        if len(analisis["examples"]) < 15:
            analisis["examples"].append({
                "event_id": e.event_id, "scenario": escenario, "cause": causa,
                "hybrid_score": round(e.hybrid_score, 2),
                "anomaly_score": round(e.anomaly_score, 4),
                "rules": [h.rule.id for h in e.rule_matches],
                "command_line": (etiquetado.event.command_line or "")[:120],
            })

    total_fp = sum(analisis["by_scenario"].values())
    benignos = sum(1 for x in conjunto if x.label == 0)
    analisis["total_false_positives"] = total_fp
    analisis["benign_events"] = benignos
    analisis["false_positive_rate"] = round(total_fp / benignos, 4) if benignos else "NOT EVALUABLE"
    analisis["interpretation"] = (
        "La causa indica qué señal cruzó el umbral, no un veredicto sobre quién "
        "tiene la culpa: una regla demasiado amplia y un umbral demasiado bajo "
        "producen el mismo síntoma y se distinguen mirando el escenario."
    )
    return analisis


# ================================ main ======================================
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=5,
                        help="Duración de cada escenario de carga.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--benign", type=int, default=2000)
    parser.add_argument("--only-ablation", action="store_true")
    parser.add_argument("--only-load", action="store_true")
    args = parser.parse_args()

    run_id = new_run_id()
    destino = RESULTS / f"benchmark_{run_id}"
    destino.mkdir(parents=True, exist_ok=True)
    inicio = time.perf_counter()

    print("=" * 76)
    print(f"BENCHMARK EMPRESARIAL — run_id {run_id}")
    print("=" * 76)

    conjunto = construye_conjunto(args.benign, args.seed)
    n_mal = sum(x.label for x in conjunto)
    print(f"\nConjunto con verdad-terreno: {len(conjunto):,} eventos "
          f"({n_mal} maliciosos, {len(conjunto) - n_mal} benignos)")
    escenarios = {}
    for x in conjunto:
        escenarios[x.scenario] = escenarios.get(x.scenario, 0) + 1
    for nombre, cuantos in sorted(escenarios.items()):
        print(f"   {nombre:42s} {cuantos:>5,}")

    metricas: dict[str, Any] = {}
    if not args.only_ablation:
        print(f"\n{'='*76}\nCARGA ({args.seconds}s por escenario)\n{'='*76}")
        for objetivo in ESCENARIOS:
            print(f"\n  {objetivo:,} ev/s objetivo...", flush=True)
            r = experimento_carga(conjunto, objetivo, args.seconds)
            metricas[f"{objetivo}_eps"] = r
            rec = r["resources"]
            recursos = (f"CPU {rec['cpu_percent']['mean']}% RAM {rec['rss_mb']['max']} MB"
                        if rec.get("status") == "OK" else rec.get("status"))
            srv, resp = r["service_latency_ms"], r["response_latency_ms"]
            print(f"    logrado {r['achieved_eps']:>9,.0f} ev/s"
                  f"{'  [SATURADO]' if r['saturated'] else ''} · "
                  f"servicio p50 {srv['p50']:.2f} ms p99 {srv['p99']:.2f} · "
                  f"respuesta p50 {resp['p50']:>9,.0f} ms p99 {resp['p99']:>9,.0f} · "
                  f"atraso max {r['max_backlog_s']:.1f}s · {recursos}")
            if r["errors_by_type"]:
                print(f"    errores: {r['errors_by_type']}")

    ablacion: dict[str, Any] = {}
    if not args.only_load:
        print(f"\n{'='*76}\nABLACION (7 configuraciones, mismos datos)\n{'='*76}")
        ablacion = experimento_ablacion(conjunto)
        print(f"\n  {'Configuracion':<18} {'TP':>4} {'FP':>5} {'TN':>5} {'FN':>4} "
              f"{'Precision':>10} {'Recall':>8} {'F1':>8} {'FPR':>8} {'Incid.':>8} "
              f"{'MaxScore':>9}")
        print("  " + "-" * 97)
        for nombre, r in ablacion.items():
            def f(v):
                return f"{v:.4f}" if isinstance(v, float) else str(v)[:10]
            inc = r["incident_level"]
            ciego = " *" if r["score_distribution"]["structurally_blind"] else ""
            print(f"  {nombre:<18} {r['TP']:>4} {r['FP']:>5} {r['TN']:>5} {r['FN']:>4} "
                  f"{f(r['precision']):>10} {f(r['recall']):>8} {f(r['f1']):>8} "
                  f"{f(r['fpr']):>8} {inc['detected']:>4}/{inc['total']:<3} "
                  f"{f(r['score_distribution']['max_observed']):>9}{ciego}")
        print("\n  (*) ciego por construcción: ninguna puntuación alcanza el umbral "
              f"de {ALERT_THRESHOLD}, de modo que su recall de 0 mide la capa de "
              "puntuación, no la señal.")
        print("  Recall es por evento; la columna Incid. es por escenario de ataque.")

    print(f"\n{'='*76}\nFALSOS POSITIVOS\n{'='*76}")
    fp = analiza_falsos_positivos(conjunto, ablacion)
    print(f"  {fp['total_false_positives']} FP sobre {fp['benign_events']:,} "
          f"benignos (tasa {fp['false_positive_rate']})")
    if fp["by_scenario"]:
        print(f"  por escenario: {fp['by_scenario']}")
        print(f"  por causa:     {fp['by_cause']}")

    # --- Persistencia ---
    desglose = {
        nombre: {
            "per_event_trace_ms": r["latency_by_component_ms"],
            "batch_phases_ms_per_event": r["latency_by_batch_phase_ms_per_event"],
            "attribution": r["attribution"],
        }
        for nombre, r in metricas.items()
    }
    ablacion_publica = {
        k: {kk: vv for kk, vv in v.items() if not kk.startswith("_")}
        for k, v in ablacion.items()
    }
    metadatos = {
        "run_id": run_id,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
        "seed": args.seed,
        "dataset": {
            "type": "sintetico con verdad-terreno por diseño",
            "total_events": len(conjunto),
            "malicious": n_mal, "benign": len(conjunto) - n_mal,
            "scenarios": escenarios,
        },
        "config": {
            "alert_threshold": ALERT_THRESHOLD,
            "seconds_per_scenario": args.seconds,
            "load_scenarios_eps": ESCENARIOS,
            "ablation_configs": list(CONFIGURACIONES),
            "rag_enabled": False, "llm_enabled": False,
            "note": ("RAG y LLM desactivados en el banco: producen texto, no "
                     "decisiones de detección, y su coste dominaría la latencia "
                     "sin afectar a TP/FP"),
        },
        "versions": {
            "python": sys.version.split()[0],
            "cybersentinel": "0.1.0",
        },
        "total_runtime_s": round(time.perf_counter() - inicio, 2),
    }

    for nombre, datos in (("metrics.json", metricas),
                          ("ablation.json", ablacion_publica),
                          ("latency_breakdown.json", desglose),
                          ("false_positive_analysis.json", fp),
                          ("run_metadata.json", metadatos)):
        (destino / nombre).write_text(
            json.dumps(datos, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nResultados persistidos en {destino}/")
    for archivo in sorted(destino.iterdir()):
        print(f"   {archivo.name:32s} {archivo.stat().st_size:>8,} bytes")
    print(f"\nTiempo total: {metadatos['total_runtime_s']}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
