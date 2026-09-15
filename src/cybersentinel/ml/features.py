"""
Feature Extraction Defensivo sin Leakage.

Convierte SecurityEvent en vectores numéricos interpretables.
Mantiene una separación estricta: fit() aprende diccionarios de rareza
solo sobre el conjunto de TRAIN, mientras que extract_batch() calcula
propiedades sin alterar el modelo de frecuencias aprendido, y mantiene
estado temporal localmente.
"""
from __future__ import annotations
from collections import Counter
import numpy as np
from datetime import datetime, timedelta

from ..schema import SecurityEvent

# Etiquetas legibles para explicabilidad
FEATURE_LABELS_ES = {
    # Network
    "bytes_out_log": "volumen de datos saliente",
    "bytes_in_log": "volumen de datos entrante",
    "bytes_ratio": "asimetria de trafico",
    "is_rare_port": "puerto poco comun",
    "port_rarity": "rareza del puerto (linea base)",
    # Process
    "cmd_len": "longitud del comando",
    "cmd_special_chars": "caracteres especiales en comando",
    "cmd_entropy": "entropia del comando (ofuscacion)",
    "user_rarity": "rareza del usuario",
    "src_ip_rarity": "rareza de IP de origen",
    "has_hash": "presencia de hash",
    "has_parent_cmd": "presencia de proceso padre",
    "is_process": "evento de proceso",
    "is_network": "evento de red",
    # Temporal
    "hour_sin": "ciclo horario",
    "hour_cos": "ciclo horario",
    "is_night": "actividad nocturna",
    "events_in_window": "rafaga de eventos (ventana)",
    "time_since_prev_log": "tiempo desde evento previo (log)",
}

class FeatureExtractor:
    FEATURE_NAMES = list(FEATURE_LABELS_ES.keys())
    COMMON_PORTS = {80, 443, 22, 53, 25, 3389, 445, 139, 21, 23, 3306, 8080}

    def __init__(self, window_minutes: int = 5):
        self.window_minutes = window_minutes
        self._users: Counter[str] = Counter()
        self._ips: Counter[str] = Counter()
        self._ports: Counter[str] = Counter()
        self._total = 0
        self._is_fitted = False

    def fit(self, events: list[SecurityEvent]) -> "FeatureExtractor":
        """Entrena la línea base estrictamente con el set de TRAIN."""
        self._users = Counter(e.user or "" for e in events)
        self._ips = Counter(e.src_ip or "" for e in events)
        self._ports = Counter(str(e.dst_port or "") for e in events)
        self._total = len(events)
        self._is_fitted = True
        return self

    def _rarity(self, counter: Counter[str], value: str) -> float:
        """Rareza en [0, 1]: 0.0=frecuente, 1.0=nunca visto."""
        if self._total == 0:
            return 0.0
        return 1.0 - (counter.get(value, 0) / self._total)

    def extract_batch(self, events: list[SecurityEvent]) -> np.ndarray:
        """
        Extrae features para un lote. 
        Calcula estado temporal de forma local al lote simulando la recepción temporal real.
        """
        if not events:
            return np.empty((0, len(self.FEATURE_NAMES)))
        
        # Mantenemos el orden original del batch (no forzamos sort a menos que sea necesario)
        # para simular una secuencia real. En producción vienen ordenados.
        
        host_windows: dict[str, list[datetime]] = {}
        host_last_event: dict[str, datetime] = {}
        
        matrix = []
        for event in events:
            host = event.host or event.src_ip or "unknown"
            ts = event.timestamp
            
            window = host_windows.setdefault(host, [])
            cutoff = ts - timedelta(minutes=self.window_minutes)
            window = [t for t in window if t > cutoff]
            events_in_window = len(window)
            window.append(ts)
            host_windows[host] = window
            
            last_ts = host_last_event.get(host)
            if last_ts:
                # Los eventos pueden llegar desordenados (fuentes distintas, relojes
                # distintos). Un delta negativo hace que log1p devuelva NaN, y un
                # NaN se propaga silenciosamente por todo el vector de features
                # hasta envenenar el modelo. Se acota en 0: "sin separación
                # temporal medible respecto al anterior".
                delta_sec = max(0.0, (ts - last_ts).total_seconds())
            else:
                delta_sec = self.window_minutes * 60
            host_last_event[host] = ts
            
            cmd = event.command_line or ""
            hour = ts.hour
            angle = 2.0 * np.pi * hour / 24.0
            port = event.dst_port
            
            vec = [
                # Network
                float(np.log1p(event.bytes_out or 0)),
                float(np.log1p(event.bytes_in or 0)),
                _ratio(event.bytes_out, event.bytes_in),
                1.0 if (port and port not in self.COMMON_PORTS) else 0.0,
                self._rarity(self._ports, str(port or "")),
                # Process
                float(len(cmd)),
                float(sum(1 for ch in cmd if not ch.isalnum() and not ch.isspace())),
                _shannon_entropy(cmd),
                self._rarity(self._users, event.user or ""),
                self._rarity(self._ips, event.src_ip or ""),
                1.0 if "hashes" in event.properties else 0.0,
                1.0 if "parent_command_line" in event.properties else 0.0,
                1.0 if event.category == "process" else 0.0,
                1.0 if event.category == "network" else 0.0,
                # Temporal
                float(np.sin(angle)),
                float(np.cos(angle)),
                1.0 if (hour < 6 or hour > 22) else 0.0,
                float(np.log1p(events_in_window)),
                float(np.log1p(delta_sec)),
            ]
            matrix.append(vec)
            
        return np.array(matrix, dtype=float)

def _ratio(out_bytes: int | None, in_bytes: int | None) -> float:
    total = (out_bytes or 0) + (in_bytes or 0)
    return (out_bytes or 0) / total if total else 0.5

def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: Counter[str] = Counter(text)
    n = len(text)
    return float(-sum((c / n) * np.log2(c / n) for c in counts.values()))
