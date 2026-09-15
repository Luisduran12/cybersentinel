"""
Auditoría CTI False Positives.
Evalúa cómo el motor procesa IOCs válidos, de baja confianza, y falsos positivos.
"""
import pytest
from datetime import datetime, timezone
from cybersentinel.schema import SecurityEvent
from cybersentinel.cti.stix_ingestor import StixIngestor
from cybersentinel.cti.enrichment import CTIEnricher
from cybersentinel.detection.hybrid import DetectionEvidence
from cybersentinel.cti.models import Indicator, ThreatActor

def test_audit_cti_false_positives():
    # 1. Configurar ingestor
    ingestor = StixIngestor()
    
    # Simular IOC de baja confianza y alta confianza
    # No usamos load_bundle para saltar la deserialización, directamente poblamos.
    ind_high = Indicator(id="indicator--1", pattern="[ipv4-addr:value = '198.51.100.99']", valid_from=datetime.now(timezone.utc), labels=["malicious"])
    ind_low = Indicator(id="indicator--2", pattern="[ipv4-addr:value = '8.8.8.8']", valid_from=datetime.now(timezone.utc), labels=["benign_but_watched"])
    
    ingestor.indicators["indicator--1"] = ind_high
    ingestor.indicators["indicator--2"] = ind_low
    
    enricher = CTIEnricher(ingestor)
    
    # 2. Casos de prueba
    
    # A. Evento benigno + IOC inexistente
    ev_a = SecurityEvent(event_id="ev_a", timestamp=datetime.now(), source="fw", category="net", action="allow", src_ip="192.168.1.10", dst_ip="10.0.0.1")
    hits_a = enricher.enrich_event(ev_a)
    dev_a = DetectionEvidence(event_id="ev_a", anomaly_score=0.1, cti_hits=hits_a)
    
    # B. Evento benigno + IOC de baja confianza ("benign_but_watched" aporta +5.0)
    ev_b = SecurityEvent(event_id="ev_b", timestamp=datetime.now(), source="fw", category="net", action="allow", src_ip="192.168.1.10", dst_ip="8.8.8.8")
    hits_b = enricher.enrich_event(ev_b)
    dev_b = DetectionEvidence(event_id="ev_b", anomaly_score=0.1, cti_hits=hits_b)
    
    # C. Evento sospechoso + IOC malicioso ("malicious" aporta +30.0)
    ev_c = SecurityEvent(event_id="ev_c", timestamp=datetime.now(), source="fw", category="net", action="allow", src_ip="192.168.1.10", dst_ip="198.51.100.99")
    hits_c = enricher.enrich_event(ev_c)
    dev_c = DetectionEvidence(event_id="ev_c", anomaly_score=0.1, cti_hits=hits_c)

    # Imprimir para la auditoria manual o aserciones
    print(f"Score A (Normal): {dev_a.hybrid_score}")
    print(f"Score B (Benign + Low Trust IOC): {dev_b.hybrid_score}")
    print(f"Score C (Normal + High Trust IOC): {dev_c.hybrid_score}")
    
    assert dev_a.hybrid_score == 0.0
    assert dev_b.hybrid_score == 5.0
    assert dev_c.hybrid_score == 30.0
