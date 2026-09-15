"""
Tests para validar el Ciclo de Vida del CTI (Fase 5.2).
Asegura que los IOC expirados o revocados no generen hits.
"""
import pytest
from datetime import datetime, timezone, timedelta
from cybersentinel.schema import SecurityEvent
from cybersentinel.cti.stix_ingestor import StixIngestor
from cybersentinel.cti.enrichment import CTIEnricher
from cybersentinel.cti.models import Indicator

def test_cti_ignores_revoked_and_expired():
    ingestor = StixIngestor()
    now = datetime.now(timezone.utc)
    
    # 1. IOC Válido
    ind_valid = Indicator(
        id="ind--1", 
        pattern="[ipv4-addr:value = '1.1.1.1']", 
        valid_from=now - timedelta(days=1),
        valid_until=now + timedelta(days=1)
    )
    
    # 2. IOC Revocado
    ind_revoked = Indicator(
        id="ind--2", 
        pattern="[ipv4-addr:value = '2.2.2.2']", 
        valid_from=now - timedelta(days=1),
        revoked=True
    )
    
    # 3. IOC Expirado
    ind_expired = Indicator(
        id="ind--3", 
        pattern="[ipv4-addr:value = '3.3.3.3']", 
        valid_from=now - timedelta(days=10),
        valid_until=now - timedelta(days=1)
    )
    
    # 4. Multi-observable OR
    ind_multi = Indicator(
        id="ind--4",
        pattern="[ipv4-addr:value = '4.4.4.4' OR ipv4-addr:value = '5.5.5.5']",
        valid_from=now
    )
    
    ingestor.indicators = {
        "ind--1": ind_valid,
        "ind--2": ind_revoked,
        "ind--3": ind_expired,
        "ind--4": ind_multi
    }
    
    enricher = CTIEnricher(ingestor)
    
    # Evaluar Válido
    ev1 = SecurityEvent(event_id="e1", timestamp=now, source="fw", category="net", action="allow", src_ip="1.1.1.1")
    assert len(enricher.enrich_event(ev1)) == 1
    
    # Evaluar Revocado
    ev2 = SecurityEvent(event_id="e2", timestamp=now, source="fw", category="net", action="allow", src_ip="2.2.2.2")
    assert len(enricher.enrich_event(ev2)) == 0
    
    # Evaluar Expirado
    ev3 = SecurityEvent(event_id="e3", timestamp=now, source="fw", category="net", action="allow", src_ip="3.3.3.3")
    assert len(enricher.enrich_event(ev3)) == 0
    
    # Evaluar Multi-Observable OR (A)
    ev4 = SecurityEvent(event_id="e4", timestamp=now, source="fw", category="net", action="allow", src_ip="4.4.4.4")
    assert len(enricher.enrich_event(ev4)) == 1
    
    # Evaluar Multi-Observable OR (B)
    ev5 = SecurityEvent(event_id="e5", timestamp=now, source="fw", category="net", action="allow", src_ip="5.5.5.5")
    assert len(enricher.enrich_event(ev5)) == 1
