"""
Tests para el Motor de Enriquecimiento CTI (Fase 5).
"""
import pytest
from datetime import datetime, timezone
from pathlib import Path

from cybersentinel.schema import SecurityEvent
from cybersentinel.cti.stix_ingestor import StixIngestor
from cybersentinel.cti.enrichment import CTIEnricher

def test_cti_enrichment_matches_observables():
    # 1. Configurar StixIngestor
    bundle_data = {
        "type": "bundle",
        "id": "bundle--33b000be-f67f-4422-bc57-01053ea6f0e4",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                "created": "2026-09-14T00:00:00.000Z",
                "modified": "2026-09-14T00:00:00.000Z",
                "pattern": "[ipv4-addr:value = '198.51.100.99']",
                "pattern_type": "stix",
                "valid_from": "2026-09-14T00:00:00.000Z",
                "name": "Malicious C2 IP",
                "labels": ["c2"]
            },
            {
                "type": "threat-actor",
                "id": "threat-actor--56f3f0bc-3d60-4e56-9a25-cb1a021b4a9f",
                "created": "2026-09-14T00:00:00.000Z",
                "modified": "2026-09-14T00:00:00.000Z",
                "name": "Lazarus Group",
                "labels": ["nation-state"]
            },
            {
                "type": "relationship",
                "id": "relationship--c4d62b92-49cc-4395-bf38-0bece2f0d9c4",
                "created": "2026-09-14T00:00:00.000Z",
                "modified": "2026-09-14T00:00:00.000Z",
                "relationship_type": "indicates",
                "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                "target_ref": "threat-actor--56f3f0bc-3d60-4e56-9a25-cb1a021b4a9f"
            }
        ]
    }
    
    ingestor = StixIngestor()
    ingestor.load_bundle(bundle_data)
    
    # 2. Instanciar Enricher
    enricher = CTIEnricher(ingestor)
    
    # 3. Crear evento malicioso
    event = SecurityEvent(
        event_id="ev1",
        timestamp=datetime.now(timezone.utc),
        source="firewall",
        category="network",
        action="connection",
        src_ip="192.168.1.10",
        dst_ip="198.51.100.99"
    )
    
    # 4. Enriquecer
    hits = enricher.enrich_event(event)
    
    assert len(hits) == 1
    hit = hits[0]
    assert hit.observable_value == "198.51.100.99"
    assert hit.indicator.name == "Malicious C2 IP"
    assert len(hit.related_actors) == 1
    assert hit.related_actors[0].name == "Lazarus Group"

def test_cti_enrichment_no_match():
    ingestor = StixIngestor()
    enricher = CTIEnricher(ingestor)
    
    event = SecurityEvent(
        event_id="ev2",
        timestamp=datetime.now(timezone.utc),
        source="firewall",
        category="network",
        action="connection",
        src_ip="192.168.1.10",
        dst_ip="8.8.8.8"
    )
    
    hits = enricher.enrich_event(event)
    assert len(hits) == 0
