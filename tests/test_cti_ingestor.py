"""
Tests para el ingestor STIX 2.1 (Fase 5).
"""
import pytest
from pathlib import Path
from cybersentinel.cti.stix_ingestor import StixIngestor

def test_stix_ingestor_loads_minimal_bundle(tmp_path: Path):
    bundle_data = {
        "type": "bundle",
        "id": "bundle--33b000be-f67f-4422-bc57-01053ea6f0e4",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                "created": "2026-09-14T00:00:00.000Z",
                "modified": "2026-09-14T00:00:00.000Z",
                "pattern": "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
                "pattern_type": "stix",
                "valid_from": "2026-09-14T00:00:00.000Z",
                "name": "Malicious Hash",
                "labels": ["malicious-activity"]
            },
            {
                "type": "threat-actor",
                "id": "threat-actor--56f3f0bc-3d60-4e56-9a25-cb1a021b4a9f",
                "created": "2026-09-14T00:00:00.000Z",
                "modified": "2026-09-14T00:00:00.000Z",
                "name": "APT28",
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
    
    assert len(ingestor.indicators) == 1
    assert len(ingestor.actors) == 1
    
    # Comprobar relationships
    related_actors = ingestor.get_related_actors("indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f")
    assert len(related_actors) == 1
    assert related_actors[0].name == "APT28"
