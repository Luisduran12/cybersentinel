"""
Generador de campañas de ataque sintéticas ETIQUETADAS.

Produce secuencias de tácticas MITRE ATT&CK con las que entrenar y evaluar el
modelo de predicción de kill-chain (`correlation/sequence_model.py`).

LÍMITE QUE HAY QUE DECLARAR EN LA MEMORIA
-----------------------------------------
Estas secuencias las genera este archivo. Un modelo entrenado con ellas aprende
**la distribución que yo escribí aquí**, no cómo se comportan los atacantes
reales. Los números que salen de esta evaluación miden si el modelo es capaz de
aprender una estructura de campaña a partir de ejemplos, no su eficacia frente a
adversarios reales. Para eso hacen falta secuencias observadas (Fase 4: EVTX
mapeados a ATT&CK, Security-Datasets, telemetría propia de Atomic Red Team).

La comparación con la línea base canónica sí es justa: ninguno de los dos modelos
conoce el generador, y ambos se evalúan sobre las mismas secuencias retenidas.

Los perfiles reproducen patrones descritos públicamente en informes de respuesta
a incidentes. No contienen indicadores, comandos ni artefactos reales: son
secuencias de nombres de tácticas.

Los nombres son los de la matriz ATT&CK **vigente**: `defense-evasion` ya no
existe —MITRE la dividió en `stealth` y `defense-impairment`—. Los corpus y
modelos anteriores siguen funcionando porque el modelo de secuencia traduce los
nombres retirados, pero lo que se genera aquí usa los actuales.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CampaignProfile:
    """
    Patrón de campaña: la secuencia de tácticas que sigue un tipo de ataque.

    `skip_probability` modela que un atacante no siempre deja rastro de todas las
    fases (o que el sensor no las ve), y `truncate_probability` que la campaña se
    detenga antes de completarse (contención, abandono, detección temprana).
    """
    name: str
    description: str
    tactics: list[str]
    weight: float = 1.0
    skip_probability: float = 0.15
    truncate_probability: float = 0.25
    swap_probability: float = 0.05
    notes: list[str] = field(default_factory=list)


PROFILES: list[CampaignProfile] = [
    CampaignProfile(
        name="ransomware",
        description="Cifrado masivo tras comprometer y moverse por la red.",
        tactics=[
            "initial-access", "execution", "persistence", "privilege-escalation",
            "stealth", "defense-impairment", "discovery", "lateral-movement",
            "collection", "impact",
        ],
        weight=1.4,
        truncate_probability=0.15,   # rara vez se detiene: llega hasta el cifrado
        notes=[
            "La fase de impacto es el objetivo, no un efecto colateral.",
            "Incluye degradacion de defensas: el borrado de copias de seguridad.",
        ],
    ),
    CampaignProfile(
        name="robo-de-credenciales",
        description="Acceso con cuentas validas, volcado de credenciales y fuga de datos.",
        tactics=[
            "reconnaissance", "initial-access", "credential-access",
            "discovery", "collection", "exfiltration",
        ],
        weight=1.2,
    ),
    CampaignProfile(
        name="apt-lenta",
        description="Intrusion prolongada, sigilosa y con canal de mando persistente.",
        tactics=[
            "reconnaissance", "resource-development", "initial-access", "execution",
            "persistence", "stealth", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control", "exfiltration",
        ],
        weight=0.8,
        skip_probability=0.25,       # mucho sigilo: deja menos rastro por fase
        truncate_probability=0.35,
        notes=["Es la campana que mas fases omite: el sigilo reduce la telemetria."],
    ),
    CampaignProfile(
        name="insider",
        description="Usuario legitimo que abusa de su acceso; no hay acceso inicial.",
        tactics=["discovery", "collection", "exfiltration"],
        weight=0.7,
        skip_probability=0.10,
        notes=["Sin acceso inicial ni ejecucion: empieza dentro."],
    ),
    CampaignProfile(
        name="explotacion-web",
        description="Explotacion de una aplicacion expuesta y canal de mando saliente.",
        tactics=[
            "reconnaissance", "initial-access", "execution",
            "persistence", "command-and-control", "exfiltration",
        ],
        weight=1.0,
    ),
    CampaignProfile(
        name="malware-comun",
        description="Infeccion oportunista de bajo perfil, sin movimiento lateral.",
        tactics=["initial-access", "execution", "command-and-control", "impact"],
        weight=0.9,
        truncate_probability=0.40,
        notes=["Suele detenerse pronto: es ruidosa y se contiene rapido."],
    ),
]

PROFILES_BY_NAME = {p.name: p for p in PROFILES}


def _realize(profile: CampaignProfile, rng: random.Random) -> list[str]:
    """Instancia una campaña concreta a partir de su perfil, con variación."""
    sequence = [t for t in profile.tactics if rng.random() > profile.skip_probability]

    # El atacante vuelve sobre una fase anterior (p. ej. mas descubrimiento tras
    # moverse). Se modela como un intercambio local, no como un salto arbitrario.
    for i in range(len(sequence) - 1):
        if rng.random() < profile.swap_probability:
            sequence[i], sequence[i + 1] = sequence[i + 1], sequence[i]

    # La campaña se corta antes de completarse.
    if len(sequence) > 2 and rng.random() < profile.truncate_probability:
        sequence = sequence[: rng.randint(2, len(sequence) - 1)]

    # Se deduplica conservando el orden, igual que hace Incident.tactics: el
    # corpus de entrenamiento debe tener la misma forma que lo que vera en
    # produccion.
    seen: set[str] = set()
    return [t for t in sequence if not (t in seen or seen.add(t))]


def generate_sequences(
    n: int = 400, seed: int = 7, min_length: int = 2
) -> tuple[list[list[str]], list[str]]:
    """
    Genera `n` campañas.

    Devuelve (secuencias de tácticas, nombre del perfil de cada una). El perfil
    no se usa para entrenar —el modelo solo ve tácticas— pero permite analizar
    los errores por tipo de campaña.
    """
    rng = random.Random(seed)
    weights = [p.weight for p in PROFILES]
    sequences: list[list[str]] = []
    labels: list[str] = []
    guard = 0
    while len(sequences) < n and guard < n * 50:
        guard += 1
        profile = rng.choices(PROFILES, weights=weights, k=1)[0]
        sequence = _realize(profile, rng)
        if len(sequence) >= min_length:
            sequences.append(sequence)
            labels.append(profile.name)
    return sequences, labels


def train_test_split(
    sequences: list[list[str]],
    labels: list[str],
    test_ratio: float = 0.3,
    seed: int = 7,
) -> tuple[list[list[str]], list[str], list[list[str]], list[str]]:
    """
    Partición reproducible en entrenamiento y evaluación.

    Medir sobre las mismas secuencias con las que se entrenó no mide nada: la
    cadena de Markov reproduciría sus propios conteos.
    """
    indices = list(range(len(sequences)))
    random.Random(seed).shuffle(indices)
    cut = int(len(indices) * (1 - test_ratio))
    train, test = indices[:cut], indices[cut:]
    return (
        [sequences[i] for i in train], [labels[i] for i in train],
        [sequences[i] for i in test], [labels[i] for i in test],
    )


def main(path: str | Path | None = None, n: int = 400, seed: int = 7) -> Path:
    """Escribe el corpus en JSONL para inspeccionarlo o versionarlo."""
    path = Path(path or Path(__file__).parent / "campaigns.jsonl")
    sequences, labels = generate_sequences(n=n, seed=seed)
    with open(path, "w", encoding="utf-8") as fh:
        for sequence, label in zip(sequences, labels):
            fh.write(json.dumps({"profile": label, "tactics": sequence},
                                ensure_ascii=False) + "\n")
    return path


if __name__ == "__main__":
    out = main()
    seqs, labs = generate_sequences()
    print(f"Generado: {out}")
    print(f"{len(seqs)} campanas, longitud media {sum(map(len, seqs)) / len(seqs):.1f} tacticas")
    for profile in PROFILES:
        count = labs.count(profile.name)
        print(f"  {profile.name:22s} {count:4d} campanas  ({profile.description})")
