"""
Capa de streaming (Fase 1 de la hoja de ruta de producción).

Desacopla la ingesta de la detección con un bus de mensajes real: NATS
JetStream. Ver `docs/PRODUCTION-ARCHITECTURE.md` para la justificación de por
qué NATS y no Kafka, y por qué un normalizador propio en vez de
Substation/Tenzir.

Este paquete es opcional: importar `cybersentinel.streaming.bus` no requiere
tener `nats-py` instalado; solo falla al intentar *conectar* de verdad. Así la
suite principal de pytest no depende de una dependencia adicional ni de un
servidor NATS levantado.
"""
