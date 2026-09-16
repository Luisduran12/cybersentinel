"""
Registro de escritura anticipada: que un 202 signifique algo.

Hasta aquí, la API respondía **202 Accepted** en cuanto el evento entraba en una
cola en memoria. Si el proceso moría —un `kill -9`, un despliegue, un fallo de
disco— todo lo encolado desaparecía sin dejar rastro: el emisor tenía un 202 en
su log y el sistema no tenía el evento. Ese es el «un fallo = pérdida total de
visibilidad» en su forma más concreta, y es peor que perder el evento a secas,
porque nadie sabe que falta.

Aquí se cierra ese hueco: **nada se acepta hasta que está escrito en disco**. El
orden es registro → cola → respuesta, nunca al revés. Si el registro falla, la
API devuelve 503 y el emisor reintenta; un rechazo honesto es mejor que una
aceptación falsa.

Diseño
------
- **Segmentos**, no un archivo único. Compactar un archivo grande obliga a
  reescribirlo entero; con segmentos basta con borrar los que están enteramente
  por debajo del punto de control.
- **Punto de control**, no borrado inmediato. El worker marca hasta dónde ha
  procesado *después* de persistir el resultado. Al arrancar se reproduce lo que
  quede por encima. Puede reprocesar un lote ya persistido —el almacén de
  incidentes usa `INSERT OR IGNORE` justo por esto—, y eso es correcto: en un
  sistema de detección, ver dos veces un evento es un problema menor; no verlo
  es el problema.
- **Escritura atómica del punto de control** (archivo temporal + `rename`). Un
  punto de control a medio escribir es peor que ninguno: apuntaría a una
  posición que no existe.

La política de `fsync` y su precio
----------------------------------
`fsync` en cada petición garantiza que ni un corte de corriente pierde nada, y
cuesta un viaje al disco por lote. Las tres políticas están expuestas porque la
elección **no es del código, es del despliegue**:

| `CYBERSENTINEL_WAL_FSYNC` | Qué garantiza | Qué cuesta |
|---|---|---|
| `always` | ni un corte de corriente pierde un evento aceptado | una bajada al plato por lote |
| `interval` *(defecto)* | se pierde como mucho `WAL_FSYNC_MS` de ventana | un `fsync` cada 200 ms |
| `never` | nada frente a un corte; sí frente a `kill -9` | nada |

Con `never` el evento sigue estando en la caché del sistema operativo, así que
sobrevive a la muerte del proceso —que es el fallo frecuente— pero no a la del
equipo. Está dicho para que nadie elija por lo que suena.

Y una trampa que solo se ve midiendo: en macOS, `fsync()` **no** vacía la caché
del disco. La primera versión del banco de pruebas daba `always` y `never`
prácticamente iguales, lo cual es imposible si `always` garantizase algo. Por
eso `always` usa `F_FULLFSYNC` en Darwin; ver `_sincronizar_de_verdad`.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger(__name__)

SEGMENT_PREFIX = "wal-"
SEGMENT_SUFFIX = ".jsonl"
CHECKPOINT_NAME = "checkpoint.json"

#: Registros por segmento. Con 5 000, un segmento pesa unos pocos MB y se borra
#: entero en cuanto el worker pasa de él.
SEGMENT_MAX_RECORDS = int(os.environ.get("CYBERSENTINEL_WAL_SEGMENT", "5000"))

FSYNC_POLICY = os.environ.get("CYBERSENTINEL_WAL_FSYNC", "interval").lower()
FSYNC_INTERVAL_S = float(os.environ.get("CYBERSENTINEL_WAL_FSYNC_MS", "200")) / 1000.0


def _sincronizar_de_verdad(fd: int) -> None:
    """
    Baja los datos al **plato**, no solo al sistema operativo.

    En macOS, `fsync()` entrega los datos al dispositivo pero **no le obliga a
    vaciar su caché de escritura**: ante un corte de corriente se pierden
    igual. La llamada que sí lo garantiza es `F_FULLFSYNC`.

    Esto se descubrió midiendo, no leyendo: el banco de pruebas daba `always` y
    `never` prácticamente iguales, lo cual es imposible si `always` estuviera
    garantizando algo. Un `fsync` que no cuesta nada es un `fsync` que no hace
    nada.

    En Linux `fsync()` sí llega al dispositivo, así que allí se usa tal cual.
    """
    if sys.platform == "darwin":
        try:
            import fcntl

            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            return
        except (AttributeError, OSError):
            pass  # sin F_FULLFSYNC, mejor un fsync normal que nada
    os.fsync(fd)


@dataclass(frozen=True)
class WalEntry:
    """Un registro tal y como llegó, con su número de secuencia."""

    seq: int
    record: dict[str, Any]
    source: str

    def to_line(self) -> str:
        return json.dumps({"seq": self.seq, "source": self.source,
                           "record": self.record}, ensure_ascii=False) + "\n"


class WalLocked(Exception):
    """Otro proceso ya es dueño de este registro."""


class WriteAheadLog:
    """
    Registro en disco de todo lo aceptado y aún no procesado.

    **Un solo escritor por directorio, y se impone con un candado.** Dos
    procesos sobre el mismo registro calcularían la misma secuencia siguiente y
    abrirían el mismo segmento: escribirían eventos distintos con el mismo
    número, y al recuperar los dos reproducirían las mismas entradas. El
    resultado no sería una pérdida —sería algo peor: duplicados silenciosos y
    un punto de control que da por procesado lo que no lo está.

    Por eso el segundo proceso **no arranca** en lugar de compartir. Escalar la
    ingestión a varias réplicas no se hace compartiendo este directorio: se hace
    dándole a cada réplica el suyo, o poniendo delante una cola compartida. Está
    dicho aquí y en la documentación porque es la frontera real de este diseño.
    """

    def __init__(self, directory: str | Path,
                 fsync_policy: str = FSYNC_POLICY,
                 fsync_interval_s: float = FSYNC_INTERVAL_S,
                 segment_max_records: int = SEGMENT_MAX_RECORDS) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        if fsync_policy not in {"always", "interval", "never"}:
            raise ValueError(
                f"política de fsync desconocida: {fsync_policy!r}; "
                "válidas: always, interval, never")
        self.fsync_policy = fsync_policy
        self.fsync_interval_s = fsync_interval_s
        self.segment_max_records = max(1, segment_max_records)

        self._lock = threading.Lock()
        self._fh = None
        self._segment_records = 0
        self._last_fsync = time.monotonic()
        self.appended = 0
        self.replayed = 0
        self.fsyncs = 0

        self._lock_fh = None
        self._tomar_propiedad()
        self._seq = self._max_seq_en_disco()
        self._checkpoint = self._leer_checkpoint()
        self._abrir_segmento()

    # --- Propiedad exclusiva ---------------------------------------------
    def _tomar_propiedad(self) -> None:
        """
        Toma el candado del directorio, o falla diciendo por qué.

        Se mantiene abierto mientras viva el objeto: el sistema operativo lo
        libera solo si el proceso muere, que es justo lo que hace falta para que
        el siguiente arranque pueda recuperar sin intervención manual.
        """
        try:
            import fcntl
        except ImportError:  # pragma: no cover - solo fuera de POSIX
            logger.warning("Sin `fcntl`: no se puede impedir que dos procesos "
                           "compartan el registro. Asegura un solo escritor.")
            return

        ruta = self.dir / ".owner.lock"
        self._lock_fh = open(ruta, "a+")
        try:
            fcntl.flock(self._lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._lock_fh.close()
            self._lock_fh = None
            raise WalLocked(
                f"otro proceso ya usa el registro de {self.dir}. Un registro "
                "admite un solo escritor: da a cada réplica su propio "
                "directorio (CYBERSENTINEL_WAL) o pon una cola compartida "
                "delante."
            ) from exc
        self._lock_fh.write(f"{os.getpid()}\n")
        self._lock_fh.flush()

    def _soltar_propiedad(self) -> None:
        if self._lock_fh is None:
            return
        try:
            import fcntl

            fcntl.flock(self._lock_fh.fileno(), fcntl.LOCK_UN)
        except (ImportError, OSError):  # pragma: no cover
            pass
        finally:
            self._lock_fh.close()
            self._lock_fh = None

    # --- Segmentos --------------------------------------------------------
    def _segmentos(self) -> list[Path]:
        return sorted(self.dir.glob(f"{SEGMENT_PREFIX}*{SEGMENT_SUFFIX}"))

    def _max_seq_en_disco(self) -> int:
        """
        Mayor secuencia escrita, para no reutilizar números tras un reinicio.

        Se lee el último segmento entero en vez de solo su última línea: si el
        proceso murió a mitad de una escritura, la última línea puede estar
        truncada y `json.loads` fallaría.
        """
        segmentos = self._segmentos()
        if not segmentos:
            return 0
        mayor = 0
        for linea in segmentos[-1].read_text(encoding="utf-8").splitlines():
            if not linea.strip():
                continue
            try:
                mayor = max(mayor, int(json.loads(linea)["seq"]))
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                # Línea truncada por una muerte a mitad de escritura. Se ignora
                # aquí y se ignora también al reproducir: un registro a medias
                # no es un evento, y aceptarlo inventaría datos.
                continue
        return mayor

    def _abrir_segmento(self) -> None:
        nombre = self.dir / f"{SEGMENT_PREFIX}{self._seq + 1:012d}{SEGMENT_SUFFIX}"
        self._fh = open(nombre, "a", encoding="utf-8")
        self._segment_records = 0

    def _rodar(self) -> None:
        """
        Cierra el segmento actual y abre el siguiente.

        Se llama **dentro** del bucle de escritura, no al terminar la petición.
        Comprobándolo solo al final, un lote de 10 000 eventos —el máximo que
        acepta la API— cabía entero en un segmento de 5 000 y el tope no servía
        de nada: el segmento crecía sin límite y la compactación no podía
        borrarlo hasta procesarlo entero.
        """
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._fh.close()
        self._abrir_segmento()

    # --- Escritura --------------------------------------------------------
    def append(self, entradas: list[tuple[dict[str, Any], str]]) -> list[int]:
        """
        Escribe los registros y devuelve sus secuencias.

        Lanza si no puede escribir. Quien llama **debe** propagar el fallo al
        emisor: aceptar lo que no se pudo registrar es la aceptación falsa que
        este módulo existe para evitar.
        """
        if not entradas:
            return []
        with self._lock:
            seqs = []
            for registro, source in entradas:
                self._seq += 1
                self._fh.write(WalEntry(self._seq, registro, source).to_line())
                seqs.append(self._seq)
                self._segment_records += 1
                if self._segment_records >= self.segment_max_records:
                    self._rodar()
            self._fh.flush()
            self._quizas_fsync()
            self.appended += len(seqs)
            return seqs

    def _quizas_fsync(self) -> None:
        if self.fsync_policy == "never":
            return
        ahora = time.monotonic()
        if self.fsync_policy == "always":
            # `always` promete sobrevivir a un corte de corriente, así que tiene
            # que bajar al plato. Con `os.fsync` en macOS la promesa sería falsa
            # y además barata, que es la peor combinación posible.
            _sincronizar_de_verdad(self._fh.fileno())
            self._last_fsync = ahora
            self.fsyncs += 1
        elif (ahora - self._last_fsync) >= self.fsync_interval_s:
            os.fsync(self._fh.fileno())
            self._last_fsync = ahora
            self.fsyncs += 1

    def flush(self) -> None:
        """Fuerza la bajada a disco. La llama el apagado ordenado."""
        with self._lock:
            if self._fh and not self._fh.closed:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self.fsyncs += 1

    def close(self) -> None:
        with self._lock:
            if self._fh and not self._fh.closed:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._fh.close()

    def release(self) -> None:
        """Cierra y suelta la propiedad del directorio."""
        self.close()
        self._soltar_propiedad()

    @property
    def is_open(self) -> bool:
        return bool(self._fh and not self._fh.closed)

    def reopen(self) -> None:
        """
        Vuelve a abrir el segmento tras un cierre ordenado.

        Hace falta porque arrancar y parar el servicio en el mismo proceso es
        legítimo —pruebas, uso empotrado, un reinicio en caliente—, y sin esto
        el segundo arranque escribía sobre un descriptor cerrado: la excepción
        se traducía en «registro no disponible» y la API rechazaba todo con 503.
        Lo encontró la suite, no un despliegue, que es donde conviene.
        """
        with self._lock:
            if self._lock_fh is None:
                self._tomar_propiedad()
            if self._fh is None or self._fh.closed:
                self._seq = max(self._seq, self._max_seq_en_disco())
                self._abrir_segmento()

    # --- Punto de control -------------------------------------------------
    def _leer_checkpoint(self) -> int:
        ruta = self.dir / CHECKPOINT_NAME
        if not ruta.exists():
            return 0
        try:
            return int(json.loads(ruta.read_text(encoding="utf-8"))["seq"])
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            logger.error("Punto de control ilegible en %s: se reproducirá todo "
                         "el registro. Es preferible reprocesar a perder.", ruta)
            return 0

    @property
    def checkpoint_seq(self) -> int:
        return self._checkpoint

    def checkpoint(self, seq: int) -> None:
        """
        Marca hasta dónde se ha procesado y borra lo que ya sobra.

        Se escribe con archivo temporal y `rename` —atómico en el mismo sistema
        de archivos— porque un punto de control a medio escribir apuntaría a una
        posición inexistente, que es peor que no tener ninguno.
        """
        with self._lock:
            if seq <= self._checkpoint:
                return
            self._checkpoint = seq
            destino = self.dir / CHECKPOINT_NAME
            temporal = destino.with_suffix(".tmp")
            temporal.write_text(json.dumps({"seq": seq}), encoding="utf-8")
            temporal.replace(destino)
            self._compactar()

    def _compactar(self) -> None:
        """Borra los segmentos enteramente por debajo del punto de control."""
        abierto = Path(self._fh.name) if self._fh else None
        for segmento in self._segmentos():
            if segmento == abierto:
                continue
            mayor = 0
            try:
                for linea in segmento.read_text(encoding="utf-8").splitlines():
                    if linea.strip():
                        mayor = max(mayor, int(json.loads(linea)["seq"]))
            except (json.JSONDecodeError, KeyError, ValueError, TypeError, OSError):
                continue  # ante la duda, no se borra
            if mayor and mayor <= self._checkpoint:
                segmento.unlink(missing_ok=True)

    # --- Recuperación -----------------------------------------------------
    def replay(self) -> Iterator[WalEntry]:
        """
        Devuelve lo aceptado y no procesado, en orden.

        Una línea corrupta —la que quedó a medias cuando murió el proceso— se
        salta con un registro de error en vez de abortar la recuperación: perder
        un evento por una escritura truncada es malo; perder los diez mil que
        vienen detrás porque uno estaba roto es mucho peor.
        """
        for segmento in self._segmentos():
            try:
                lineas = segmento.read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                logger.error("No se pudo leer el segmento %s: %s", segmento, exc)
                continue
            for numero, linea in enumerate(lineas, 1):
                if not linea.strip():
                    continue
                try:
                    d = json.loads(linea)
                    entrada = WalEntry(int(d["seq"]), d["record"], d.get("source", "desconocida"))
                except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                    logger.error("Línea %d de %s ilegible (¿escritura truncada?): "
                                 "se salta", numero, segmento.name)
                    continue
                if entrada.seq > self._checkpoint:
                    self.replayed += 1
                    yield entrada

    def pending(self) -> int:
        """Cuántos registros quedan por procesar según el disco."""
        return max(0, self._seq - self._checkpoint)

    # --- Estado -----------------------------------------------------------
    def stats(self) -> dict[str, Any]:
        return {
            "dir": str(self.dir),
            "last_seq": self._seq,
            "checkpoint_seq": self._checkpoint,
            "pending": self.pending(),
            "segments": len(self._segmentos()),
            "appended": self.appended,
            "replayed": self.replayed,
            "fsyncs": self.fsyncs,
            "fsync_policy": self.fsync_policy,
            "durability_note": {
                "always": "un evento aceptado sobrevive a un corte de corriente",
                "interval": (f"se pierde como mucho una ventana de "
                             f"{self.fsync_interval_s * 1000:.0f} ms ante un corte "
                             "de corriente; nada ante la muerte del proceso"),
                "never": ("sobrevive a la muerte del proceso, no a la del equipo"),
            }[self.fsync_policy],
        }
