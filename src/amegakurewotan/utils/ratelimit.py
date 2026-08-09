# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.utils.ratelimit
Contexto: CIVIL — Consolidación AmegakureWotan (OPSEC L3, control de tasa de salida)

Rate limiter DURO para TODA petición HTTP/S de la plataforma.

Doctrina AmegakureDojo (regla operativa de Lugh): máximo 13 requests/segundo,
SIN ráfagas. Saturar la red del objetivo es inaceptable — una ráfaga tumbó la
conexión en el pasado. Por eso este limitador combina DOS garantías:

  1. Ventana deslizante de 1 s: nunca más de `rate` peticiones en cualquier
     segundo móvil (límite de caudal).
  2. Espaciado mínimo forzado (1/rate s entre acquire() consecutivos): las
     peticiones salen equiespaciadas, jamás en ráfaga (límite de forma).

Es thread-safe (varios agentes concurrentes comparten el mismo grifo global) y
usa reloj monótono, inmune a saltos del reloj de pared.

Uso:
    from amegakurewotan.utils.ratelimit import get_rate_limiter
    get_rate_limiter().acquire()   # bloquea lo justo para respetar la tasa
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Deque, Optional

logger = logging.getLogger("amegakurewotan.utils.ratelimit")


class RateLimiter:
    """Token-bucket de ventana deslizante con espaciado mínimo anti-ráfaga.

    Args:
        rate: peticiones por segundo permitidas (caudal máximo). Debe ser > 0.
        no_burst: si True (por defecto), fuerza además un intervalo mínimo de
            1/rate segundos entre peticiones consecutivas, garantizando salida
            equiespaciada (sin ráfagas).
        clock: función de reloj monótono inyectable (para tests deterministas).
        sleep: función de espera inyectable (para tests deterministas).
    """

    def __init__(
        self,
        rate: float,
        no_burst: bool = True,
        clock=time.monotonic,
        sleep=time.sleep,
    ) -> None:
        if rate <= 0:
            raise ValueError(f"rate debe ser > 0, recibido: {rate}")
        self.rate = float(rate)
        self.no_burst = no_burst
        self._min_interval = 1.0 / self.rate
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        # Marcas de tiempo (monótonas) de las peticiones dentro de la ventana de 1 s.
        self._window: Deque[float] = deque()
        self._last_ts: Optional[float] = None

    def acquire(self) -> float:
        """Bloquea lo necesario para respetar caudal y espaciado. Devuelve la
        cantidad de segundos que durmió (0.0 si no hubo espera). Es la ÚNICA
        forma legítima de emitir una petición de red saliente en la plataforma.
        """
        slept_total = 0.0
        with self._lock:
            while True:
                now = self._clock()
                # 1) Purga marcas fuera de la ventana deslizante de 1 s.
                cutoff = now - 1.0
                while self._window and self._window[0] <= cutoff:
                    self._window.popleft()

                # 2) Espera por espaciado mínimo (anti-ráfaga).
                wait_spacing = 0.0
                if self.no_burst and self._last_ts is not None:
                    elapsed = now - self._last_ts
                    if elapsed < self._min_interval:
                        wait_spacing = self._min_interval - elapsed

                # 3) Espera por caudal (ventana llena): hasta que expire la marca
                #    más antigua.
                wait_window = 0.0
                if len(self._window) >= self.rate:
                    wait_window = self._window[0] + 1.0 - now

                wait = max(wait_spacing, wait_window)
                # Tolerancia FP: un wait por debajo de epsilon es ruido de punto
                # flotante (p. ej. min_interval - elapsed ≈ 1e-17), que sleep() no
                # puede sumar al reloj y provocaría un bucle infinito. Se concede.
                if wait <= 1e-9:
                    # Permiso concedido: registra y sale.
                    ts = self._clock()
                    self._window.append(ts)
                    self._last_ts = ts
                    return slept_total

                self._sleep(wait)
                slept_total += wait

    def __enter__(self) -> "RateLimiter":
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        return None


# ── Singleton global (el grifo compartido por toda la plataforma) ──────────────
_limiter: Optional[RateLimiter] = None
_limiter_lock = threading.Lock()
_limiter_rate: Optional[float] = None


def get_rate_limiter() -> RateLimiter:
    """Devuelve el limitador global, construido desde config en el primer uso.

    Relee `config.opsec.max_requests_per_second` en tiempo de llamada; si la tasa
    configurada cambió (p. ej. override de test/despliegue tras reset de config),
    reconstruye el limitador para honrar el nuevo valor.
    """
    global _limiter, _limiter_rate
    from amegakurewotan.config import get_config

    rate = float(get_config().opsec.max_requests_per_second)
    with _limiter_lock:
        if _limiter is None or _limiter_rate != rate:
            _limiter = RateLimiter(rate=rate)
            _limiter_rate = rate
            logger.debug("RateLimiter global inicializado: %.3f req/s (sin ráfagas)", rate)
        return _limiter


def reset_rate_limiter() -> None:
    """Resetea el singleton (para tests y reconfiguración de despliegue)."""
    global _limiter, _limiter_rate
    with _limiter_lock:
        _limiter = None
        _limiter_rate = None
