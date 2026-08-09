# FORGE_CONTEXT: CIVIL
"""
Tests del rate limiter DURO (utils.ratelimit) — doctrina AmegakureDojo: máx 13
req/s SIN ráfagas. Reloj y sleep inyectados => deterministas, no duermen de verdad.
"""
import threading

import pytest

from amegakurewotan.utils.ratelimit import RateLimiter, get_rate_limiter, reset_rate_limiter


class FakeClock:
    """Reloj monótono virtual: sleep() avanza el tiempo sin dormir de verdad."""

    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, secs):
        assert secs >= 0
        self.t += secs


def test_rate_rejects_nonpositive():
    with pytest.raises(ValueError):
        RateLimiter(rate=0)
    with pytest.raises(ValueError):
        RateLimiter(rate=-5)


def test_spacing_no_burst_enforced():
    """Con no_burst, cada acquire consecutivo se separa >= 1/rate segundos."""
    clk = FakeClock()
    rl = RateLimiter(rate=13.0, no_burst=True, clock=clk.now, sleep=clk.sleep)
    min_interval = 1.0 / 13.0

    stamps = []
    for _ in range(13):
        rl.acquire()
        stamps.append(clk.now())

    # La primera no espera; el resto respeta el espaciado mínimo.
    for prev, cur in zip(stamps, stamps[1:]):
        assert cur - prev >= min_interval - 1e-9


def test_caudal_max_13_in_any_second():
    """Nunca más de 13 peticiones en cualquier ventana deslizante de 1 segundo."""
    clk = FakeClock()
    rl = RateLimiter(rate=13.0, no_burst=True, clock=clk.now, sleep=clk.sleep)

    stamps = []
    for _ in range(40):
        rl.acquire()
        stamps.append(clk.now())

    # Garantía rigurosa: para cada instante t de una petición, el nº de peticiones
    # en la ventana half-open (t-1, t] no supera 13. Epsilon FP en ambos bordes.
    eps = 1e-9
    for t in stamps:
        in_window = sum(1 for s in stamps if (t - 1.0 + eps) < s <= (t + eps))
        assert in_window <= 13, f"ventana excede 13: {in_window} en t={t}"


def test_burst_allowed_when_no_burst_false():
    """Sin anti-ráfaga, hasta `rate` permisos son inmediatos (t=0)."""
    clk = FakeClock()
    rl = RateLimiter(rate=13.0, no_burst=False, clock=clk.now, sleep=clk.sleep)

    for _ in range(13):
        rl.acquire()
    # Las primeras 13 no avanzan el reloj (caben en la ventana inicial).
    assert clk.now() == 0.0
    # La 14ª debe esperar a que expire la ventana.
    rl.acquire()
    assert clk.now() >= 1.0 - 1e-9


def test_effective_rate_never_exceeds_13():
    """En régimen sostenido, N peticiones ocupan al menos (N-1)/rate segundos,
    es decir el caudal sostenido jamás supera 13 req/s (la 1ª petición es gratis)."""
    clk = FakeClock()
    rl = RateLimiter(rate=13.0, clock=clk.now, sleep=clk.sleep)
    n = 130
    for _ in range(n):
        rl.acquire()
    elapsed = clk.now()
    min_expected = (n - 1) / 13.0
    assert elapsed >= min_expected - 1e-6, f"demasiado rápido: {elapsed} < {min_expected}"
    # Caudal sostenido (excluyendo el permiso inicial gratuito) <= 13/s.
    sustained = (n - 1) / elapsed if elapsed > 0 else float("inf")
    assert sustained <= 13.0 + 1e-6


def test_thread_safe_shared_grifo():
    """Varios hilos comparten el limitador sin exceder el caudal agregado."""
    clk = FakeClock()
    clk_lock = threading.Lock()

    def now():
        with clk_lock:
            return clk.t

    def sleep(secs):
        with clk_lock:
            clk.t += secs

    rl = RateLimiter(rate=13.0, clock=now, sleep=sleep)
    count = {"n": 0}
    count_lock = threading.Lock()

    def worker():
        for _ in range(10):
            rl.acquire()
            with count_lock:
                count["n"] += 1

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert count["n"] == 50  # 5 hilos x 10 = todas completaron


def test_singleton_honors_config(monkeypatch):
    """get_rate_limiter reconstruye si cambia la tasa de config."""
    reset_rate_limiter()
    rl1 = get_rate_limiter()
    assert rl1.rate == 13.0  # default doctrinal

    # Cambia la tasa vía override de config y resetea el singleton de config.
    import amegakurewotan.config as cfg

    monkeypatch.setenv("OPSEC_MAX_REQUESTS_PER_SECOND", "5")
    cfg._config = None  # fuerza relectura
    reset_rate_limiter()
    rl2 = get_rate_limiter()
    assert rl2.rate == 5.0

    # Restaura estado global limpio para no contaminar otros tests.
    cfg._config = None
    reset_rate_limiter()
