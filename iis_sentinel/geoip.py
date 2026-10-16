"""Real IP geolocation for the threat matrix / pending threats.

Source order:
  1. A local MaxMind-format database in <data>/geoip/. Any GeoLite2-City / GeoLite2-Country / DB-IP .mmdb dropped
     there is used. Unless disabled (WATCHERS > GeoIP auto-download), Sentinel downloads the free DB-IP
     "IP to City Lite" database (CC BY 4.0, no account needed) and refreshes it monthly.
  2. Until a database is available (offline host, first start), the registered country from RDAP WHOIS.
Lookups never raise: an unknown address is simply "" (rendered as "—").
"""
from __future__ import annotations

import asyncio
import gzip
import ipaddress
import logging
import os
import shutil
import time
from datetime import date
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("sentinel.geoip")

DBIP_URL = "https://download.db-ip.com/free/dbip-city-lite-{month}.mmdb.gz"
DBIP_FILE = "dbip-city-lite.mmdb"
REFRESH_DAYS = 32
RETRY_SECONDS = 6 * 3600
_PREFERRED = ("GeoLite2-City.mmdb", "GeoIP2-City.mmdb", DBIP_FILE, "GeoLite2-Country.mmdb", "dbip-country-lite.mmdb")


def special_label(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return "??"
    if addr.is_loopback:
        return "LOCALHOST"
    if addr.is_private or addr.is_link_local or addr in ipaddress.ip_network("100.64.0.0/10"):
        return "LAN / INTERNAL"
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return "RESERVED"
    return None


def format_record(rec: dict[str, Any] | None) -> str:
    if not rec:
        return ""
    country = (rec.get("country") or rec.get("registered_country") or {}).get("iso_code") or ""
    city = ((rec.get("city") or {}).get("names") or {}).get("en") or ""
    if not city:
        subs = rec.get("subdivisions") or []
        city = ((subs[0].get("names") or {}).get("en") or "") if subs else ""
    return f"{country} / {city}" if country and city else country


def _months_to_try() -> list[str]:
    today = date.today()
    prev = date(today.year - (today.month == 1), 12 if today.month == 1 else today.month - 1, 1)
    return [today.strftime("%Y-%m"), prev.strftime("%Y-%m")]


class GeoResolver:
    def __init__(self, data_dir: Path, whois: Any = None, auto_download: Callable[[], bool] = lambda: True) -> None:
        self.dir = data_dir / "geoip"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.whois = whois
        self.auto_download = auto_download
        self._reader: Any = None
        self._db_path: Path | None = None
        self._cache: dict[str, str] = {}
        self._last_attempt = 0.0
        self.last_error: str | None = None
        self._open_best()

    # ------------------------------------------------------------------ database
    def _candidates(self) -> list[Path]:
        try:
            files = [p for p in self.dir.glob("*.mmdb") if p.is_file()]
        except OSError:
            return []
        rank = {name.lower(): i for i, name in enumerate(_PREFERRED)}
        return sorted(files, key=lambda p: (rank.get(p.name.lower(), len(rank)), p.name))

    def _open_best(self) -> None:
        try:
            import maxminddb
        except ImportError:
            self.last_error = "maxminddb package not installed"
            return
        for path in self._candidates():
            try:
                reader = maxminddb.open_database(str(path))
            except Exception as exc:  # noqa: BLE001
                log.warning("Unusable GeoIP database %s: %s", path, exc)
                continue
            old, self._reader, self._db_path = self._reader, reader, path
            self._cache.clear()
            if old is not None:
                try:
                    old.close()
                except Exception:  # noqa: BLE001
                    pass
            log.info("GeoIP database loaded: %s", path.name)
            return

    def status(self) -> dict[str, Any]:
        built = None
        if self._reader is not None:
            try:
                built = time.strftime("%Y-%m-%d", time.gmtime(self._reader.metadata().build_epoch))
            except Exception:  # noqa: BLE001
                built = None
        return {"source": self._db_path.name if self._db_path else ("rdap-country" if self.whois else "none"),
                "database": str(self._db_path) if self._db_path else None, "built": built, "error": self.last_error}

    def _download(self) -> None:
        import requests

        tmp_gz = self.dir / (DBIP_FILE + ".gz.part")
        tmp = self.dir / (DBIP_FILE + ".part")
        errors = []
        for month in _months_to_try():
            url = DBIP_URL.format(month=month)
            try:
                with requests.get(url, stream=True, timeout=(10, 120), headers={"User-Agent": "IIS-Sentinel"}) as r:
                    if r.status_code == 404:
                        errors.append(f"{month}: not published yet")
                        continue
                    r.raise_for_status()
                    with open(tmp_gz, "wb") as fh:
                        for chunk in r.iter_content(1 << 20):
                            fh.write(chunk)
                with gzip.open(tmp_gz, "rb") as src, open(tmp, "wb") as dst:
                    shutil.copyfileobj(src, dst, 1 << 20)
                import maxminddb

                maxminddb.open_database(str(tmp)).close()
                os.replace(tmp, self.dir / DBIP_FILE)
                log.info("Downloaded DB-IP City Lite %s", month)
                return
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{month}: {type(exc).__name__}: {str(exc)[:160]}")
            finally:
                for p in (tmp_gz, tmp):
                    try:
                        p.unlink()
                    except OSError:
                        pass
        raise RuntimeError("; ".join(errors) or "download failed")

    def _needs_download(self) -> bool:
        if not self.auto_download():
            return False
        own = self.dir / DBIP_FILE
        if self._db_path is not None and self._db_path.name != DBIP_FILE:
            return False
        try:
            return not own.exists() or time.time() - own.stat().st_mtime > REFRESH_DAYS * 86400
        except OSError:
            return True

    async def run(self) -> None:
        while True:
            if self._needs_download() and time.time() - self._last_attempt > RETRY_SECONDS:
                self._last_attempt = time.time()
                try:
                    await asyncio.to_thread(self._download)
                    self.last_error = None
                    await asyncio.to_thread(self._open_best)
                except Exception as exc:  # noqa: BLE001
                    self.last_error = f"GeoIP download failed (using WHOIS country instead): {exc}"
                    log.warning(self.last_error)
            elif self._reader is None and self._candidates():
                await asyncio.to_thread(self._open_best)
            await asyncio.sleep(300)

    # ------------------------------------------------------------------ lookups
    def quick(self, ip: str) -> str:
        """Instant answer (special ranges, cache, local database) or '' when a network lookup is needed."""
        label = special_label(ip)
        if label:
            return label
        hit = self._cache.get(ip)
        if hit is not None:
            return hit
        if self._reader is None:
            return ""
        try:
            geo = format_record(self._reader.get(ip.split("%", 1)[0]))
        except Exception:  # noqa: BLE001
            geo = ""
        if len(self._cache) > 50000:
            self._cache.clear()
        self._cache[ip] = geo
        return geo

    async def resolve(self, ip: str) -> str:
        geo = self.quick(ip)
        if geo or self._reader is not None or self.whois is None:
            return geo
        try:
            info = await self.whois.lookup(ip)
        except Exception:  # noqa: BLE001
            return ""
        if info.get("error"):
            return ""
        geo = str(info.get("country") or "").upper()
        if not geo and info.get("registry"):
            geo = f"{info['registry']} REG."
        self._cache[ip] = geo
        return geo
