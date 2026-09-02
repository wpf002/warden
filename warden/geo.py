"""Geo lookup and distance. Stand-in for a real GeoIP database.

Country centroids are coarse on purpose: impossible travel only needs to know that two
logins are thousands of km apart, not which suburb they came from. Swap `COORDS` for
MaxMind city-level lookups and the detection is unchanged.
"""
from __future__ import annotations

from math import asin, cos, radians, sin, sqrt

# country code -> (lat, lon) centroid
COORDS: dict[str, tuple[float, float]] = {
    "US": (39.8, -98.6),
    "CA": (56.1, -106.3),
    "BR": (-14.2, -51.9),
    "GB": (55.4, -3.4),
    "DE": (51.2, 10.5),
    "FR": (46.2, 2.2),
    "NL": (52.1, 5.3),
    "RU": (61.5, 105.3),
    "CN": (35.9, 104.2),
    "IN": (20.6, 79.0),
    "JP": (36.2, 138.3),
    "AU": (-25.3, 133.8),
    "NG": (9.1, 8.7),
    "ZA": (-30.6, 22.9),
    "SG": (1.35, 103.8),
    "IR": (32.4, 53.7),
    "KP": (40.3, 127.5),
    "UA": (48.4, 31.2),
}

# IP prefix -> country. Real deployments replace this with a GeoIP lookup.
PREFIXES: dict[str, str] = {
    "203.0.113.": "RU",
    "198.51.100.": "CN",
    "192.0.2.": "BR",
    "185.220.": "NL",
    "45.83.": "DE",
    "10.": "internal",
    "172.16.": "internal",
    "192.168.": "internal",
}

INTERNAL = "internal"


def country_for_ip(ip: str) -> str:
    for prefix, geo in PREFIXES.items():
        if ip.startswith(prefix):
            return geo
    return "US"


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1, lat2, lon2 = map(radians, (*a, *b))
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    return 2 * 6371.0 * asin(sqrt(h))


def distance_km(geo_a: str, geo_b: str) -> float | None:
    """None when either side is unmappable (internal, unknown country)."""
    a, b = COORDS.get(geo_a), COORDS.get(geo_b)
    if a is None or b is None:
        return None
    return haversine_km(a, b)


def required_kmh(geo_a: str, geo_b: str, seconds: float) -> float | None:
    """Speed a human would need to make the trip. None if unmappable or same place."""
    km = distance_km(geo_a, geo_b)
    if km is None or seconds <= 0:
        return None
    return km / (seconds / 3600.0)
