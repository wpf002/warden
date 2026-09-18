"""Behavioral anomaly for a host: new processes, new parent->child pairs, new external
destinations, or volumes far outside its baseline."""
from __future__ import annotations

from . import register
from ._anomaly import AnomalyDetection


@register
class HostAnomaly(AnomalyDetection):
    id = "anomaly.host"
    name = "Host behavior anomaly"
    entity_type = "host"
