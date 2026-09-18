"""Behavioral anomaly for a user: a day that departs from their last 30 days. No rule
names what happened; the contributing features say why it was flagged."""
from __future__ import annotations

from . import register
from ._anomaly import AnomalyDetection


@register
class UserAnomaly(AnomalyDetection):
    id = "anomaly.user"
    name = "User behavior anomaly"
    entity_type = "user"
