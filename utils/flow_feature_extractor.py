# utils/flow_feature_extractor.py
# ─────────────────────────────────────────────────────────────────────────────
# Maintains per-flow statistics from live pyshark packets and produces a
# feature dictionary that matches the CIC-IDS-2017 column names used during
# training. Only the 12 features derivable from pyshark metadata are computed.
# ─────────────────────────────────────────────────────────────────────────────

import time
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

# How many seconds a flow lives before it is reset
FLOW_TIMEOUT = 30.0

# CIC-IDS feature names produced here (must match training columns)
FEATURE_NAMES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "ACK Flag Count",
    "FIN Flag Count",
]


class _Flow:
    __slots__ = (
        "start_time", "last_time",
        "fwd_pkts", "bwd_pkts",
        "fwd_bytes", "bwd_bytes",
        "syn", "ack", "fin",
    )

    def __init__(self, now: float):
        self.start_time = now
        self.last_time  = now
        self.fwd_pkts   = 0
        self.bwd_pkts   = 0
        self.fwd_bytes  = 0
        self.bwd_bytes  = 0
        self.syn        = 0
        self.ack        = 0
        self.fin        = 0


class FlowFeatureExtractor:
    """
    Usage
    -----
    Call ``FlowFeatureExtractor.update(pkt, summary)`` for each live packet.

    Returns
    -------
    dict  – feature dict keyed by CIC-IDS column names, or
    None  – if the flow has fewer than 2 packets (not enough data yet)
    """

    _flows: dict = defaultdict(lambda: None)

    @classmethod
    def _flow_key(cls, summary: dict) -> tuple:
        return (
            summary.get("src", ""),
            summary.get("dst", ""),
            summary.get("protocol", ""),
        )

    @classmethod
    def update(cls, pkt, summary: dict):
        now = time.monotonic()
        key = cls._flow_key(summary)
        flow: _Flow = cls._flows.get(key)

        # Create or reset expired flow
        if flow is None or (now - flow.last_time) > FLOW_TIMEOUT:
            flow = _Flow(now)
            cls._flows[key] = flow

        flow.last_time = now

        # Determine direction by comparing src with flow key src
        is_forward = True  # simplified: treat all as forward

        # Packet length
        try:
            pkt_len = int(getattr(pkt, "length", 0))
        except Exception:
            pkt_len = 0

        if is_forward:
            flow.fwd_pkts  += 1
            flow.fwd_bytes += pkt_len
        else:
            flow.bwd_pkts  += 1
            flow.bwd_bytes += pkt_len

        # TCP flags
        flags = str(summary.get("flags", "") or "")
        if "S" in flags:
            flow.syn += 1
        if "A" in flags:
            flow.ack += 1
        if "F" in flags:
            flow.fin += 1

        total_pkts = flow.fwd_pkts + flow.bwd_pkts

        # Need at least 2 packets to compute rates
        if total_pkts < 2:
            return None

        duration = max(now - flow.start_time, 1e-6)

        fwd_len_mean = flow.fwd_bytes / max(flow.fwd_pkts, 1)
        bwd_len_mean = flow.bwd_bytes / max(flow.bwd_pkts, 1)
        total_bytes  = flow.fwd_bytes + flow.bwd_bytes

        features = {
            "Flow Duration":                  duration,
            "Total Fwd Packets":              flow.fwd_pkts,
            "Total Backward Packets":         flow.bwd_pkts,
            "Total Length of Fwd Packets":    flow.fwd_bytes,
            "Total Length of Bwd Packets":    flow.bwd_bytes,
            "Fwd Packet Length Mean":         fwd_len_mean,
            "Bwd Packet Length Mean":         bwd_len_mean,
            "Flow Bytes/s":                   total_bytes  / duration,
            "Flow Packets/s":                 total_pkts   / duration,
            "SYN Flag Count":                 flow.syn,
            "ACK Flag Count":                 flow.ack,
            "FIN Flag Count":                 flow.fin,
        }

        return features
