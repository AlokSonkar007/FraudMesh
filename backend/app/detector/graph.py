"""Layer 3a — temporal entity graph.

Link two events when they share an entity (actor, target, device, domain, payee).
Edge weight w = type_weight[entity_type] * exp(-dt / tau[entity_type]) * idf(entity),
idf = log(N / (1 + degree(entity))) normalized -> suppresses hub entities (popular
merchants/broadcast senders) so legitimate payment bursts do not form giant clusters.
Edges below w_min are dropped; components > max_component are split with Louvain.

Implementation: bipartite event<->entity graph; campaign candidates are connected
components restricted to EVENT nodes (events linked through a shared entity count
as connected). Event-event edge strength is computed on demand via pair_strength().
"""
from __future__ import annotations

import math
from collections import defaultdict
from itertools import combinations
from typing import Any

import networkx as nx
from networkx.algorithms.community import louvain_communities

from backend.app.schema import Event

ENTITY_FIELDS = {"actor": "actor_id", "target": "target_id", "device": "device_id",
                 "url_domain": "url_domain", "payee_vpa": "payee_vpa"}


def ent_node(etype: str, val: str) -> str:
    return f"ENT:{etype}:{val}"


class EntityGraph:
    def __init__(self, cfg: dict[str, Any]):
        g = cfg["graph"]
        self.type_weight = g["type_weight"]
        self.tau_sec = {k: v * 60 for k, v in g["tau_minutes"].items()}
        self.w_min = g["w_min"]
        self.max_component = g["max_component"]
        self.resolution = g["louvain_resolution"]
        self.G = nx.Graph()
        self.event_ts: dict[str, int] = {}
        self.event_entities: dict[str, list[tuple[str, str]]] = {}
        self.entity_index: dict[tuple[str, str], list[str]] = defaultdict(list)
        # entities that have ALREADY produced a w_min-surviving link. A first-time
        # entity (new payee/device/domain) carries no correlation evidence yet; the
        # second sighting of the same entity within tau is what forms the edge.
        self._linked_entities: set[tuple[str, str]] = set()
        self.N = 1                                   # events seen (for idf)
        self.degree_count: dict[tuple[str, str], int] = defaultdict(int)

    # ---------- construction ----------
    def add_event(self, e: Event) -> None:
        self.N += 1
        self.event_ts[e.event_id] = e.timestamp
        self.G.add_node(e.event_id, kind="event")
        pairs = []
        for etype, field in ENTITY_FIELDS.items():
            val = getattr(e, field)
            if not val:
                continue
            key = (etype, val)
            prior = [p for p in self.entity_index[key] if p in self.event_ts]
            self.entity_index[key].append(e.event_id)
            self.degree_count[key] += 1
            node = ent_node(*key)
            self.G.add_node(node, kind="entity", entity_type=etype, entity=val)
            active = key in self._linked_entities
            if not active:
                # provisional idf at degree>=2 — monotone per entity, so once an
                # entity's decay window closes it can never form a link later.
                prov_idf = self.idf(max(self.degree_count[key], 2))
                tw = self.type_weight[etype]
                for p in prior:
                    dt = abs(e.timestamp - self.event_ts[p])
                    if tw * math.exp(-dt / self.tau_sec[etype]) * prov_idf >= self.w_min:
                        active = True
                        break
            if active:
                self._linked_entities.add(key)
                self.G.add_edge(e.event_id, node, dormant=False)
                for p in prior:                       # revive earlier dormant links
                    if self.G.has_edge(p, node):
                        self.G.edges[p, node]["dormant"] = False
            else:
                self.G.add_edge(e.event_id, node, dormant=True)
            pairs.append(key)
        self.event_entities[e.event_id] = pairs

    def edge_weight(self, key: tuple[str, str], dt_sec: float) -> float:
        """Time-decayed, IDF-suppressed shared-entity strength between two events."""
        etype, _val = key
        tw = self.type_weight[etype]
        decay = math.exp(-dt_sec / self.tau_sec[etype])
        return tw * decay * self.idf(self.degree_count[key])

    def idf(self, degree: int) -> float:
        """log(N/(1+deg)) normalized against the single-use ceiling -> [0,1]."""
        raw = math.log(max(self.N, 2) / (1 + degree))
        cap = math.log(max(self.N, 2) / 2)
        return max(0.0, min(1.0, raw / max(cap, 1e-9)))

    def pair_strength(self, eid_a: str, eid_b: str) -> tuple[float, str, str]:
        """Best (weight, entity_type, entity) over all shared entities."""
        dt = abs(self.event_ts[eid_a] - self.event_ts[eid_b])
        best = (0.0, "", "")
        setb = set(self.event_entities.get(eid_b, []))
        for key in self.event_entities.get(eid_a, []):
            if key in setb:
                w = self.edge_weight(key, dt)
                if w > best[0]:
                    best = (w, key[0], key[1])
        return best

    # ---------- windowing ----------
    def prune(self, now_ts: int, window_hours: float) -> None:
        cutoff = now_ts - int(window_hours * 3600)
        stale = [n for n, d in self.G.nodes(data=True)
                 if d["kind"] == "event" and self.event_ts.get(n, now_ts) < cutoff]
        for n in stale:
            self.event_ts.pop(n, None)
            self.event_entities.pop(n, None)
            nbrs = list(self.G.neighbors(n))
            self.G.remove_node(n)
            for m in nbrs:
                nd = self.G.nodes.get(m)
                if nd and nd["kind"] == "entity" and not list(self.G.neighbors(m)):
                    self.entity_index.pop((nd["entity_type"], nd["entity"]), None)
                    self.G.remove_node(m)

    # ---------- candidates ----------
    def assign_component_ids(self) -> None:
        """Label every event node with its component id (cheap union-find pass)."""
        self.comp_of = {}
        for cid, comp in enumerate(self.event_components()):
            for n in comp:
                self.comp_of[n] = cid

    def comp_id_of(self, eid: str) -> int | None:
        return getattr(self, "comp_of", {}).get(eid)

    def active_graph(self) -> nx.Graph:
        """Subgraph containing only w_min-surviving links (dormant edges dropped)."""
        H = nx.Graph()
        for a, b, d in self.G.edges(data=True):
            if not d.get("dormant"):
                H.add_edge(a, b)
        for n, d in self.G.nodes(data=True):
            if n not in H and d["kind"] == "event":
                H.add_node(n)
        return H

    def event_components(self) -> list[list[str]]:
        H = self.active_graph()
        ev_nodes = [n for n, d in H.nodes(data=True) if d.get("kind") == "event"]
        comps, seen = [], set()
        for n in ev_nodes:
            if n in seen:
                continue
            comp = {x for x in nx.node_connected_component(H, n)
                    if H.nodes[x].get("kind") == "event"}
            seen |= comp
            if len(comp) >= 2:
                comps.append(sorted(comp))
        return comps

    def components(self, ids: set[int] | None = None) -> list[list[str]]:
        """Campaign candidates: components (optionally only those with the given
        component ids), capped & Louvain-split when oversized."""
        all_comps = self.event_components()
        if ids is not None and getattr(self, "comp_of", None):
            prev_ids = self.comp_of   # ids refer to the PREVIOUS labeling
            wanted = {n for n, c in prev_ids.items() if c in ids}
            pool = []
            for comp in all_comps:
                inter = [n for n in comp if n in wanted]
                if inter:
                    pool.append(comp)   # include whole (possibly merged) component
            comps_src = pool
        else:
            comps_src = all_comps
        comps = []
        for comp in comps_src:
            if len(comp) > self.max_component:
                full = set(comp)
                for n in comp:
                    full |= {m for m in self.G.neighbors(n)
                             if self.G.nodes[m]["kind"] == "entity"}
                wsub = self.G.subgraph(full)
                try:
                    comms = louvain_communities(wsub, resolution=self.resolution, seed=0)
                except Exception:
                    comms = [set(comp)]
                parts = []
                for c in comms:
                    ev = sorted(n for n in c if self.G.nodes[n]["kind"] == "event")
                    if ev:
                        parts.append(ev)
                if len(parts) <= 1:
                    parts = [sorted(comp)[i:i + self.max_component]
                             for i in range(0, len(comp), self.max_component)]
                comps.extend(parts)
            else:
                comps.append(comp)
        return comps

    # ---------- dashboard dump ----------
    def graph_dump(self, event_ids: list[str]) -> dict[str, Any]:
        eset = set(event_ids)
        nodes = [{"id": n, "kind": "event"} for n in sorted(eset)]
        edges, ents = [], set()
        for a, b in combinations(sorted(eset), 2):
            w, etype, val = self.pair_strength(a, b)
            if etype:
                edges.append({"source": a, "target": b, "weight": round(w, 4),
                              "entity_type": etype, "entity": val,
                              "below_w_min": w < self.w_min,
                              "dt_sec": abs(self.event_ts[a] - self.event_ts[b])})
        for n in eset:
            ents |= set(self.event_entities.get(n, []))
        for etype, val in sorted(ents):
            dormant = (etype, val) not in self._linked_entities
            nodes.append({"id": ent_node(etype, val), "kind": "entity",
                          "entity_type": etype, "entity": val, "dormant": dormant})
            for n in sorted(eset):
                if (etype, val) in self.event_entities.get(n, []):
                    edges.append({"source": ent_node(etype, val), "target": n,
                                  "weight": 1.0, "entity_type": etype,
                                  "membership": True, "dormant": dormant})
        return {"nodes": nodes, "edges": edges}
