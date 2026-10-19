# 05 — Leakage abuse & novel/academic constructions

Some challenges implement a **paper** (encrypted graphs, structured/searchable encryption, ORAM, a bespoke "GES/SDSP" scheme, a homomorphic gadget). There is no off-the-shelf payload — you break it by reasoning about **what each interaction leaks** and reconstructing the secret from the leakage. This is the general skill; the specific scheme changes every time.

## Method
1. **Get and read the construction** (server source or the referenced paper/README). Write down: the secret object (a graph, a permutation, a database, a key schedule), the public API (which queries are allowed), and — precisely — **the observable output of each query type**.
2. **Characterize per-query leakage.** For each query, what function of the secret becomes known? Examples of leakage that fully break schemes:
   - **Access pattern**: which encrypted records a query touches (repeats reveal equality; co-occurrence reveals structure).
   - **Response length / volume**: number of matches leaks frequencies → frequency analysis on the plaintext space.
   - **Degree / adjacency leakage** (encrypted graphs): each neighborhood query reveals a node's degree or its neighbor set → recover the **degree sequence**, then the graph up to isomorphism, then the labeling from any anchor.
   - **Path/traversal leakage** (tree/DAG schemes, "SDSP" shortest-path style): each query reveals the set/order of nodes on a path → intersect paths to recover the tree structure and node identities.
3. **Model recovery as an inference problem.** Turn the collected leakage into constraints (equalities, orderings, counts) and solve: union-find for equality classes, sorting for order leakage, `networkx` to rebuild a graph from a degree sequence / edge set, linear algebra if the leakage is linear.
4. **Query planning.** You usually have a query budget. Choose queries that maximize new structure learned (cover all nodes/edges, disambiguate symmetric cases with a distinguishing query).

```python
import networkx as nx

def rebuild_from_neighbor_leakage(neighbor_sets):
    # neighbor_sets: {node_id: set(neighbor_ids)} learned from queries -> exact graph
    G = nx.Graph()
    for u, nbrs in neighbor_sets.items():
        for v in nbrs:
            G.add_edge(u, v)
    return G

def rebuild_from_degree_sequence(deg_seq):
    # only degrees leaked (no adjacency): get *a* realization, then disambiguate with anchors.
    if not nx.is_graphical(deg_seq):
        deg_seq = sorted(deg_seq, reverse=True)     # fix ordering; else adjust collected data
    return nx.havel_hakimi_graph(deg_seq)           # one graph with exactly these degrees

def label_by_structure(G, known):
    # known: {node_in_G: real_label} anchors. Propagate labels by matching unique degree/neighborhood.
    labels = dict(known)
    changed = True
    while changed:
        changed = False
        for n in G.nodes():
            if n in labels: continue
            # a node uniquely identified by (degree, sorted neighbor labels) gets its label
            sig = (G.degree(n), tuple(sorted(labels[m] for m in G[n] if m in labels)))
            cand = [t for t in G.nodes() if t not in labels.values()
                    and (G.degree(t), ) == (sig[0],)]
            if len(cand) == 1:
                labels[n] = cand[0]; changed = True
    return labels
# For tree/shortest-path leakage: intersect the node sets of many queried paths to fix parent/child,
#   then root the tree at the anchor and read node identities off the recovered topology.
```

## General tips for "I've never seen this scheme"
- The intended break is almost always **the leakage the authors traded away for efficiency** — search the source/paper for the security caveats ("leaks access pattern", "reveals equality", "assumes honest queries").
- If it's a **homomorphic** gadget, use the homomorphism to craft a query whose decrypted result reveals a bit of the secret (see RSA/ElGamal oracle pages — same idea, different algebra).
- If randomness is involved, check for **reuse / low entropy / predictable RNG** (see the RNG note below).
- Count queries: if `k` queries each reveal `b` bits and the secret is `S` bits, you need `S/b` queries — if the budget is smaller, there's extra structure (linearity, symmetry) you're meant to exploit.

## Predictable randomness (cross-cutting)
Many "academic" and misc challenges hinge on a weak RNG: Python `random` (Mersenne Twister — recover full state from 624 consecutive 32-bit outputs, then predict/rewind; `randcrack`-style or hand LFSR), LCG (solve modulus/multiplier from consecutive outputs), or a seeded-by-time PRNG (brute the seed over the time window). If outputs feed keys/nonces/tokens, recovering the RNG state breaks everything downstream.
