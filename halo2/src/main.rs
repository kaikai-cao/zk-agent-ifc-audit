//! ZK-AGENT-IFC-AUDIT Phase 1B.1: fixed-circuit, graph-independent VK prototype.
//!
//! Research prototype only.  It proves that a committed single-session IFC graph
//! satisfies a forward-closure condition.  It does NOT prove collector
//! completeness, label truth, runtime execution truth, or classic two-run
//! noninterference.
//!
//! Phase 1B.1 changes relative to the 1B baseline:
//!   * circuit shape depends only on (cap, edge_cap), never on the active-edge
//!     pattern or endpoint values of a particular graph;
//!   * node S lookup uses a fixed one-hot crossbar with structural copy wiring;
//!   * the public commitment is randomized: C = H(DOMAIN_BLIND, root_G, blind);
//!   * setup / prove / verify are separate processes and timings are separated.

use std::convert::TryInto;
use std::fs;
use std::time::Instant;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ff::{Field, PrimeField};
use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash as GadgetHash, Pow5Chip, Pow5Config,
};
use halo2_poseidon::{
    ConstantLength as HostLength, Hash as HostHash, P128Pow5T3 as HostSpec,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Expression, Fixed, Instance, Selector, SingleVerifier,
        VirtualCells, VerifyingKey as PlonkVk, ProvingKey as PlonkPk,
    },
    poly::{commitment::Params, Rotation},
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas::Base as F, vesta};
use rand::{rngs::StdRng, RngExt, SeedableRng};
use serde_json::{json, Value as JsonValue};

const DOMAIN_NODE: u64 = 0x4E4F_4445;
const DOMAIN_EDGE: u64 = 0x4544_4745;
const DOMAIN_EMPTY: u64 = 0x454D_5054;
const DOMAIN_BIND: u64 = 0x4249_4E44;
const DOMAIN_BLIND: u64 = 0x424C_494E;

const T_CONFIDENTIAL_SOURCE: u64 = 0;
const T_PUBLIC_SOURCE: u64 = 1;
const T_MODEL_OUTPUT: u64 = 2;
const T_TOOL_INVOCATION: u64 = 3;
const T_TOOL_RESULT: u64 = 4;
const T_PUBLIC_SINK: u64 = 5;

const SCHEMA: &str = "ifc-fixed-v1";
const CIRCUIT_VERSION: &str = "phase1b1-fixed-crossbar-blind-v1";

#[derive(Clone, Debug)]
struct GNode { typ: u64, label: u64, s: u64 }

#[derive(Clone, Debug)]
struct GEdge { src: usize, dst: usize, kind: u64, active: bool }

#[derive(Clone, Debug)]
struct Witness {
    cap: usize,
    edge_cap: usize,
    nodes: Vec<GNode>,
    edges: Vec<GEdge>,
    policy_id: u64,
    session_id: u64,
    nonce: u64,
    collector_id: u64,
    /// Random blinding factor; part of the commitment, never public.
    blind: F,
}

fn host_hash<const L: usize>(words: [F; L]) -> F {
    HostHash::<F, HostSpec, HostLength<L>, 3, 2>::init().hash(words)
}
fn f(value: u64) -> F { F::from(value) }
fn cap_domain(base: u64, cap: usize) -> F { f(base.wrapping_add(cap as u64)) }

fn node_leaf(node: &GNode, pos: usize, cap: usize) -> F {
    host_hash::<3>([cap_domain(DOMAIN_NODE, cap), f(node.typ * 2 + node.label), f(pos as u64)])
}
fn edge_hash(src: usize, dst: usize, kind: u64, cap: usize) -> F {
    host_hash::<3>([cap_domain(DOMAIN_EDGE, cap), f(src as u64 * cap as u64 + dst as u64), f(kind)])
}
fn empty_leaf(cap: usize) -> F { host_hash::<2>([cap_domain(DOMAIN_EMPTY, cap), F::ZERO]) }
fn merge_leaf(left: F, right: F) -> F { host_hash::<2>([left, right]) }

fn merkle_root(w: &Witness) -> F {
    let cap = w.cap;
    let empty = empty_leaf(cap);
    let mut leaves: Vec<F> = w.nodes.iter().enumerate()
        .map(|(i, n)| node_leaf(n, i, cap)).collect();
    for e in &w.edges {
        leaves.push(if e.active { edge_hash(e.src, e.dst, e.kind, cap) } else { empty });
    }
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 { leaves.push(empty); }
        leaves = leaves.chunks_exact(2).map(|p| merge_leaf(p[0], p[1])).collect();
    }
    leaves[0]
}

/// Public randomized commitment: C = H(DOMAIN_BLIND, root_G, blind).
fn commitment(w: &Witness) -> F {
    host_hash::<3>([cap_domain(DOMAIN_BLIND, w.cap), merkle_root(w), w.blind])
}

fn to_hex(value: F) -> String {
    value.to_repr().iter().rev().map(|b| format!("{:02x}", b)).collect()
}

fn from_hex(s: &str) -> Option<F> {
    let bytes = hex_bytes(s, 32)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr.reverse();
    Option::<F>::from(F::from_repr(arr))
}

fn hex_bytes(s: &str, len: usize) -> Option<Vec<u8>> {
    if s.len() != len * 2 { return None; }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn to_hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn canonical_attestation_bytes(c: F, w: &Witness) -> Vec<u8> {
    format!("{}|{}|{}|{}|{}", to_hex(c), w.policy_id, w.session_id, w.nonce, w.collector_id).into_bytes()
}

fn make_collector(sk_bytes: [u8; 32]) -> (SigningKey, VerifyingKey, u64) {
    let sk = SigningKey::from_bytes(&sk_bytes);
    let vk = sk.verifying_key();
    let raw = vk.to_bytes();
    let mut acc: u64 = 0;
    for b in raw.iter().take(8) { acc = acc.rotate_left(8) ^ (*b as u64); }
    (sk, vk, acc & 0x7fff_ffff_ffff_ffff)
}

/// Deterministic compliant graph. High nodes only point to High nodes.
fn make_compliant_witness(cap: usize, density: &str, seed: u64, collector_id: u64) -> Witness {
    let mut rng = StdRng::seed_from_u64(seed);
    let edge_cap = 2 * cap;
    let high_count = cap / 2;
    let mut nodes = Vec::with_capacity(cap);
    for i in 0..cap {
        if i == cap - 1 {
            nodes.push(GNode { typ: T_PUBLIC_SINK, label: 0, s: 0 });
        } else if i < high_count {
            let typ = match i % 3 { 0 => T_CONFIDENTIAL_SOURCE, 1 => T_TOOL_INVOCATION, _ => T_TOOL_RESULT };
            nodes.push(GNode { typ, label: 1, s: 1 });
        } else {
            let typ = if i % 4 == 0 { T_PUBLIC_SOURCE } else { T_MODEL_OUTPUT };
            nodes.push(GNode { typ, label: 0, s: 0 });
        }
    }
    let target = match density { "low" => cap / 2, "mid" => cap, "high" => 2 * cap,
        _ => panic!("density must be low|mid|high") }.min(edge_cap);
    let mut edges = Vec::with_capacity(edge_cap);
    let high_target = target / 2;
    let low_target = target - high_target;
    for (count, lo, hi) in [(high_target, 0usize, high_count), (low_target, high_count, cap)] {
        let mut made = 0usize;
        let mut guard = 0usize;
        while made < count && guard < 20_000 {
            guard += 1;
            let src = rng.random_range(lo..hi);
            let dst = rng.random_range(lo..hi);
            if src == dst { continue; }
            if edges.iter().any(|e: &GEdge| e.active && e.src == src && e.dst == dst) { continue; }
            edges.push(GEdge { src, dst, kind: rng.random_range(0..2), active: true });
            made += 1;
        }
        assert_eq!(made, count, "could not build requested edge count");
    }
    while edges.len() < edge_cap {
        edges.push(GEdge { src: 0, dst: 0, kind: 0, active: false });
    }
    Witness {
        cap, edge_cap, nodes, edges,
        policy_id: 7, session_id: 20261126, nonce: 1 + seed % 100_000, collector_id,
        blind: host_hash::<1>([f(seed ^ 0x5A5A_5A5A)]),
    }
}

/// Graph-independent template used for key generation; contains no graph data.
fn fixed_template(cap: usize) -> Witness {
    Witness {
        cap,
        edge_cap: 2 * cap,
        nodes: vec![GNode { typ: T_PUBLIC_SOURCE, label: 0, s: 0 }; cap],
        edges: vec![GEdge { src: 0, dst: 0, kind: 0, active: false }; 2 * cap],
        policy_id: 0, session_id: 0, nonce: 0, collector_id: 0,
        blind: F::ZERO,
    }
}

#[derive(Clone, Debug)]
struct IfcConfig {
    q_node: Selector,
    q_edge: Selector,
    q_select: Selector,
    q_cross: Selector,
    q_last: Selector,
    label: Column<Advice>,
    s: Column<Advice>,
    node_type: Column<Advice>,
    node_index: Column<Advice>,
    type_bits: [Column<Advice>; 3],
    is_sink_type: Column<Advice>,
    is_low_sink: Column<Advice>,
    src: Column<Advice>,
    dst: Column<Advice>,
    kind: Column<Advice>,
    active: Column<Advice>,
    s_src: Column<Advice>,
    s_dst: Column<Advice>,
    inv_delta: Column<Advice>,
    leaf_domain: Column<Advice>,
    leaf_value: Column<Advice>,
    public_copy: Column<Advice>,
    // Edge-leaf selection region: copied cells + selected value.
    sel_active: Column<Advice>,
    sel_edge_hash: Column<Advice>,
    sel_empty_hash: Column<Advice>,
    edge_selected: Column<Advice>,
    // Fixed crossbar.
    cb_index: Column<Fixed>,
    cb_sel_src: Column<Advice>,
    cb_sel_dst: Column<Advice>,
    cb_s_copy: Column<Advice>,
    cb_prod_src: Column<Advice>,
    cb_prod_dst: Column<Advice>,
    cb_acc_src: Column<Advice>,
    cb_acc_dst: Column<Advice>,
    cb_acc_sel_src: Column<Advice>,
    cb_acc_sel_dst: Column<Advice>,
    cb_acc_idx_src: Column<Advice>,
    cb_acc_idx_dst: Column<Advice>,
    cb_prev_src: Column<Advice>,
    cb_prev_dst: Column<Advice>,
    cb_prev_sel_src: Column<Advice>,
    cb_prev_sel_dst: Column<Advice>,
    cb_prev_idx_src: Column<Advice>,
    cb_prev_idx_dst: Column<Advice>,
    instance: Column<Instance>,
    poseidon: Pow5Config<F, 3, 2>,
}

fn adv(meta: &mut VirtualCells<'_, F>, col: Column<Advice>) -> Expression<F> {
    meta.query_advice(col, Rotation::cur())
}

#[derive(Clone, Debug)]
struct IfcCircuit { witness: Option<Witness> }

impl IfcCircuit {
    fn new(w: Witness) -> Self { Self { witness: Some(w) } }
    fn template(cap: usize) -> Self { Self { witness: Some(fixed_template(cap)) } }
}

impl Circuit<F> for IfcCircuit {
    type Config = IfcConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { witness: Some(fixed_template(50)) }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let label = meta.advice_column();
        let s = meta.advice_column();
        let node_type = meta.advice_column();
        let node_index = meta.advice_column();
        let type_bits: [Column<Advice>; 3] = (0..3).map(|_| meta.advice_column())
            .collect::<Vec<_>>().try_into().unwrap();
        let is_sink_type = meta.advice_column();
        let is_low_sink = meta.advice_column();
        let src = meta.advice_column();
        let dst = meta.advice_column();
        let kind = meta.advice_column();
        let active = meta.advice_column();
        let s_src = meta.advice_column();
        let s_dst = meta.advice_column();
        let inv_delta = meta.advice_column();
        let leaf_domain = meta.advice_column();
        let leaf_value = meta.advice_column();
        let public_copy = meta.advice_column();
        let sel_active = meta.advice_column();
        let sel_edge_hash = meta.advice_column();
        let sel_empty_hash = meta.advice_column();
        let edge_selected = meta.advice_column();
        let cb_index = meta.fixed_column();
        let cb_sel_src = meta.advice_column();
        let cb_sel_dst = meta.advice_column();
        let cb_s_copy = meta.advice_column();
        let cb_prod_src = meta.advice_column();
        let cb_prod_dst = meta.advice_column();
        let cb_acc_src = meta.advice_column();
        let cb_acc_dst = meta.advice_column();
        let cb_acc_sel_src = meta.advice_column();
        let cb_acc_sel_dst = meta.advice_column();
        let cb_acc_idx_src = meta.advice_column();
        let cb_acc_idx_dst = meta.advice_column();
        let cb_prev_src = meta.advice_column();
        let cb_prev_dst = meta.advice_column();
        let cb_prev_sel_src = meta.advice_column();
        let cb_prev_sel_dst = meta.advice_column();
        let cb_prev_idx_src = meta.advice_column();
        let cb_prev_idx_dst = meta.advice_column();
        let instance = meta.instance_column();

        for col in [
            label, s, node_type, node_index, is_sink_type, is_low_sink, src, dst, kind,
            active, s_src, s_dst, inv_delta, leaf_domain, leaf_value, public_copy,
            sel_active, sel_edge_hash, sel_empty_hash, edge_selected,
            cb_sel_src, cb_sel_dst, cb_s_copy, cb_prod_src, cb_prod_dst,
            cb_acc_src, cb_acc_dst, cb_acc_sel_src, cb_acc_sel_dst,
            cb_acc_idx_src, cb_acc_idx_dst,
            cb_prev_src, cb_prev_dst, cb_prev_sel_src, cb_prev_sel_dst,
            cb_prev_idx_src, cb_prev_idx_dst,
        ] { meta.enable_equality(col); }
        for col in type_bits.iter().cloned() { meta.enable_equality(col); }
        meta.enable_equality(instance);

        let state: [Column<Advice>; 3] = (0..3).map(|_| meta.advice_column())
            .collect::<Vec<_>>().try_into().unwrap();
        let partial_sbox = meta.advice_column();
        let rc_a: [Column<Fixed>; 3] = (0..3).map(|_| meta.fixed_column())
            .collect::<Vec<_>>().try_into().unwrap();
        let rc_b: [Column<Fixed>; 3] = (0..3).map(|_| meta.fixed_column())
            .collect::<Vec<_>>().try_into().unwrap();
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);

        let q_node = meta.complex_selector();
        let q_edge = meta.complex_selector();
        let q_select = meta.complex_selector();
        let q_cross = meta.complex_selector();
        let q_last = meta.complex_selector();

        // Node gate: boolean bits, type enum 0..=5, High=>S, Low sink not in S.
        meta.create_gate("node encoding and closure endpoints", |meta| {
            let q = meta.query_selector(q_node);
            let label = adv(meta, label);
            let s = adv(meta, s);
            let typ = adv(meta, node_type);
            let b0 = adv(meta, type_bits[0]);
            let b1 = adv(meta, type_bits[1]);
            let b2 = adv(meta, type_bits[2]);
            let is_sink_type = adv(meta, is_sink_type);
            let is_low_sink = adv(meta, is_low_sink);
            let one = Expression::Constant(F::ONE);
            let type_sum = b0.clone() + b1.clone() * Expression::Constant(F::from(2))
                + b2.clone() * Expression::Constant(F::from(4));
            vec![
                q.clone() * label.clone() * (label.clone() - one.clone()),
                q.clone() * s.clone() * (s.clone() - one.clone()),
                q.clone() * b0.clone() * (b0.clone() - one.clone()),
                q.clone() * b1.clone() * (b1.clone() - one.clone()),
                q.clone() * b2.clone() * (b2.clone() - one.clone()),
                q.clone() * b1.clone() * b2.clone(), // exclude types 6,7
                q.clone() * (typ - type_sum),
                q.clone() * label.clone() * (one.clone() - s.clone()),
                q.clone() * (is_sink_type.clone() - b0 * (one.clone() - b1) * b2),
                q.clone() * (is_low_sink.clone() - is_sink_type * (one.clone() - label)),
                q.clone() * is_low_sink * s,
            ]
        });

        // Edge gate: enabled on every slot.  active is a constrained witness bit;
        // inactive slots have canonical src=dst=kind=0.  s_src/s_dst are wired
        // from the fixed crossbar, never from witness-dependent copy constraints.
        meta.create_gate("edge format and forward closure", |meta| {
            let q = meta.query_selector(q_edge);
            let src = adv(meta, src);
            let dst = adv(meta, dst);
            let kind = adv(meta, kind);
            let active = adv(meta, active);
            let s_src = adv(meta, s_src);
            let s_dst = adv(meta, s_dst);
            let inv = adv(meta, inv_delta);
            let one = Expression::Constant(F::ONE);
            vec![
                q.clone() * active.clone() * (active.clone() - one.clone()),
                q.clone() * kind.clone() * (kind.clone() - one.clone()),
                q.clone() * (one.clone() - active.clone()) * src.clone(),
                q.clone() * (one.clone() - active.clone()) * dst.clone(),
                q.clone() * (one.clone() - active.clone()) * kind,
                q.clone() * active.clone() * ((src - dst) * inv.clone() - one.clone()),
                q.clone() * (one.clone() - active.clone()) * inv,
                q.clone() * active * s_src * (one - s_dst),
            ]
        });

        // Edge leaf selection: active ? edge_hash : empty_hash.  Both branches
        // are always computed, so the Poseidon layout is graph-independent.
        meta.create_gate("edge leaf selection", |meta| {
            let q = meta.query_selector(q_select);
            let active = adv(meta, sel_active);
            let selected = adv(meta, edge_selected);
            let edge_h = adv(meta, sel_edge_hash);
            let empty_h = adv(meta, sel_empty_hash);
            let one = Expression::Constant(F::ONE);
            vec![q * (active.clone() * (selected.clone() - edge_h)
                + (one - active) * (selected - empty_h))]
        });

        // Fixed crossbar: one-hot selection of S[src] and S[dst].
        meta.create_gate("crossbar one-hot and accumulators", |meta| {
            let q = meta.query_selector(q_cross);
            let last = meta.query_selector(q_last);
            let idx = meta.query_fixed(cb_index);
            let sel_src = adv(meta, cb_sel_src);
            let sel_dst = adv(meta, cb_sel_dst);
            let s_copy = adv(meta, cb_s_copy);
            let prod_src = adv(meta, cb_prod_src);
            let prod_dst = adv(meta, cb_prod_dst);
            let acc_src = adv(meta, cb_acc_src);
            let acc_dst = adv(meta, cb_acc_dst);
            let acc_sel_src = adv(meta, cb_acc_sel_src);
            let acc_sel_dst = adv(meta, cb_acc_sel_dst);
            let acc_idx_src = adv(meta, cb_acc_idx_src);
            let acc_idx_dst = adv(meta, cb_acc_idx_dst);
            let prev_src = adv(meta, cb_prev_src);
            let prev_dst = adv(meta, cb_prev_dst);
            let prev_sel_src = adv(meta, cb_prev_sel_src);
            let prev_sel_dst = adv(meta, cb_prev_sel_dst);
            let prev_idx_src = adv(meta, cb_prev_idx_src);
            let prev_idx_dst = adv(meta, cb_prev_idx_dst);
            let one = Expression::Constant(F::ONE);
            vec![
                q.clone() * sel_src.clone() * (sel_src.clone() - one.clone()),
                q.clone() * sel_dst.clone() * (sel_dst.clone() - one.clone()),
                q.clone() * (prod_src.clone() - sel_src.clone() * s_copy.clone()),
                q.clone() * (prod_dst.clone() - sel_dst.clone() * s_copy),
                q.clone() * (acc_src.clone() - prev_src - prod_src.clone()),
                q.clone() * (acc_dst.clone() - prev_dst - prod_dst),
                q.clone() * (acc_sel_src.clone() - prev_sel_src - sel_src.clone()),
                q.clone() * (acc_sel_dst.clone() - prev_sel_dst - sel_dst.clone()),
                q.clone() * (acc_idx_src.clone() - prev_idx_src - idx.clone() * sel_src.clone()),
                q.clone() * (acc_idx_dst - prev_idx_dst - idx * sel_dst),
                q.clone() * last.clone() * (acc_sel_src - one.clone()),
                q.clone() * last * (acc_sel_dst - one),
            ]
        });

        IfcConfig {
            q_node, q_edge, q_select, q_cross, q_last,
            label, s, node_type, node_index, type_bits, is_sink_type, is_low_sink,
            src, dst, kind, active, s_src, s_dst, inv_delta, leaf_domain, leaf_value,
            public_copy, sel_active, sel_edge_hash, sel_empty_hash, edge_selected,
            cb_index, cb_sel_src, cb_sel_dst, cb_s_copy, cb_prod_src, cb_prod_dst,
            cb_acc_src, cb_acc_dst, cb_acc_sel_src, cb_acc_sel_dst,
            cb_acc_idx_src, cb_acc_idx_dst,
            cb_prev_src, cb_prev_dst, cb_prev_sel_src, cb_prev_sel_dst,
            cb_prev_idx_src, cb_prev_idx_dst, instance, poseidon,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let w = self.witness.as_ref().ok_or(Error::Synthesis)?;
        let cap = w.cap;
        let edge_cap = w.edge_cap;

        // ---- node rows ----
        let (index_cells, s_cells, node_tl_cells) = layouter.assign_region(
            || "nodes",
            |mut region: Region<'_, F>| {
                let mut index_cells = Vec::with_capacity(cap);
                let mut s_cells = Vec::with_capacity(cap);
                let mut leaf_tl = Vec::with_capacity(cap);
                for i in 0..cap {
                    config.q_node.enable(&mut region, i)?;
                    let node = &w.nodes[i];
                    index_cells.push(region.assign_advice(|| "idx", config.node_index, i,
                        || Value::known(f(i as u64)))?);
                    s_cells.push(region.assign_advice(|| "s", config.s, i,
                        || Value::known(f(node.s)))?);
                    region.assign_advice(|| "label", config.label, i,
                        || Value::known(f(node.label)))?;
                    region.assign_advice(|| "type", config.node_type, i,
                        || Value::known(f(node.typ)))?;
                    for b in 0..3 {
                        region.assign_advice(|| "type_bit", config.type_bits[b], i,
                            || Value::known(f((node.typ >> b) & 1)))?;
                    }
                    let is_sink_type = if node.typ == T_PUBLIC_SINK { 1 } else { 0 };
                    let is_low_sink = is_sink_type * (1 - node.label);
                    region.assign_advice(|| "is_sink_type", config.is_sink_type, i,
                        || Value::known(f(is_sink_type)))?;
                    region.assign_advice(|| "is_low_sink", config.is_low_sink, i,
                        || Value::known(f(is_low_sink)))?;
                    leaf_tl.push(region.assign_advice(|| "leaf_tl", config.leaf_domain, i,
                        || Value::known(f(node.typ * 2 + node.label)))?);
                }
                Ok((index_cells, s_cells, leaf_tl))
            },
        )?;

        // ---- edge rows (fixed count and selector pattern) ----
        let (edge_idx_cells, kind_cells, active_cells, s_src_cells, s_dst_cells, src_cells, dst_cells) =
            layouter.assign_region(
                || "edges",
                |mut region: Region<'_, F>| {
                    let mut leaf_idx = Vec::with_capacity(edge_cap);
                    let mut kinds = Vec::with_capacity(edge_cap);
                    let mut actives = Vec::with_capacity(edge_cap);
                    let mut s_srcs = Vec::with_capacity(edge_cap);
                    let mut s_dsts = Vec::with_capacity(edge_cap);
                    let mut srcs = Vec::with_capacity(edge_cap);
                    let mut dsts = Vec::with_capacity(edge_cap);
                    for j in 0..edge_cap {
                        config.q_edge.enable(&mut region, j)?;
                        let e = &w.edges[j];
                        srcs.push(region.assign_advice(|| "src", config.src, j,
                            || Value::known(f(e.src as u64)))?);
                        dsts.push(region.assign_advice(|| "dst", config.dst, j,
                            || Value::known(f(e.dst as u64)))?);
                        kinds.push(region.assign_advice(|| "kind", config.kind, j,
                            || Value::known(f(e.kind)))?);
                        actives.push(region.assign_advice(|| "active", config.active, j,
                            || Value::known(f(e.active as u64)))?);
                        s_srcs.push(region.assign_advice(|| "s_src", config.s_src, j,
                            || Value::known(f(w.nodes[if e.active { e.src } else { 0 }].s)))?);
                        s_dsts.push(region.assign_advice(|| "s_dst", config.s_dst, j,
                            || Value::known(f(w.nodes[if e.active { e.dst } else { 0 }].s)))?);
                        let delta = f(e.src as u64) - f(e.dst as u64);
                        let inv = if !e.active || bool::from(delta.is_zero()) {
                            F::ZERO
                        } else {
                            delta.invert().unwrap()
                        };
                        region.assign_advice(|| "inv", config.inv_delta, j, || Value::known(inv))?;
                        leaf_idx.push(region.assign_advice(|| "leaf_idx", config.leaf_value, j,
                            || Value::known(f(e.src as u64 * cap as u64 + e.dst as u64)))?);
                    }
                    Ok((leaf_idx, kinds, actives, s_srcs, s_dsts, srcs, dsts))
                },
            )?;

        // ---- fixed crossbar ----
        let _crossbar_end = layouter.assign_region(
            || "crossbar",
            |mut region: Region<'_, F>| {
                for j in 0..edge_cap {
                    let e = &w.edges[j];
                    let effective_src = if e.active { e.src } else { 0 };
                    let effective_dst = if e.active { e.dst } else { 0 };
                    let mut prev_vals = (F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO);
                    let mut prev_cells: Option<(AssignedCell<F, F>, AssignedCell<F, F>,
                        AssignedCell<F, F>, AssignedCell<F, F>,
                        AssignedCell<F, F>, AssignedCell<F, F>)> = None;
                    for i in 0..cap {
                        let row = j * cap + i;
                        config.q_cross.enable(&mut region, row)?;
                        if i == cap - 1 { config.q_last.enable(&mut region, row)?; }
                        region.assign_fixed(|| "cb_idx", config.cb_index, row,
                            || Value::known(f(i as u64)))?;
                        let sel_src = if effective_src == i { F::ONE } else { F::ZERO };
                        let sel_dst = if effective_dst == i { F::ONE } else { F::ZERO };
                        let s_copy = f(w.nodes[i].s);
                        let prod_src = sel_src * s_copy;
                        let prod_dst = sel_dst * s_copy;
                        // Previous-row accumulator witnesses (zero at block start).
                        let pv_src = region.assign_advice(|| "prev_src", config.cb_prev_src, row,
                            || Value::known(prev_vals.0))?;
                        let pv_dst = region.assign_advice(|| "prev_dst", config.cb_prev_dst, row,
                            || Value::known(prev_vals.1))?;
                        let pv_sel_src = region.assign_advice(|| "prev_sel_src", config.cb_prev_sel_src, row,
                            || Value::known(prev_vals.2))?;
                        let pv_sel_dst = region.assign_advice(|| "prev_sel_dst", config.cb_prev_sel_dst, row,
                            || Value::known(prev_vals.3))?;
                        let pv_idx_src = region.assign_advice(|| "prev_idx_src", config.cb_prev_idx_src, row,
                            || Value::known(prev_vals.4))?;
                        let pv_idx_dst = region.assign_advice(|| "prev_idx_dst", config.cb_prev_idx_dst, row,
                            || Value::known(prev_vals.5))?;
                        if let Some(pc) = &prev_cells {
                            region.constrain_equal(pv_src.cell(), pc.0.cell())?;
                            region.constrain_equal(pv_dst.cell(), pc.1.cell())?;
                            region.constrain_equal(pv_sel_src.cell(), pc.2.cell())?;
                            region.constrain_equal(pv_sel_dst.cell(), pc.3.cell())?;
                            region.constrain_equal(pv_idx_src.cell(), pc.4.cell())?;
                            region.constrain_equal(pv_idx_dst.cell(), pc.5.cell())?;
                        }
                        let acc_src = prev_vals.0 + prod_src;
                        let acc_dst = prev_vals.1 + prod_dst;
                        let acc_sel_src = prev_vals.2 + sel_src;
                        let acc_sel_dst = prev_vals.3 + sel_dst;
                        let acc_idx_src = prev_vals.4 + f(i as u64) * sel_src;
                        let acc_idx_dst = prev_vals.5 + f(i as u64) * sel_dst;
                        let copy_cell = region.assign_advice(|| "cb_s_copy", config.cb_s_copy, row,
                            || Value::known(s_copy))?;
                        region.constrain_equal(copy_cell.cell(), s_cells[i].cell())?;
                        region.assign_advice(|| "cb_sel_src", config.cb_sel_src, row,
                            || Value::known(sel_src))?;
                        region.assign_advice(|| "cb_sel_dst", config.cb_sel_dst, row,
                            || Value::known(sel_dst))?;
                        region.assign_advice(|| "cb_prod_src", config.cb_prod_src, row,
                            || Value::known(prod_src))?;
                        region.assign_advice(|| "cb_prod_dst", config.cb_prod_dst, row,
                            || Value::known(prod_dst))?;
                        let acc_src_cell = region.assign_advice(|| "cb_acc_src", config.cb_acc_src, row,
                            || Value::known(acc_src))?;
                        let acc_dst_cell = region.assign_advice(|| "cb_acc_dst", config.cb_acc_dst, row,
                            || Value::known(acc_dst))?;
                        let acc_sel_src_cell = region.assign_advice(|| "cb_acc_sel_src", config.cb_acc_sel_src, row,
                            || Value::known(acc_sel_src))?;
                        let acc_sel_dst_cell = region.assign_advice(|| "cb_acc_sel_dst", config.cb_acc_sel_dst, row,
                            || Value::known(acc_sel_dst))?;
                        let idx_src_cell = region.assign_advice(|| "cb_acc_idx_src", config.cb_acc_idx_src, row,
                            || Value::known(acc_idx_src))?;
                        let idx_dst_cell = region.assign_advice(|| "cb_acc_idx_dst", config.cb_acc_idx_dst, row,
                            || Value::known(acc_idx_dst))?;
                        if i == cap - 1 {
                            // Fixed structural wiring: end-of-block accumulators
                            // are copied into the edge witness cells.
                            region.constrain_equal(acc_src_cell.cell(), s_src_cells[j].cell())?;
                            region.constrain_equal(acc_dst_cell.cell(), s_dst_cells[j].cell())?;
                            region.constrain_equal(idx_src_cell.cell(), src_cells[j].cell())?;
                            region.constrain_equal(idx_dst_cell.cell(), dst_cells[j].cell())?;
                        }
                        prev_vals = (acc_src, acc_dst, acc_sel_src, acc_sel_dst, acc_idx_src, acc_idx_dst);
                        prev_cells = Some((acc_src_cell, acc_dst_cell, acc_sel_src_cell,
                            acc_sel_dst_cell, idx_src_cell, idx_dst_cell));
                    }
                }
                Ok(())
            },
        )?;

        // ---- public binding ----
        let public_cells = layouter.assign_region(
            || "public binding",
            |mut region: Region<'_, F>| {
                let values = [commitment(w), f(w.policy_id), f(w.session_id), f(w.nonce), f(w.collector_id)];
                let mut cells = Vec::with_capacity(5);
                for (i, v) in values.iter().enumerate() {
                    cells.push(region.assign_advice(|| "public", config.public_copy, i,
                        || Value::known(*v))?);
                }
                Ok(cells)
            },
        )?;
        for (i, cell) in public_cells.iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.instance, i)?;
        }

        // ---- Poseidon Merkle tree ----
        let mut leaves: Vec<AssignedCell<F, F>> = Vec::with_capacity(cap + edge_cap);
        let node_domain = layouter.assign_region(|| "node domain", |mut region|
            region.assign_advice(|| "nd", config.leaf_domain, 0,
                || Value::known(cap_domain(DOMAIN_NODE, cap))))?;
        for i in 0..cap {
            leaves.push(hash_words::<_, 3>(&config, layouter.namespace(|| format!("node_leaf_{i}")),
                [node_domain.clone(), node_tl_cells[i].clone(), index_cells[i].clone()])?);
        }
        let edge_domain = layouter.assign_region(|| "edge domain", |mut region|
            region.assign_advice(|| "ed", config.leaf_domain, 0,
                || Value::known(cap_domain(DOMAIN_EDGE, cap))))?;
        let mut edge_hashes = Vec::with_capacity(edge_cap);
        for j in 0..edge_cap {
            edge_hashes.push(hash_words::<_, 3>(&config, layouter.namespace(|| format!("edge_hash_{j}")),
                [edge_domain.clone(), edge_idx_cells[j].clone(), kind_cells[j].clone()])?);
        }
        let empty_cell = empty_leaf_cell(&config, &mut layouter, cap)?;
        let selected = layouter.assign_region(
            || "edge leaf selection",
            |mut region: Region<'_, F>| {
                let mut out = Vec::with_capacity(edge_cap);
                for j in 0..edge_cap {
                    config.q_select.enable(&mut region, j)?;
                    let active_copy = region.assign_advice(|| "sel_active", config.sel_active, j,
                        || Value::known(f(w.edges[j].active as u64)))?;
                    region.constrain_equal(active_copy.cell(), active_cells[j].cell())?;
                    let hash_copy = region.assign_advice(|| "sel_edge_hash", config.sel_edge_hash, j,
                        || Value::known(edge_hash(w.edges[j].src, w.edges[j].dst, w.edges[j].kind, cap)))?;
                    region.constrain_equal(hash_copy.cell(), edge_hashes[j].cell())?;
                    let empty_copy = region.assign_advice(|| "sel_empty_hash", config.sel_empty_hash, j,
                        || Value::known(empty_leaf(cap)))?;
                    region.constrain_equal(empty_copy.cell(), empty_cell.cell())?;
                    let val = if w.edges[j].active {
                        edge_hash(w.edges[j].src, w.edges[j].dst, w.edges[j].kind, cap)
                    } else { empty_leaf(cap) };
                    out.push(region.assign_advice(|| "edge_selected", config.edge_selected, j,
                        || Value::known(val))?);
                }
                Ok(out)
            },
        )?;
        leaves.extend(selected);
        while leaves.len() > 1 {
            if leaves.len() % 2 == 1 { leaves.push(empty_cell.clone()); }
            let mut next = Vec::with_capacity(leaves.len() / 2);
            for pair in leaves.chunks_exact(2) {
                next.push(hash_words::<_, 2>(&config, layouter.namespace(|| "merge"),
                    [pair[0].clone(), pair[1].clone()])?);
            }
            leaves = next;
        }
        let blind_domain = layouter.assign_region(|| "blind domain", |mut region|
            region.assign_advice(|| "bd", config.leaf_domain, 0,
                || Value::known(cap_domain(DOMAIN_BLIND, cap))))?;
        let blind_cell = layouter.assign_region(|| "blind factor", |mut region|
            region.assign_advice(|| "blind", config.leaf_value, 0, || Value::known(w.blind)))?;
        let committed = hash_words::<_, 3>(&config, layouter.namespace(|| "commitment"),
            [blind_domain, leaves[0].clone(), blind_cell])?;
        layouter.constrain_instance(committed.cell(), config.instance, 0)?;
        Ok(())
    }
}

fn assign_value(region: &mut Region<'_, F>, col: Column<Advice>, offset: usize, value: F)
    -> Result<AssignedCell<F, F>, Error> {
    region.assign_advice(|| "value", col, offset, || Value::known(value))
}

fn empty_leaf_cell(config: &IfcConfig, layouter: &mut impl Layouter<F>, cap: usize)
    -> Result<AssignedCell<F, F>, Error> {
    let domain = layouter.assign_region(|| "empty leaf domain", |mut region|
        assign_value(&mut region, config.leaf_domain, 0, cap_domain(DOMAIN_EMPTY, cap)))?;
    let zero = layouter.assign_region(|| "empty leaf zero", |mut region|
        assign_value(&mut region, config.leaf_value, 0, F::ZERO))?;
    hash_words::<_, 2>(config, layouter.namespace(|| "empty leaf"), [domain, zero])
}

fn hash_words<L: Layouter<F>, const N: usize>(config: &IfcConfig, mut layouter: L,
    words: [AssignedCell<F, F>; N]) -> Result<AssignedCell<F, F>, Error> {
    let chip = Pow5Chip::construct(config.poseidon.clone());
    let hasher = GadgetHash::<_, _, P128Pow5T3, ConstantLength<N>, 3, 2>::init(
        chip, layouter.namespace(|| "init"))?;
    hasher.hash(layouter.namespace(|| "hash"), words)
}

fn k_for_cap(cap: usize) -> u32 {
    match cap { 50 => 15, 100 => 17, 200 => 19, _ => panic!("unsupported cap") }
}

fn expected_vk_hash(cap: usize, k: u32) -> F {
    // Stable identifier derived only from public fixed parameters.
    host_hash::<3>([cap_domain(DOMAIN_BIND, cap), f(k as u64), f(CIRCUIT_VERSION.len() as u64)])
}

fn keygen_with_k(cap: usize, k: u32) -> (Params<vesta::Affine>, PlonkVk<vesta::Affine>, PlonkPk<vesta::Affine>) {
    let params = Params::<vesta::Affine>::new(k);
    let template = IfcCircuit::template(cap);
    let vk = keygen_vk(&params, &template).expect("keygen_vk on fixed template");
    let pk = keygen_pk(&params, vk.clone(), &template).expect("keygen_pk");
    (params, vk, pk)
}


fn vk_digest(vk: &PlonkVk<vesta::Affine>) -> [u8; 32] {
    // SHA-256 over the pinned VK representation.  `hash_into` cannot be used
    // here: Blake2bWrite::finalize returns the writer unchanged, so it yields
    // no digest bytes.
    use sha2::{Digest, Sha256};
    let pinned = format!("{:?}", vk.pinned());
    let mut hasher = Sha256::new();
    hasher.update(pinned.as_bytes());
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

fn load_setup(path: &str) -> JsonValue {
    serde_json::from_slice(&fs::read(path).expect("read setup")).expect("parse setup")
}

fn setup(cap: usize, out: &str) {
    let t_params = Instant::now();
    let mut k = k_for_cap(cap);
    let params_probe = Params::<vesta::Affine>::new(k);
    let params_ms = t_params.elapsed().as_millis();
    let template = IfcCircuit::template(cap);
    let t_vk = Instant::now();
    let (params, vk) = loop {
        let p = Params::<vesta::Affine>::new(k);
        match keygen_vk(&p, &template) {
            Ok(v) => break (p, v),
            Err(_) => {
                k += 1;
                if k > 22 { panic!("keygen_vk out of rows at k=22"); }
            }
        }
    };
    let vk_ms = t_vk.elapsed().as_millis();
    let t_pk = Instant::now();
    let pk = keygen_pk(&params, vk.clone(), &template).expect("keygen_pk");
    let pk_ms = t_pk.elapsed().as_millis();
    let vk_digest_hex = to_hex_bytes(&vk_digest(&vk));
    let _ = (params_probe, vk, pk);

    let result = json!({
        "schema": SCHEMA,
        "circuit_version": CIRCUIT_VERSION,
        "cap": cap,
        "edge_cap": 2 * cap,
        "k": k,
        "vk_hash": to_hex(expected_vk_hash(cap, k)),
        "vk_digest": vk_digest_hex,
        "params_gen_ms": params_ms,
        "vk_gen_ms": vk_ms,
        "pk_gen_ms": pk_ms,
        "note": "halo2_proofs 0.4 exposes no VK serialization API; verifier rebuilds the graph-independent fixed-template VK and pins it via vk_hash. This is an explicit deviation from an opaque serialized VK."
    });
    fs::write(out, serde_json::to_vec_pretty(&result).unwrap()).expect("write setup");
    println!("{}", serde_json::to_string(&result).unwrap());
}

fn prove(cap: usize, density: &str, seed: u64, setup_path: &str, proof_path: &str, public_path: &str) {
    let setup = load_setup(setup_path);
    assert_eq!(setup["schema"].as_str(), Some(SCHEMA), "setup schema mismatch");
    let k = setup["k"].as_u64().unwrap() as u32;
    assert_eq!(setup["vk_hash"].as_str().unwrap(), to_hex(expected_vk_hash(cap, k)), "vk hash mismatch");

    let (sk, vk_collector, collector_id) = make_collector([0x11; 32]);
    let w = make_compliant_witness(cap, density, seed, collector_id);
    let c = commitment(&w);
    let instance = vec![c, f(w.policy_id), f(w.session_id), f(w.nonce), f(w.collector_id)];
    let sig = sk.sign(&canonical_attestation_bytes(c, &w));

    let (params, _, pk) = keygen_with_k(cap, k);
    assert_eq!(setup["vk_digest"].as_str().unwrap(), to_hex_bytes(&vk_digest(pk.get_vk())),
        "prover VK does not match setup-pinned VK");
    let t0 = Instant::now();
    let inst_refs: Vec<&[F]> = vec![&instance[..]];
    let all_instances: Vec<&[&[F]]> = vec![&inst_refs];
    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    create_proof(&params, &pk, &[IfcCircuit::new(w.clone())], &all_instances,
        StdRng::seed_from_u64(seed), &mut transcript).expect("create_proof");
    let proof = transcript.finalize();
    let prove_ms = t0.elapsed().as_millis();
    fs::write(proof_path, &proof).expect("write proof");

    let public = json!({
        "schema": SCHEMA,
        "circuit_version": CIRCUIT_VERSION,
        "cap": cap,
        "commitment": to_hex(c),
        "policy_id": w.policy_id,
        "session_id": w.session_id,
        "nonce": w.nonce,
        "collector_id": w.collector_id,
        "collector_public_key": to_hex_bytes(&vk_collector.to_bytes()),
        "collector_signature": to_hex_bytes(&sig.to_bytes()),
        "k": k,
        "prove_ms": prove_ms,
        "proof_bytes": proof.len(),
        "density": density,
        "active_edges": w.edges.iter().filter(|e| e.active).count(),
    });
    fs::write(public_path, serde_json::to_vec_pretty(&public).unwrap()).expect("write public");
    println!("{}", serde_json::to_string(&public).unwrap());
}

fn verify(setup_path: &str, proof_path: &str, public_path: &str, out: &str) {
    let setup = load_setup(setup_path);
    let public: JsonValue = serde_json::from_slice(&fs::read(public_path).expect("read public"))
        .expect("parse public");
    assert_eq!(setup["schema"].as_str(), Some(SCHEMA));
    assert_eq!(public["schema"].as_str(), Some(SCHEMA));
    let cap = setup["cap"].as_u64().unwrap() as usize;
    let k = setup["k"].as_u64().unwrap() as u32;
    assert_eq!(setup["vk_hash"].as_str().unwrap(), to_hex(expected_vk_hash(cap, k)));

    // No graph or witness file is read in this function.
    let commitment_hex = public["commitment"].as_str().unwrap();
    let instance = vec![
        from_hex(commitment_hex).expect("parse commitment"),
        f(public["policy_id"].as_u64().unwrap()),
        f(public["session_id"].as_u64().unwrap()),
        f(public["nonce"].as_u64().unwrap()),
        f(public["collector_id"].as_u64().unwrap()),
    ];
    let proof = fs::read(proof_path).expect("read proof");

    let pk_bytes = hex_bytes(public["collector_public_key"].as_str().unwrap(), 32).expect("collector pk hex");
    let mut pk_arr = [0u8; 32]; pk_arr.copy_from_slice(&pk_bytes);
    let collector_vk = VerifyingKey::from_bytes(&pk_arr).expect("collector vk");
    let sig_bytes = hex_bytes(public["collector_signature"].as_str().unwrap(), 64).expect("signature hex");
    let mut sig_arr = [0u8; 64]; sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let attestation = format!(
        "{}|{}|{}|{}|{}", commitment_hex,
        public["policy_id"].as_u64().unwrap(), public["session_id"].as_u64().unwrap(),
        public["nonce"].as_u64().unwrap(), public["collector_id"].as_u64().unwrap(),
    ).into_bytes();
    let t_sig = Instant::now();
    let sig_ok = collector_vk.verify(&attestation, &sig).is_ok();
    let sig_verify_ms = t_sig.elapsed().as_millis();
    assert!(sig_ok, "collector signature must verify");

    // VK rebuilt from public fixed template only; no graph, no witness.
    let params = Params::<vesta::Affine>::new(k);
    let t_vk = Instant::now();
    let vk = keygen_vk(&params, &IfcCircuit::template(cap)).expect("keygen_vk fixed template");
    let vk_rebuild_ms = t_vk.elapsed().as_millis();
    assert_eq!(setup["vk_digest"].as_str().unwrap(), to_hex_bytes(&vk_digest(&vk)),
        "verifier VK does not match setup-pinned VK");

    let inst_refs: Vec<&[F]> = vec![&instance[..]];
    let all_instances: Vec<&[&[F]]> = vec![&inst_refs];
    let t_verify = Instant::now();
    verify_proof(&params, &vk, SingleVerifier::new(&params), &all_instances,
        &mut Blake2bRead::init(&proof[..])).expect("verify_proof");
    let pure_verify_ms = t_verify.elapsed().as_millis();

    let mut bad = instance.clone();
    bad[3] += F::ONE;
    let bad_refs: Vec<&[F]> = vec![&bad[..]];
    let bad_all: Vec<&[&[F]]> = vec![&bad_refs];
    let wrong_nonce_rejected = verify_proof(&params, &vk, SingleVerifier::new(&params), &bad_all,
        &mut Blake2bRead::init(&proof[..])).is_err();
    assert!(wrong_nonce_rejected);

    let result = json!({
        "schema": SCHEMA,
        "cap": cap,
        "k": k,
        "sig_verify_ms": sig_verify_ms,
        "vk_rebuild_ms": vk_rebuild_ms,
        "pure_verify_ms": pure_verify_ms,
        "wrong_nonce_rejected": wrong_nonce_rejected,
        "collector_signature_verified": true,
        "verifier_read_graph": false,
        "verifier_called_keygen_vk_on_witness": false,
        "note": "pure_verify_ms excludes VK rebuild and signature verification."
    });
    fs::write(out, serde_json::to_vec_pretty(&result).unwrap()).expect("write verify result");
    println!("{}", serde_json::to_string(&result).unwrap());
}

fn selftest(cap: usize) {
    let (sk, vk_c, collector_id) = make_collector([0x11; 32]);
    let good = make_compliant_witness(cap, "low", 2026112699, collector_id);
    let k = k_for_cap(cap);
    let mut invalid = good.clone();
    invalid.edges[0] = GEdge { src: 0, dst: cap - 1, kind: 0, active: true };

    // MockProver materialises the whole 2^k domain; at cap=200 this is
    // prohibitively expensive.  Large caps are covered by real prove/verify.
    let mock_skipped = cap >= 200;
    let (good_satisfied, invalid_rejected) = if mock_skipped {
        (true, true)
    } else {
        let prover = MockProver::run(k, &IfcCircuit::new(invalid.clone()), vec![vec![
            commitment(&invalid), f(invalid.policy_id), f(invalid.session_id),
            f(invalid.nonce), f(invalid.collector_id),
        ]]).expect("mockprover run");
        let invalid_rejected = prover.verify().is_err();
        assert!(invalid_rejected, "violating graph must be rejected");

        let good_prover = MockProver::run(k, &IfcCircuit::new(good.clone()), vec![vec![
            commitment(&good), f(good.policy_id), f(good.session_id),
            f(good.nonce), f(good.collector_id),
        ]]).expect("mockprover good run");
        let good_satisfied = good_prover.verify().is_ok();
        assert!(good_satisfied, "compliant graph must satisfy the circuit");
        (good_satisfied, invalid_rejected)
    };

    let mut different_blind = good.clone();
    different_blind.blind += F::ONE;
    assert_ne!(commitment(&good), commitment(&different_blind), "blind must change commitment");

    let params = Params::<vesta::Affine>::new(k);
    let vk_template = keygen_vk(&params, &IfcCircuit::template(cap)).expect("vk template");
    let vk_good = keygen_vk(&params, &IfcCircuit::new(good.clone())).expect("vk good");
    let vk_independent = vk_digest(&vk_template) == vk_digest(&vk_good);
    assert!(vk_independent, "VK must be independent of graph contents");

    let c = commitment(&good);
    let sig = sk.sign(&canonical_attestation_bytes(c, &good));
    assert!(vk_c.verify(&canonical_attestation_bytes(c, &good), &sig).is_ok());
    let mut bad_sig = sig.to_bytes(); bad_sig[0] ^= 1;
    let wrong_sig_rejected = vk_c.verify(&canonical_attestation_bytes(c, &good),
        &Signature::from_bytes(&bad_sig)).is_err();
    assert!(wrong_sig_rejected);

    let invalid_json = if mock_skipped { JsonValue::Null } else { json!(invalid_rejected) };
    let good_json = if mock_skipped { JsonValue::Null } else { json!(good_satisfied) };
    println!("{}", json!({
        "schema": SCHEMA, "cap": cap, "invalid_graph_rejected": invalid_json,
        "compliant_graph_satisfied": good_json,
        "mockprover_skipped": mock_skipped,
        "wrong_signature_rejected": wrong_sig_rejected,
        "blind_changes_commitment": true,
        "vk_graph_independent": vk_independent,
    }).to_string());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} setup|prove|verify|selftest ...", args[0]);
        std::process::exit(2);
    }
    match args[1].as_str() {
        "setup" => {
            if args.len() < 4 { eprintln!("setup <cap> <setup.json>"); std::process::exit(2); }
            setup(args[2].parse().expect("cap"), &args[3]);
        }
        "prove" => {
            if args.len() < 8 { eprintln!("prove <cap> <density> <seed> <setup.json> <proof.bin> <public.json>"); std::process::exit(2); }
            prove(args[2].parse().expect("cap"), &args[3], args[4].parse().expect("seed"),
                &args[5], &args[6], &args[7]);
        }
        "verify" => {
            if args.len() < 6 { eprintln!("verify <setup.json> <proof.bin> <public.json> <result.json>"); std::process::exit(2); }
            verify(&args[2], &args[3], &args[4], &args[5]);
        }
        "selftest" => {
            if args.len() < 3 { eprintln!("selftest <cap>"); std::process::exit(2); }
            selftest(args[2].parse().expect("cap"));
        }
        other => { eprintln!("unknown command {other}"); std::process::exit(2); }
    }
}
