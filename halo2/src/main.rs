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

use std::collections::BTreeMap;
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
use rand::{rngs::{StdRng, SysRng}, RngExt, SeedableRng, TryRng};
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
const CIRCUIT_VERSION: &str = "phase1b1-2-soundness-v1";

#[derive(Clone, Debug)]
struct GNode { typ: u64, label: u64, s: u64 }

#[derive(Clone, Debug)]
struct GEdge { src: usize, dst: usize, kind: u64, active: bool }

/// Attacker-controlled assignment overrides used by Phase 1B.1.2 negative tests.
///
/// A normal witness always carries `MaliciousOverrides::default()`.  Audit cases
/// deliberately set fields that used to be unconstrained advice cells.
#[derive(Clone, Debug, Default)]
struct MaliciousOverrides {
    node_tl: Option<Vec<F>>,
    node_index: Option<Vec<F>>,
    edge_idx: Option<Vec<F>>,
    s_src: Option<Vec<F>>,
    s_dst: Option<Vec<F>>,
    domains: BTreeMap<&'static str, F>,
    empty_zero: Option<F>,
    crossbar_prev: BTreeMap<(usize, usize), [F; 6]>,
}

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
    malicious: MaliciousOverrides,
}

fn host_hash<const L: usize>(words: [F; L]) -> F {
    HostHash::<F, HostSpec, HostLength<L>, 3, 2>::init().hash(words)
}
fn f(value: u64) -> F { F::from(value) }
fn cap_domain(base: u64, cap: usize) -> F { f(base.wrapping_add(cap as u64)) }

fn domain_override(name: &'static str, cap: usize, ov: &MaliciousOverrides) -> F {
    if let Some(v) = ov.domains.get(name) { return *v; }
    match name {
        "node" => cap_domain(DOMAIN_NODE, cap),
        "edge" => cap_domain(DOMAIN_EDGE, cap),
        "empty" => cap_domain(DOMAIN_EMPTY, cap),
        "blind" => cap_domain(DOMAIN_BLIND, cap),
        _ => panic!("unknown domain name"),
    }
}

fn node_tl_value(node: &GNode, pos: usize, ov: &MaliciousOverrides) -> F {
    ov.node_tl.as_ref().and_then(|v| v.get(pos)).copied()
        .unwrap_or_else(|| f(node.typ * 2 + node.label))
}
fn node_pos_value(pos: usize, ov: &MaliciousOverrides) -> F {
    ov.node_index.as_ref().and_then(|v| v.get(pos)).copied()
        .unwrap_or_else(|| f(pos as u64))
}
fn edge_idx_value(e: &GEdge, j: usize, cap: usize, ov: &MaliciousOverrides) -> F {
    ov.edge_idx.as_ref().and_then(|v| v.get(j)).copied()
        .unwrap_or_else(|| f(e.src as u64 * cap as u64 + e.dst as u64))
}

fn node_leaf(node: &GNode, pos: usize, cap: usize, ov: &MaliciousOverrides) -> F {
    host_hash::<3>([domain_override("node", cap, ov), node_tl_value(node, pos, ov),
        node_pos_value(pos, ov)])
}
fn edge_hash(e: &GEdge, j: usize, cap: usize, ov: &MaliciousOverrides) -> F {
    host_hash::<3>([domain_override("edge", cap, ov), edge_idx_value(e, j, cap, ov), f(e.kind)])
}
fn empty_leaf(cap: usize, ov: &MaliciousOverrides) -> F {
    host_hash::<2>([domain_override("empty", cap, ov), ov.empty_zero.unwrap_or(F::ZERO)])
}
fn merge_leaf(left: F, right: F) -> F { host_hash::<2>([left, right]) }

fn merkle_root(w: &Witness) -> F {
    let cap = w.cap;
    let ov = &w.malicious;
    let empty = empty_leaf(cap, ov);
    let mut leaves: Vec<F> = w.nodes.iter().enumerate()
        .map(|(i, n)| node_leaf(n, i, cap, ov)).collect();
    for (j, e) in w.edges.iter().enumerate() {
        leaves.push(if e.active { edge_hash(e, j, cap, ov) } else { empty });
    }
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 { leaves.push(empty); }
        leaves = leaves.chunks_exact(2).map(|p| merge_leaf(p[0], p[1])).collect();
    }
    leaves[0]
}

/// Public randomized commitment: C = H(DOMAIN_BLIND, root_G, blind).
fn commitment(w: &Witness) -> F {
    host_hash::<3>([domain_override("blind", w.cap, &w.malicious), merkle_root(w), w.blind])
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

/// Canonical collector identity shared by Rust and Python:
/// collector_id = big-endian u64 of SHA256(raw Ed25519 public key)[0..8] & (2^63 - 1).
fn collector_id_from_key_bytes(raw: &[u8]) -> u64 {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(raw);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[0..8]);
    u64::from_be_bytes(bytes) & 0x7fff_ffff_ffff_ffff
}

fn make_collector(sk_bytes: [u8; 32]) -> (SigningKey, VerifyingKey, u64) {
    let sk = SigningKey::from_bytes(&sk_bytes);
    let vk = sk.verifying_key();
    let id = collector_id_from_key_bytes(&vk.to_bytes());
    (sk, vk, id)
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
        malicious: MaliciousOverrides::default(),
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
        malicious: MaliciousOverrides::default(),
    }
}

#[derive(Clone, Debug)]
struct IfcConfig {
    q_node: Selector,
    q_edge: Selector,
    q_select: Selector,
    q_cross: Selector,
    q_last: Selector,
    q_first: Selector,
    q_domain: Selector,
    q_zero: Selector,
    node_pos: Column<Fixed>,
    domain_fixed: Column<Fixed>,
    cap_fixed: Column<Fixed>,
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
struct IfcCircuit { witness: Option<Witness>, cap_hint: usize }

impl IfcCircuit {
    fn new(w: Witness) -> Self {
        let cap = w.cap;
        Self { witness: Some(w), cap_hint: cap }
    }
    fn template(cap: usize) -> Self { Self { witness: Some(fixed_template(cap)), cap_hint: cap } }
}

impl Circuit<F> for IfcCircuit {
    type Config = IfcConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { witness: Some(fixed_template(self.cap_hint)), cap_hint: self.cap_hint }
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
        let node_pos = meta.fixed_column();
        let domain_fixed = meta.fixed_column();
        let cap_fixed = meta.fixed_column();
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
        let q_first = meta.selector();
        let q_domain = meta.selector();
        let q_zero = meta.selector();

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
            let leaf_tl = adv(meta, leaf_domain);
            let node_index = adv(meta, node_index);
            let pos = meta.query_fixed(node_pos);
            let one = Expression::Constant(F::ONE);
            let type_sum = b0.clone() + b1.clone() * Expression::Constant(F::from(2))
                + b2.clone() * Expression::Constant(F::from(4));
            let two = Expression::Constant(F::from(2));
            vec![
                q.clone() * label.clone() * (label.clone() - one.clone()),
                q.clone() * s.clone() * (s.clone() - one.clone()),
                q.clone() * b0.clone() * (b0.clone() - one.clone()),
                q.clone() * b1.clone() * (b1.clone() - one.clone()),
                q.clone() * b2.clone() * (b2.clone() - one.clone()),
                q.clone() * b1.clone() * b2.clone(), // exclude types 6,7
                q.clone() * (typ.clone() - type_sum),
                q.clone() * label.clone() * (one.clone() - s.clone()),
                q.clone() * (is_sink_type.clone() - b0 * (one.clone() - b1) * b2),
                q.clone() * (is_low_sink.clone() - is_sink_type.clone() * (one.clone() - label.clone())),
                q.clone() * is_low_sink * s,
                // F1/F2: the committed leaf preimage is the checked type/label,
                // and the committed position is the fixed row position.
                q.clone() * (leaf_tl - (typ * two + label)),
                q.clone() * (node_index - pos),
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
            let leaf_idx = adv(meta, leaf_value);
            let cap = meta.query_fixed(cap_fixed);
            let one = Expression::Constant(F::ONE);
            vec![
                q.clone() * active.clone() * (active.clone() - one.clone()),
                q.clone() * kind.clone() * (kind.clone() - one.clone()),
                q.clone() * (one.clone() - active.clone()) * src.clone(),
                q.clone() * (one.clone() - active.clone()) * dst.clone(),
                q.clone() * (one.clone() - active.clone()) * kind,
                q.clone() * active.clone() * ((src.clone() - dst.clone()) * inv.clone() - one.clone()),
                q.clone() * (one.clone() - active.clone()) * inv,
                q.clone() * active * s_src * (one - s_dst.clone()),
                // F3: committed edge preimage equals the checked endpoints.
                q * (leaf_idx - src * cap - dst),
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
            let first = meta.query_selector(q_first);
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
                q.clone() * (acc_src.clone() - prev_src.clone() - prod_src.clone()),
                q.clone() * (acc_dst.clone() - prev_dst.clone() - prod_dst),
                q.clone() * (acc_sel_src.clone() - prev_sel_src.clone() - sel_src.clone()),
                q.clone() * (acc_sel_dst.clone() - prev_sel_dst.clone() - sel_dst.clone()),
                q.clone() * (acc_idx_src.clone() - prev_idx_src.clone() - idx.clone() * sel_src.clone()),
                q.clone() * (acc_idx_dst.clone() - prev_idx_dst.clone() - idx * sel_dst),
                q.clone() * last.clone() * (acc_sel_src - one.clone()),
                q.clone() * last.clone() * (acc_sel_dst - one),
                // F5: every block starts with six zero accumulators.
                q.clone() * first.clone() * prev_src,
                q.clone() * first.clone() * prev_dst,
                q.clone() * first.clone() * prev_sel_src,
                q.clone() * first.clone() * prev_sel_dst,
                q.clone() * first.clone() * prev_idx_src,
                q * first * prev_idx_dst,
            ]
        });

        // F4: Poseidon domain tags and the empty-leaf padding input are fixed.
        meta.create_gate("domain constants", |meta| {
            let qd = meta.query_selector(q_domain);
            let domain = adv(meta, leaf_domain);
            let fixed = meta.query_fixed(domain_fixed);
            vec![qd * (domain - fixed)]
        });
        meta.create_gate("empty padding zero", |meta| {
            let qz = meta.query_selector(q_zero);
            let value = adv(meta, leaf_value);
            vec![qz * value]
        });

        IfcConfig {
            q_node, q_edge, q_select, q_cross, q_last, q_first, q_domain, q_zero,
            node_pos, domain_fixed, cap_fixed,
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
                    region.assign_fixed(|| "node_pos", config.node_pos, i,
                        || Value::known(f(i as u64)))?;
                    let node = &w.nodes[i];
                    index_cells.push(region.assign_advice(|| "idx", config.node_index, i,
                        || Value::known(node_pos_value(i, &w.malicious)))?);
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
                        || Value::known(node_tl_value(node, i, &w.malicious)))?);
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
                        region.assign_fixed(|| "cap", config.cap_fixed, j,
                            || Value::known(f(cap as u64)))?;
                        let e = &w.edges[j];
                        srcs.push(region.assign_advice(|| "src", config.src, j,
                            || Value::known(f(e.src as u64)))?);
                        dsts.push(region.assign_advice(|| "dst", config.dst, j,
                            || Value::known(f(e.dst as u64)))?);
                        kinds.push(region.assign_advice(|| "kind", config.kind, j,
                            || Value::known(f(e.kind)))?);
                        actives.push(region.assign_advice(|| "active", config.active, j,
                            || Value::known(f(e.active as u64)))?);
                        let s_src_val = w.malicious.s_src.as_ref().and_then(|v| v.get(j)).copied()
                            .unwrap_or_else(|| f(w.nodes[if e.active { e.src } else { 0 }].s));
                        let s_dst_val = w.malicious.s_dst.as_ref().and_then(|v| v.get(j)).copied()
                            .unwrap_or_else(|| f(w.nodes[if e.active { e.dst } else { 0 }].s));
                        s_srcs.push(region.assign_advice(|| "s_src", config.s_src, j,
                            || Value::known(s_src_val))?);
                        s_dsts.push(region.assign_advice(|| "s_dst", config.s_dst, j,
                            || Value::known(s_dst_val))?);
                        let delta = f(e.src as u64) - f(e.dst as u64);
                        let inv = if !e.active || bool::from(delta.is_zero()) {
                            F::ZERO
                        } else {
                            delta.invert().unwrap()
                        };
                        region.assign_advice(|| "inv", config.inv_delta, j, || Value::known(inv))?;
                        leaf_idx.push(region.assign_advice(|| "leaf_idx", config.leaf_value, j,
                            || Value::known(edge_idx_value(e, j, cap, &w.malicious)))?);
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
                        if i == 0 { config.q_first.enable(&mut region, row)?; }
                        if i == cap - 1 { config.q_last.enable(&mut region, row)?; }
                        if let Some(v) = w.malicious.crossbar_prev.get(&(j, i)) {
                            prev_vals = (v[0], v[1], v[2], v[3], v[4], v[5]);
                        }
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
            assign_domain(&config, &mut region, 0, cap_domain(DOMAIN_NODE, cap),
                domain_override("node", cap, &w.malicious)))?;
        for i in 0..cap {
            leaves.push(hash_words::<_, 3>(&config, layouter.namespace(|| format!("node_leaf_{i}")),
                [node_domain.clone(), node_tl_cells[i].clone(), index_cells[i].clone()])?);
        }
        let edge_domain = layouter.assign_region(|| "edge domain", |mut region|
            assign_domain(&config, &mut region, 0, cap_domain(DOMAIN_EDGE, cap),
                domain_override("edge", cap, &w.malicious)))?;
        let mut edge_hashes = Vec::with_capacity(edge_cap);
        for j in 0..edge_cap {
            edge_hashes.push(hash_words::<_, 3>(&config, layouter.namespace(|| format!("edge_hash_{j}")),
                [edge_domain.clone(), edge_idx_cells[j].clone(), kind_cells[j].clone()])?);
        }
        let empty_cell = empty_leaf_cell(&config, &mut layouter, cap, &w.malicious)?;
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
                        || Value::known(edge_hash(&w.edges[j], j, cap, &w.malicious)))?;
                    region.constrain_equal(hash_copy.cell(), edge_hashes[j].cell())?;
                    let empty_copy = region.assign_advice(|| "sel_empty_hash", config.sel_empty_hash, j,
                        || Value::known(empty_leaf(cap, &w.malicious)))?;
                    region.constrain_equal(empty_copy.cell(), empty_cell.cell())?;
                    let val = if w.edges[j].active {
                        edge_hash(&w.edges[j], j, cap, &w.malicious)
                    } else { empty_leaf(cap, &w.malicious) };
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
            assign_domain(&config, &mut region, 0, cap_domain(DOMAIN_BLIND, cap),
                domain_override("blind", cap, &w.malicious)))?;
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

fn assign_domain(config: &IfcConfig, region: &mut Region<'_, F>, offset: usize,
    fixed_value: F, advice_value: F) -> Result<AssignedCell<F, F>, Error> {
    config.q_domain.enable(region, offset)?;
    region.assign_fixed(|| "domain_fixed", config.domain_fixed, offset,
        || Value::known(fixed_value))?;
    region.assign_advice(|| "domain", config.leaf_domain, offset, || Value::known(advice_value))
}

fn empty_leaf_cell(config: &IfcConfig, layouter: &mut impl Layouter<F>, cap: usize,
    ov: &MaliciousOverrides) -> Result<AssignedCell<F, F>, Error> {
    let domain = layouter.assign_region(|| "empty leaf domain", |mut region|
        assign_domain(config, &mut region, 0, cap_domain(DOMAIN_EMPTY, cap),
            domain_override("empty", cap, ov)))?;
    let zero = layouter.assign_region(|| "empty leaf zero", |mut region| {
        config.q_zero.enable(&mut region, 0)?;
        assign_value(&mut region, config.leaf_value, 0, ov.empty_zero.unwrap_or(F::ZERO))
    })?;
    hash_words::<_, 2>(config, layouter.namespace(|| "empty leaf"), [domain, zero])
}

fn hash_words<L: Layouter<F>, const N: usize>(config: &IfcConfig, mut layouter: L,
    words: [AssignedCell<F, F>; N]) -> Result<AssignedCell<F, F>, Error> {
    let chip = Pow5Chip::construct(config.poseidon.clone());
    let hasher = GadgetHash::<_, _, P128Pow5T3, ConstantLength<N>, 3, 2>::init(
        chip, layouter.namespace(|| "init"))?;
    hasher.hash(layouter.namespace(|| "hash"), words)
}

fn attack_base(cap: usize) -> Witness {
    let nodes = (0..cap).map(|i| GNode {
        typ: if i == cap - 1 { T_PUBLIC_SINK } else { T_PUBLIC_SOURCE },
        label: 0,
        s: 0,
    }).collect();
    Witness {
        cap, edge_cap: 2 * cap, nodes,
        edges: vec![GEdge { src: 0, dst: 0, kind: 0, active: false }; 2 * cap],
        policy_id: 7, session_id: 20261126, nonce: 4242,
        collector_id: make_collector([0x11; 32]).2,
        blind: f(0x1234_5678_9ABC_DEF0),
        malicious: MaliciousOverrides::default(),
    }
}

fn illegal_attack_base(cap: usize) -> Witness {
    let mut w = attack_base(cap);
    for i in 0..cap / 2 {
        w.nodes[i] = GNode { typ: T_CONFIDENTIAL_SOURCE, label: 1, s: 1 };
    }
    w.edges[0] = GEdge { src: 0, dst: cap - 1, kind: 0, active: true };
    w
}

fn attack_witness(cap: usize, case: &str) -> Witness {
    let mut w = attack_base(cap);
    match case {
        "compliant" => {}
        "illegal_ifc" => w = illegal_attack_base(cap),
        "node_tl_mismatch" => {
            w.nodes[0] = GNode { typ: T_CONFIDENTIAL_SOURCE, label: 1, s: 1 };
            w.malicious.node_tl = Some(vec![f(0); cap]);
        }
        "node_position_mismatch" => {
            w.malicious.node_index = Some((0..cap).map(|i| f(((i + 1) % cap) as u64)).collect());
        }
        "edge_idx_mismatch" => {
            let a = cap / 2;
            w.edges[0] = GEdge { src: a, dst: a + 1, kind: 0, active: true };
            let mut idx = vec![f(0); 2 * cap];
            idx[0] = f(((a + 2) * cap + (a + 3)) as u64);
            w.malicious.edge_idx = Some(idx);
        }
        "crossbar_prev_src" => {
            w = illegal_attack_base(cap);
            w.malicious.crossbar_prev.insert((0, 0), [F::ONE.neg(), F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO]);
            w.malicious.s_src = Some(vec![F::ZERO; 2 * cap]);
        }
        "crossbar_prev_dst" => {
            w = illegal_attack_base(cap);
            w.malicious.crossbar_prev.insert((0, 0), [F::ZERO, F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO]);
            w.malicious.s_dst = Some(vec![F::ONE; 2 * cap]);
        }
        "crossbar_prev_sel_src" => {
            w = illegal_attack_base(cap);
            w.malicious.crossbar_prev.insert((0, 0), [F::ZERO, F::ZERO, F::ONE.neg(), F::ZERO, F::ZERO, F::ZERO]);
        }
        "crossbar_prev_sel_dst" => {
            w = illegal_attack_base(cap);
            w.malicious.crossbar_prev.insert((0, 0), [F::ZERO, F::ZERO, F::ZERO, F::ONE, F::ZERO, F::ZERO]);
        }
        "crossbar_prev_idx_src" => {
            w = illegal_attack_base(cap);
            w.edges[0].src = 1;
            w.malicious.crossbar_prev.insert((0, 0), [F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ONE, F::ZERO]);
            w.malicious.s_src = Some(vec![f(w.nodes[1].s); 2 * cap]);
        }
        "crossbar_prev_idx_dst" => {
            w = illegal_attack_base(cap);
            w.malicious.crossbar_prev.insert((0, 0), [F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ONE]);
        }
        "domain_node" => {
            w.malicious.domains.insert("node", cap_domain(DOMAIN_NODE, cap) + F::ONE);
        }
        "domain_edge" => {
            w.malicious.domains.insert("edge", cap_domain(DOMAIN_EDGE, cap) + F::ONE);
        }
        "domain_empty" => {
            w.malicious.domains.insert("empty", cap_domain(DOMAIN_EMPTY, cap) + F::ONE);
        }
        "domain_blind" => {
            w.malicious.domains.insert("blind", cap_domain(DOMAIN_BLIND, cap) + F::ONE);
        }
        "empty_zero" => w.malicious.empty_zero = Some(F::ONE),
        _ => panic!("unknown attack case {case}"),
    }
    w
}

fn attack_case_names() -> Vec<&'static str> {
    vec![
        "compliant", "illegal_ifc",
        "node_tl_mismatch", "node_position_mismatch", "edge_idx_mismatch",
        "crossbar_prev_src", "crossbar_prev_dst", "crossbar_prev_sel_src",
        "crossbar_prev_sel_dst", "crossbar_prev_idx_src", "crossbar_prev_idx_dst",
        "domain_node", "domain_edge", "domain_empty", "domain_blind", "empty_zero",
    ]
}

fn attack_suite(cap: usize) {
    let k = k_for_cap(cap);
    let mut cases = Vec::new();
    for name in attack_case_names() {
        let w = attack_witness(cap, name);
        let instance = vec![commitment(&w), f(w.policy_id), f(w.session_id), f(w.nonce), f(w.collector_id)];
        let prover = MockProver::run(k, &IfcCircuit::new(w), vec![instance])
            .expect("MockProver::run on attack case");
        let err = prover.verify().err().map(|e| format!("{e:?}"));
        cases.push(json!({
            "case": name,
            "satisfied": err.is_none(),
            "first_error": err.map(|s| s.chars().take(400).collect::<String>()),
        }));
    }
    println!("{}", json!({ "schema": SCHEMA, "phase": "phase1b1-2", "cap": cap, "cases": cases }));
}

fn prove_attack(cap: usize, case: &str, setup_path: &str, proof_path: &str, public_path: &str) {
    let setup = load_setup(setup_path);
    assert_eq!(setup["schema"].as_str(), Some(SCHEMA), "setup schema mismatch");
    let k = setup["k"].as_u64().unwrap() as u32;
    assert_eq!(setup["vk_hash"].as_str().unwrap(), to_hex(expected_vk_hash(cap, k)), "vk hash mismatch");
    let w = attack_witness(cap, case);
    let c = commitment(&w);
    let instance = vec![c, f(w.policy_id), f(w.session_id), f(w.nonce), f(w.collector_id)];
    let (sk, vk_collector, _) = make_collector([0x11; 32]);
    let sig = sk.sign(&canonical_attestation_bytes(c, &w));
    let (params, _, pk) = keygen_with_k(cap, k);
    assert_eq!(setup["vk_digest"].as_str().unwrap(), to_hex_bytes(&vk_digest(pk.get_vk())),
        "prover VK does not match setup-pinned VK");
    let inst_refs: Vec<&[F]> = vec![&instance[..]];
    let all_instances: Vec<&[&[F]]> = vec![&inst_refs];
    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    let result = create_proof(&params, &pk, &[IfcCircuit::new(w.clone())], &all_instances,
        StdRng::seed_from_u64(0x5EED_1234), &mut transcript);
    match result {
        Ok(()) => {
            let proof = transcript.finalize();
            fs::write(proof_path, &proof).expect("write attack proof");
            let public = json!({
                "schema": SCHEMA, "circuit_version": CIRCUIT_VERSION, "cap": cap,
                "commitment": to_hex(c), "policy_id": w.policy_id, "session_id": w.session_id,
                "nonce": w.nonce, "collector_id": w.collector_id,
                "collector_public_key_claimed": to_hex_bytes(&vk_collector.to_bytes()),
                "collector_signature": to_hex_bytes(&sig.to_bytes()),
                "k": k, "proof_bytes": proof.len(),
            });
            fs::write(public_path, serde_json::to_vec_pretty(&public).unwrap()).expect("write attack public");
            println!("{}", json!({ "case": case, "create_proof_ok": true, "proof_bytes": proof.len() }));
        }
        Err(e) => {
            println!("{}", json!({ "case": case, "create_proof_ok": false,
                "reason": format!("{e:?}").chars().take(400).collect::<String>() }));
        }
    }
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

/// Sample a 254-bit blind from the operating-system CSPRNG.
/// The top two bits are cleared so the canonical repr is always in field.
fn random_blind() -> F {
    let mut bytes = [0u8; 32];
    SysRng.try_fill_bytes(&mut bytes).expect("OS CSPRNG");
    // Pallas base-field repr is little-endian: bytes[31] holds the high bits.
    bytes[31] &= 0x3f;
    Option::<F>::from(F::from_repr(bytes)).expect("CSPRNG blind must be in field")
}

fn prove(cap: usize, density: &str, seed: u64, setup_path: &str, proof_path: &str,
    public_path: &str, meta_path: &str) {
    let setup = load_setup(setup_path);
    assert_eq!(setup["schema"].as_str(), Some(SCHEMA), "setup schema mismatch");
    let k = setup["k"].as_u64().unwrap() as u32;
    assert_eq!(setup["vk_hash"].as_str().unwrap(), to_hex(expected_vk_hash(cap, k)), "vk hash mismatch");

    let (sk, _vk_collector, collector_id) = make_collector([0x11; 32]);
    let mut w = make_compliant_witness(cap, density, seed, collector_id);
    w.blind = random_blind();
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
        rand::make_rng::<StdRng>(), &mut transcript).expect("create_proof");
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
        "collector_signature": to_hex_bytes(&sig.to_bytes()),
        "k": k,
        "prove_ms": prove_ms,
        "proof_bytes": proof.len(),
    });
    fs::write(public_path, serde_json::to_vec_pretty(&public).unwrap()).expect("write public");
    let meta = json!({
        "schema": SCHEMA,
        "cap": cap,
        "density": density,
        "active_edges": w.edges.iter().filter(|e| e.active).count(),
        "note": "Benchmark-private metadata; never part of proof public inputs."
    });
    fs::write(meta_path, serde_json::to_vec_pretty(&meta).unwrap()).expect("write private meta");
    println!("{}", serde_json::to_string(&public).unwrap());
}

fn finish_verify(out: &str, result: JsonValue, reason: Option<&str>) {
    let mut result = result;
    if let Some(r) = reason {
        result["reason"] = json!(r);
    }
    fs::write(out, serde_json::to_vec_pretty(&result).unwrap()).expect("write verify result");
    println!("{}", serde_json::to_string(&result).unwrap());
}

fn verify(setup_path: &str, allowlist_path: &str, proof_path: &str, public_path: &str, out: &str) {
    let setup = load_setup(setup_path);
    let public: JsonValue = serde_json::from_slice(&fs::read(public_path).expect("read public"))
        .expect("parse public");
    let allowlist: JsonValue = serde_json::from_slice(&fs::read(allowlist_path).expect("read allowlist"))
        .expect("parse allowlist");
    let mut result = json!({
        "schema": SCHEMA, "accepted": false,
        "verifier_read_graph": false,
        "verifier_called_keygen_vk_on_witness": false,
        "collector_key_source": "independent_allowlist",
        "note": "pure_verify_ms excludes VK rebuild and signature verification."
    });

    if setup["schema"].as_str() != Some(SCHEMA)
        || public["schema"].as_str() != Some(SCHEMA)
        || allowlist["schema"].as_str() != Some("collector-allowlist-v1") {
        finish_verify(out, result, Some("schema mismatch"));
        return;
    }
    let cap = setup["cap"].as_u64().unwrap() as usize;
    let k = setup["k"].as_u64().unwrap() as u32;
    if setup["vk_hash"].as_str().unwrap() != to_hex(expected_vk_hash(cap, k)) {
        finish_verify(out, result, Some("vk hash mismatch"));
        return;
    }
    let cid = match public.get("collector_id").and_then(|v| v.as_u64()) {
        Some(v) => v,
        None => { finish_verify(out, result, Some("missing collector_id")); return; }
    };
    result["cap"] = json!(cap);
    result["k"] = json!(k);

    let entry = allowlist["collectors"].as_array()
        .and_then(|xs| xs.iter().find(|e| e["collector_id"].as_u64() == Some(cid)));
    let entry = match entry {
        Some(v) => v,
        None => { finish_verify(out, result, Some("collector_id not in trusted allowlist")); return; }
    };
    let pk_bytes = match hex_bytes(entry["collector_public_key"].as_str().unwrap_or(""), 32) {
        Some(v) => v,
        None => { finish_verify(out, result, Some("invalid allowlist public key")); return; }
    };
    let derived_id = collector_id_from_key_bytes(&pk_bytes);
    if derived_id != cid || entry["collector_id"].as_u64().unwrap() != derived_id {
        finish_verify(out, result, Some("collector_id does not match allowlisted public key"));
        return;
    }
    // Any collector key supplied inside public.json is deliberately ignored.
    let mut pk_arr = [0u8; 32]; pk_arr.copy_from_slice(&pk_bytes);
    let collector_vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(v) => v,
        Err(_) => { finish_verify(out, result, Some("invalid Ed25519 verifying key")); return; }
    };
    let sig_bytes = match hex_bytes(public["collector_signature"].as_str().unwrap_or(""), 64) {
        Some(v) => v,
        None => { finish_verify(out, result, Some("invalid signature encoding")); return; }
    };
    let mut sig_arr = [0u8; 64]; sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let commitment_hex = public["commitment"].as_str().unwrap();
    let attestation = format!(
        "{}|{}|{}|{}|{}", commitment_hex,
        public["policy_id"].as_u64().unwrap(), public["session_id"].as_u64().unwrap(),
        public["nonce"].as_u64().unwrap(), cid,
    ).into_bytes();
    let t_sig = Instant::now();
    let sig_ok = collector_vk.verify(&attestation, &sig).is_ok();
    result["sig_verify_ms"] = json!(t_sig.elapsed().as_millis());
    if !sig_ok {
        finish_verify(out, result, Some("collector signature rejected"));
        return;
    }
    result["collector_signature_verified"] = json!(true);

    let instance = vec![
        from_hex(commitment_hex).expect("parse commitment"),
        f(public["policy_id"].as_u64().unwrap()),
        f(public["session_id"].as_u64().unwrap()),
        f(public["nonce"].as_u64().unwrap()),
        f(cid),
    ];
    let proof = fs::read(proof_path).expect("read proof");
    let params = Params::<vesta::Affine>::new(k);
    let t_vk = Instant::now();
    let vk = keygen_vk(&params, &IfcCircuit::template(cap)).expect("keygen_vk fixed template");
    result["vk_rebuild_ms"] = json!(t_vk.elapsed().as_millis());
    if setup["vk_digest"].as_str().unwrap() != to_hex_bytes(&vk_digest(&vk)) {
        finish_verify(out, result, Some("verifier VK does not match setup digest"));
        return;
    }

    let inst_refs: Vec<&[F]> = vec![&instance[..]];
    let all_instances: Vec<&[&[F]]> = vec![&inst_refs];
    let t_verify = Instant::now();
    let proof_ok = verify_proof(&params, &vk, SingleVerifier::new(&params), &all_instances,
        &mut Blake2bRead::init(&proof[..])).is_ok();
    result["pure_verify_ms"] = json!(t_verify.elapsed().as_millis());
    if !proof_ok {
        finish_verify(out, result, Some("verify_proof rejected"));
        return;
    }

    let mut bad = instance.clone();
    bad[3] += F::ONE;
    let bad_refs: Vec<&[F]> = vec![&bad[..]];
    let bad_all: Vec<&[&[F]]> = vec![&bad_refs];
    let wrong_nonce_rejected = verify_proof(&params, &vk, SingleVerifier::new(&params), &bad_all,
        &mut Blake2bRead::init(&proof[..])).is_err();
    result["wrong_nonce_rejected"] = json!(wrong_nonce_rejected);
    if !wrong_nonce_rejected {
        finish_verify(out, result, Some("wrong nonce was not rejected"));
        return;
    }
    result["accepted"] = json!(true);
    finish_verify(out, result, None);
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

    let without_witnesses_keeps_cap =
        IfcCircuit::template(cap).without_witnesses().witness.as_ref().unwrap().cap == cap;
    assert!(without_witnesses_keeps_cap, "without_witnesses must preserve cap");
    let collector_id_stable = collector_id == collector_id_from_key_bytes(&vk_c.to_bytes());
    assert!(collector_id_stable);

    let invalid_json = if mock_skipped { JsonValue::Null } else { json!(invalid_rejected) };
    let good_json = if mock_skipped { JsonValue::Null } else { json!(good_satisfied) };
    println!("{}", json!({
        "schema": SCHEMA, "cap": cap, "invalid_graph_rejected": invalid_json,
        "compliant_graph_satisfied": good_json,
        "mockprover_skipped": mock_skipped,
        "wrong_signature_rejected": wrong_sig_rejected,
        "blind_changes_commitment": true,
        "vk_graph_independent": vk_independent,
        "without_witnesses_keeps_cap": without_witnesses_keeps_cap,
        "collector_id_rule_stable": collector_id_stable,
    }).to_string());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} setup|prove|verify|selftest|attack|prove-attack ...", args[0]);
        std::process::exit(2);
    }
    match args[1].as_str() {
        "setup" => {
            if args.len() < 4 { eprintln!("setup <cap> <setup.json>"); std::process::exit(2); }
            setup(args[2].parse().expect("cap"), &args[3]);
        }
        "prove" => {
            if args.len() < 9 { eprintln!("prove <cap> <density> <seed> <setup.json> <proof.bin> <public.json> <meta.json>"); std::process::exit(2); }
            prove(args[2].parse().expect("cap"), &args[3], args[4].parse().expect("seed"),
                &args[5], &args[6], &args[7], &args[8]);
        }
        "verify" => {
            if args.len() < 7 { eprintln!("verify <setup.json> <allowlist.json> <proof.bin> <public.json> <result.json>"); std::process::exit(2); }
            verify(&args[2], &args[3], &args[4], &args[5], &args[6]);
        }
        "selftest" => {
            if args.len() < 3 { eprintln!("selftest <cap>"); std::process::exit(2); }
            selftest(args[2].parse().expect("cap"));
        }
        "attack" => {
            if args.len() < 3 { eprintln!("attack <cap>"); std::process::exit(2); }
            attack_suite(args[2].parse().expect("cap"));
        }
        "prove-attack" => {
            if args.len() < 7 { eprintln!("prove-attack <cap> <case> <setup.json> <proof.bin> <public.json>"); std::process::exit(2); }
            prove_attack(args[2].parse().expect("cap"), &args[3], &args[4], &args[5], &args[6]);
        }
        other => { eprintln!("unknown command {other}"); std::process::exit(2); }
    }
}
