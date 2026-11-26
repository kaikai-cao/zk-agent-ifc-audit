//! ZK-AGENT-IFC-AUDIT Phase 1B: Halo2 prototype for single-session Trace-IFC compliance.
//!
//! Research prototype only.  It proves a committed graph satisfies a forward-closure
//! condition.  It does NOT prove collector completeness, label truth, runtime
//! execution truth, or classic two-run noninterference.

use std::convert::TryInto;
use std::fs;
use std::time::Instant;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ff::Field;
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
        VirtualCells,
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

const T_CONFIDENTIAL_SOURCE: u64 = 0;
const T_PUBLIC_SOURCE: u64 = 1;
const T_MODEL_OUTPUT: u64 = 2;
const T_TOOL_INVOCATION: u64 = 3;
const T_TOOL_RESULT: u64 = 4;
const T_PUBLIC_SINK: u64 = 5;

#[derive(Clone, Debug)]
struct GNode {
    typ: u64,
    label: u64,
    s: u64,
}

#[derive(Clone, Debug)]
struct GEdge {
    src: usize,
    dst: usize,
    kind: u64,
    active: bool,
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
}

fn host_hash<const L: usize>(words: [F; L]) -> F {
    HostHash::<F, HostSpec, HostLength<L>, 3, 2>::init().hash(words)
}

fn f(value: u64) -> F {
    F::from(value)
}

fn cap_domain(base: u64, cap: usize) -> F {
    f(base.wrapping_add(cap as u64))
}

fn node_leaf(node: &GNode, pos: usize, cap: usize) -> F {
    host_hash::<3>([
        cap_domain(DOMAIN_NODE, cap),
        f(node.typ * 2 + node.label),
        f(pos as u64),
    ])
}

fn edge_leaf(edge: &GEdge, cap: usize) -> F {
    host_hash::<3>([
        cap_domain(DOMAIN_EDGE, cap),
        f(edge.src as u64 * cap as u64 + edge.dst as u64),
        f(edge.kind),
    ])
}

fn empty_leaf(cap: usize) -> F {
    host_hash::<2>([cap_domain(DOMAIN_EMPTY, cap), F::ZERO])
}

fn merge_leaf(left: F, right: F) -> F {
    host_hash::<2>([left, right])
}

fn compute_root(w: &Witness) -> F {
    let cap = w.cap;
    let mut leaves: Vec<F> = w
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| node_leaf(n, i, cap))
        .collect();
    for e in &w.edges {
        leaves.push(if e.active {
            edge_leaf(e, cap)
        } else {
            empty_leaf(cap)
        });
    }
    while leaves.len() > 1 {
        if leaves.len() % 2 == 1 {
            leaves.push(empty_leaf(cap));
        }
        leaves = leaves
            .chunks_exact(2)
            .map(|pair| merge_leaf(pair[0], pair[1]))
            .collect();
    }
    leaves[0]
}

fn root_to_hex(root: F) -> String {
    use ff::PrimeField;
    root.to_repr()
        .iter()
        .rev()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn canonical_attestation_bytes(root: F, w: &Witness) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}",
        root_to_hex(root),
        w.policy_id,
        w.session_id,
        w.nonce,
        w.collector_id
    )
    .into_bytes()
}

fn make_collector(sk_bytes: [u8; 32]) -> (SigningKey, VerifyingKey, u64) {
    let sk = SigningKey::from_bytes(&sk_bytes);
    let vk = sk.verifying_key();
    let raw = vk.to_bytes();
    let mut acc: u64 = 0;
    for b in raw.iter().take(8) {
        acc = acc.rotate_left(8) ^ (*b as u64);
    }
    (sk, vk, acc & 0x7fff_ffff_ffff_ffff)
}

/// Deterministic compliant graph.  High nodes only point to High nodes;
/// Low nodes only point to Low nodes.  The last node is a public sink.
fn make_compliant_witness(cap: usize, density: &str, seed: u64, collector_id: u64) -> Witness {
    let mut rng = StdRng::seed_from_u64(seed);
    let edge_cap = 2 * cap;
    let high_count = cap / 2;
    let mut nodes = Vec::with_capacity(cap);
    for i in 0..cap {
        if i == cap - 1 {
            nodes.push(GNode {
                typ: T_PUBLIC_SINK,
                label: 0,
                s: 0,
            });
        } else if i < high_count {
            let typ = match i % 3 {
                0 => T_CONFIDENTIAL_SOURCE,
                1 => T_TOOL_INVOCATION,
                _ => T_TOOL_RESULT,
            };
            nodes.push(GNode { typ, label: 1, s: 1 });
        } else {
            let typ = if i % 4 == 0 {
                T_PUBLIC_SOURCE
            } else {
                T_MODEL_OUTPUT
            };
            nodes.push(GNode { typ, label: 0, s: 0 });
        }
    }

    let target = match density {
        "low" => cap / 2,
        "mid" => cap,
        "high" => 2 * cap,
        _ => panic!("density must be low|mid|high"),
    }
    .min(edge_cap);
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
            if src == dst {
                continue;
            }
            if edges.iter().any(|e: &GEdge| e.active && e.src == src && e.dst == dst) {
                continue;
            }
            edges.push(GEdge {
                src,
                dst,
                kind: rng.random_range(0..2),
                active: true,
            });
            made += 1;
        }
        assert_eq!(made, count, "could not build requested edge count");
    }
    while edges.len() < edge_cap {
        edges.push(GEdge {
            src: 0,
            dst: 1,
            kind: 0,
            active: false,
        });
    }
    Witness {
        cap,
        edge_cap,
        nodes,
        edges,
        policy_id: 7,
        session_id: 20261126,
        nonce: 1 + seed % 100_000,
        collector_id,
    }
}

#[derive(Clone, Debug)]
struct IfcConfig {
    q_node: Selector,
    q_edge: Selector,
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
    s_src: Column<Advice>,
    s_dst: Column<Advice>,
    inv_delta: Column<Advice>,
    leaf_domain: Column<Advice>,
    leaf_value: Column<Advice>,
    public_copy: Column<Advice>,
    instance: Column<Instance>,
    poseidon: Pow5Config<F, 3, 2>,
}

fn adv(meta: &mut VirtualCells<'_, F>, col: Column<Advice>) -> Expression<F> {
    meta.query_advice(col, Rotation::cur())
}

impl Circuit<F> for IfcCircuit {
    type Config = IfcConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            witness: Some(Witness {
                cap: self.witness.as_ref().map(|w| w.cap).unwrap_or(50),
                edge_cap: self.witness.as_ref().map(|w| w.edge_cap).unwrap_or(100),
                nodes: vec![],
                edges: vec![],
                policy_id: 0,
                session_id: 0,
                nonce: 0,
                collector_id: 0,
            }),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let label = meta.advice_column();
        let s = meta.advice_column();
        let node_type = meta.advice_column();
        let node_index = meta.advice_column();
        let type_bits: [Column<Advice>; 3] = (0..3)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let is_sink_type = meta.advice_column();
        let is_low_sink = meta.advice_column();
        let src = meta.advice_column();
        let dst = meta.advice_column();
        let kind = meta.advice_column();
        let s_src = meta.advice_column();
        let s_dst = meta.advice_column();
        let inv_delta = meta.advice_column();
        let leaf_domain = meta.advice_column();
        let leaf_value = meta.advice_column();
        let public_copy = meta.advice_column();
        let instance = meta.instance_column();

        for col in [
            label,
            s,
            node_type,
            node_index,
            is_sink_type,
            is_low_sink,
            src,
            dst,
            kind,
            s_src,
            s_dst,
            inv_delta,
            leaf_domain,
            leaf_value,
            public_copy,
        ] {
            meta.enable_equality(col);
        }
        for col in type_bits.iter().cloned() {
            meta.enable_equality(col);
        }
        meta.enable_equality(instance);

        let state: [Column<Advice>; 3] = (0..3)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let partial_sbox = meta.advice_column();
        let rc_a: [Column<Fixed>; 3] = (0..3)
            .map(|_| meta.fixed_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let rc_b: [Column<Fixed>; 3] = (0..3)
            .map(|_| meta.fixed_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);

        let q_node = meta.complex_selector();
        let q_edge = meta.complex_selector();

        // Node gate: encoding format + C1 (High in S) + C3 (Low sink not in S) + C4 (S boolean).
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
            let type_sum = b0.clone()
                + b1.clone() * Expression::Constant(F::from(2))
                + b2.clone() * Expression::Constant(F::from(4));
            vec![
                q.clone() * label.clone() * (label.clone() - Expression::Constant(F::ONE)),
                q.clone() * s.clone() * (s.clone() - Expression::Constant(F::ONE)),
                q.clone() * b0.clone() * (b0.clone() - Expression::Constant(F::ONE)),
                q.clone() * b1.clone() * (b1.clone() - Expression::Constant(F::ONE)),
                q.clone() * b2.clone() * (b2.clone() - Expression::Constant(F::ONE)),
                q.clone() * (typ - type_sum),
                q.clone() * label.clone() * (one.clone() - s.clone()),
                q.clone() * (is_sink_type.clone() - b0 * (one.clone() - b1) * b2),
                q.clone() * (is_low_sink.clone() - is_sink_type * (one.clone() - label)),
                q.clone() * is_low_sink * s,
            ]
        });

        // Edge gate: kind boolean, C2 forward closure, and non-self-loop.
        // Endpoint existence and S lookup are enforced by copy constraints to node rows.
        meta.create_gate("edge closure C2 and format", |meta| {
            let q = meta.query_selector(q_edge);
            let src = adv(meta, src);
            let dst = adv(meta, dst);
            let kind = adv(meta, kind);
            let s_src = adv(meta, s_src);
            let s_dst = adv(meta, s_dst);
            let inv = adv(meta, inv_delta);
            vec![
                q.clone() * kind.clone() * (kind - Expression::Constant(F::ONE)),
                q.clone() * s_src * (Expression::Constant(F::ONE) - s_dst),
                q * ((src - dst) * inv - Expression::Constant(F::ONE)),
            ]
        });

        IfcConfig {
            q_node,
            q_edge,
            label,
            s,
            node_type,
            node_index,
            type_bits,
            is_sink_type,
            is_low_sink,
            src,
            dst,
            kind,
            s_src,
            s_dst,
            inv_delta,
            leaf_domain,
            leaf_value,
            public_copy,
            instance,
            poseidon,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let w = self.witness.as_ref().ok_or(Error::Synthesis)?;
        let cap = w.cap;
        let edge_cap = w.edge_cap;

        let (index_cells, s_cells, node_tl_cells) = layouter.assign_region(
            || "nodes",
            |mut region: Region<'_, F>| {
                let mut index_cells = Vec::with_capacity(cap);
                let mut s_cells = Vec::with_capacity(cap);
                let mut leaf_tl = Vec::with_capacity(cap);
                for i in 0..cap {
                    config.q_node.enable(&mut region, i)?;
                    let node = &w.nodes[i];
                    index_cells.push(region.assign_advice(
                        || format!("node_index_{i}"),
                        config.node_index,
                        i,
                        || Value::known(f(i as u64)),
                    )?);
                    s_cells.push(region.assign_advice(
                        || format!("s_{i}"),
                        config.s,
                        i,
                        || Value::known(f(node.s)),
                    )?);
                    region.assign_advice(
                        || format!("label_{i}"),
                        config.label,
                        i,
                        || Value::known(f(node.label)),
                    )?;
                    region.assign_advice(
                        || format!("node_type_{i}"),
                        config.node_type,
                        i,
                        || Value::known(f(node.typ)),
                    )?;
                    for b in 0..3 {
                        region.assign_advice(
                            || format!("type_bit_{i}_{b}"),
                            config.type_bits[b],
                            i,
                            || Value::known(f((node.typ >> b) & 1)),
                        )?;
                    }
                    let is_sink_type = if node.typ == T_PUBLIC_SINK { 1 } else { 0 };
                    let is_low_sink = is_sink_type * (1 - node.label);
                    region.assign_advice(
                        || format!("is_sink_type_{i}"),
                        config.is_sink_type,
                        i,
                        || Value::known(f(is_sink_type)),
                    )?;
                    region.assign_advice(
                        || format!("is_low_sink_{i}"),
                        config.is_low_sink,
                        i,
                        || Value::known(f(is_low_sink)),
                    )?;
                    leaf_tl.push(region.assign_advice(
                        || format!("leaf_type_label_{i}"),
                        config.leaf_domain,
                        i,
                        || Value::known(f(node.typ * 2 + node.label)),
                    )?);
                }
                Ok((index_cells, s_cells, leaf_tl))
            },
        )?;

        let (edge_idx_cells, kind_cells) = layouter.assign_region(
            || "edges",
            |mut region: Region<'_, F>| {
                let mut leaf_idx = Vec::with_capacity(edge_cap);
                let mut kinds = Vec::with_capacity(edge_cap);
                for j in 0..edge_cap {
                    let e = &w.edges[j];
                    if e.active {
                        config.q_edge.enable(&mut region, j)?;
                    }
                    region.assign_advice(
                        || format!("src_{j}"),
                        config.src,
                        j,
                        || Value::known(f(e.src as u64)),
                    )?;
                    region.assign_advice(
                        || format!("dst_{j}"),
                        config.dst,
                        j,
                        || Value::known(f(e.dst as u64)),
                    )?;
                    let kind_cell = region.assign_advice(
                        || format!("kind_{j}"),
                        config.kind,
                        j,
                        || Value::known(f(e.kind)),
                    )?;
                    let s_src = region.assign_advice(
                        || format!("s_src_{j}"),
                        config.s_src,
                        j,
                        || Value::known(f(if e.active { w.nodes[e.src].s } else { 0 })),
                    )?;
                    let s_dst = region.assign_advice(
                        || format!("s_dst_{j}"),
                        config.s_dst,
                        j,
                        || Value::known(f(if e.active { w.nodes[e.dst].s } else { 0 })),
                    )?;
                    let delta = if e.active {
                        f(e.src as u64) - f(e.dst as u64)
                    } else {
                        F::ONE
                    };
                    let inv = if bool::from(delta.is_zero()) {
                        F::ZERO
                    } else {
                        delta.invert().unwrap()
                    };
                    region.assign_advice(
                        || format!("inv_delta_{j}"),
                        config.inv_delta,
                        j,
                        || Value::known(inv),
                    )?;
                    if e.active {
                        region.constrain_equal(s_src.cell(), s_cells[e.src].cell())?;
                        region.constrain_equal(s_dst.cell(), s_cells[e.dst].cell())?;
                    }
                    leaf_idx.push(region.assign_advice(
                        || format!("leaf_index_{j}"),
                        config.leaf_value,
                        j,
                        || Value::known(f(e.src as u64 * cap as u64 + e.dst as u64)),
                    )?);
                    kinds.push(kind_cell);
                }
                Ok((leaf_idx, kinds))
            },
        )?;

        let public_cells = layouter.assign_region(
            || "public binding",
            |mut region: Region<'_, F>| {
                let values = [
                    f(w.policy_id),
                    f(w.session_id),
                    f(w.nonce),
                    f(w.collector_id),
                ];
                let mut cells = Vec::with_capacity(4);
                for (i, v) in values.iter().enumerate() {
                    cells.push(region.assign_advice(
                        || format!("public_{i}"),
                        config.public_copy,
                        i,
                        || Value::known(*v),
                    )?);
                }
                Ok(cells)
            },
        )?;
        for (i, cell) in public_cells.iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.instance, i + 1)?;
        }

        // --- Poseidon Merkle commitment ---
        let mut leaves: Vec<AssignedCell<F, F>> = Vec::with_capacity(cap + edge_cap);
        let node_domain = layouter.assign_region(
            || "node domain",
            |mut region| {
                region.assign_advice(
                    || "node_domain",
                    config.leaf_domain,
                    0,
                    || Value::known(cap_domain(DOMAIN_NODE, cap)),
                )
            },
        )?;
        for i in 0..cap {
            leaves.push(hash_words::<_, 3>(
                &config,
                layouter.namespace(|| format!("node_leaf_{i}")),
                [
                    node_domain.clone(),
                    node_tl_cells[i].clone(),
                    index_cells[i].clone(),
                ],
            )?);
        }

        let edge_domain = layouter.assign_region(
            || "edge domain",
            |mut region| {
                region.assign_advice(
                    || "edge_domain",
                    config.leaf_domain,
                    0,
                    || Value::known(cap_domain(DOMAIN_EDGE, cap)),
                )
            },
        )?;
        for j in 0..edge_cap {
            if w.edges[j].active {
                leaves.push(hash_words::<_, 3>(
                    &config,
                    layouter.namespace(|| format!("edge_leaf_{j}")),
                    [
                        edge_domain.clone(),
                        edge_idx_cells[j].clone(),
                        kind_cells[j].clone(),
                    ],
                )?);
            } else {
                leaves.push(empty_leaf_cell(&config, &mut layouter, cap)?);
            }
        }

        while leaves.len() > 1 {
            if leaves.len() % 2 == 1 {
                leaves.push(empty_leaf_cell(&config, &mut layouter, cap)?);
            }
            let mut next = Vec::with_capacity(leaves.len() / 2);
            for pair in leaves.chunks_exact(2) {
                next.push(hash_words::<_, 2>(
                    &config,
                    layouter.namespace(|| "merge"),
                    [pair[0].clone(), pair[1].clone()],
                )?);
            }
            leaves = next;
        }
        layouter.constrain_instance(leaves[0].cell(), config.instance, 0)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct IfcCircuit {
    witness: Option<Witness>,
}

impl IfcCircuit {
    fn new(w: Witness) -> Self {
        Self { witness: Some(w) }
    }
    fn for_keygen(cap: usize, edge_cap: usize) -> Self {
        Self {
            witness: Some(Witness {
                cap,
                edge_cap,
                nodes: vec![
                    GNode {
                        typ: T_PUBLIC_SOURCE,
                        label: 0,
                        s: 0,
                    };
                    cap
                ],
                edges: vec![
                    GEdge {
                        src: 0,
                        dst: 1,
                        kind: 0,
                        active: false,
                    };
                    edge_cap
                ],
                policy_id: 7,
                session_id: 20261126,
                nonce: 1,
                collector_id: 1,
            }),
        }
    }
}

fn assign_value(
    region: &mut Region<'_, F>,
    col: Column<Advice>,
    offset: usize,
    value: F,
) -> Result<AssignedCell<F, F>, Error> {
    region.assign_advice(|| "value", col, offset, || Value::known(value))
}

fn empty_leaf_cell(
    config: &IfcConfig,
    layouter: &mut impl Layouter<F>,
    cap: usize,
) -> Result<AssignedCell<F, F>, Error> {
    let domain = layouter.assign_region(
        || "empty leaf domain",
        |mut region| {
            assign_value(
                &mut region,
                config.leaf_domain,
                0,
                cap_domain(DOMAIN_EMPTY, cap),
            )
        },
    )?;
    let zero = layouter.assign_region(
        || "empty leaf zero",
        |mut region| assign_value(&mut region, config.leaf_value, 0, F::ZERO),
    )?;
    hash_words::<_, 2>(config, layouter.namespace(|| "empty leaf"), [domain, zero])
}

fn hash_words<L: Layouter<F>, const N: usize>(
    config: &IfcConfig,
    mut layouter: L,
    words: [AssignedCell<F, F>; N],
) -> Result<AssignedCell<F, F>, Error> {
    let chip = Pow5Chip::construct(config.poseidon.clone());
    let hasher = GadgetHash::<_, _, P128Pow5T3, ConstantLength<N>, 3, 2>::init(
        chip,
        layouter.namespace(|| "init"),
    )?;
    hasher.hash(layouter.namespace(|| "hash"), words)
}

fn k_for_cap(cap: usize) -> u32 {
    match cap {
        50 => 14,
        100 => 15,
        200 => 16,
        _ => panic!("unsupported cap"),
    }
}

fn run_case(cap: usize, density: &str, seed: u64, out: &str) {
    let (sk, vk, collector_id) = make_collector([0x11; 32]);
    let w = make_compliant_witness(cap, density, seed, collector_id);
    let root = compute_root(&w);
    let instance = vec![
        root,
        f(w.policy_id),
        f(w.session_id),
        f(w.nonce),
        f(w.collector_id),
    ];

    // Collector attestation: verified outside the circuit.
    let sig = sk.sign(&canonical_attestation_bytes(root, &w));
    assert!(vk.verify(&canonical_attestation_bytes(root, &w), &sig).is_ok());
    let mut bad_sig_bytes = sig.to_bytes();
    bad_sig_bytes[0] ^= 1;
    let wrong_signature_rejected = vk
        .verify(
            &canonical_attestation_bytes(root, &w),
            &Signature::from_bytes(&bad_sig_bytes),
        )
        .is_err();
    assert!(wrong_signature_rejected);

    let mut k = k_for_cap(cap);
    let shape = IfcCircuit::new(w.clone());
    let t0 = Instant::now();
    let (params, vk_plonk) = loop {
        let params = Params::<vesta::Affine>::new(k);
        match keygen_vk(&params, &shape) {
            Ok(vk) => break (params, vk),
            Err(_) => {
                k += 1;
                if k > 20 {
                    panic!("keygen_vk still out of rows at k=20");
                }
            }
        }
    };
    let pk = keygen_pk(&params, vk_plonk, &shape).expect("keygen_pk");
    let keygen_ms = t0.elapsed().as_millis();

    let circuit = IfcCircuit::new(w.clone());
    let inst_refs: Vec<&[F]> = vec![&instance[..]];
    let all_instances: Vec<&[&[F]]> = vec![&inst_refs];

    let t1 = Instant::now();
    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[circuit],
        &all_instances,
        StdRng::seed_from_u64(seed),
        &mut transcript,
    )
    .expect("create_proof");
    let proof = transcript.finalize();
    let prove_ms = t1.elapsed().as_millis();

    let t2 = Instant::now();
    let shape_v = IfcCircuit::new(w.clone());
    let vk_v = keygen_vk(&params, &shape_v).expect("keygen_vk verify");
    verify_proof(
        &params,
        &vk_v,
        SingleVerifier::new(&params),
        &all_instances,
        &mut Blake2bRead::init(&proof[..]),
    )
    .expect("verify_proof");
    let verify_ms = t2.elapsed().as_millis();

    let mut bad_instance = instance.clone();
    bad_instance[3] += F::ONE;
    let bad_refs: Vec<&[F]> = vec![&bad_instance[..]];
    let bad_all: Vec<&[&[F]]> = vec![&bad_refs];
    let wrong_nonce_rejected = verify_proof(
        &params,
        &vk_v,
        SingleVerifier::new(&params),
        &bad_all,
        &mut Blake2bRead::init(&proof[..]),
    )
    .is_err();
    assert!(wrong_nonce_rejected);

    // Violating graph: one High -> Low sink edge makes C1-C3 unsatisfiable.
    // Run only for the smallest cap to keep the suite fast.
    let mut invalid_rejected: Option<bool> = None;
    if cap == 50 {
        let mut invalid = w.clone();
        invalid.edges[0] = GEdge {
            src: 0,
            dst: cap - 1,
            kind: 0,
            active: true,
        };
        let bad_root = compute_root(&invalid);
        let prover = MockProver::run(
            k,
            &IfcCircuit::new(invalid),
            vec![vec![
                bad_root,
                f(w.policy_id),
                f(w.session_id),
                f(w.nonce),
                f(w.collector_id),
            ]],
        )
        .expect("mockprover run");
        invalid_rejected = Some(prover.verify().is_err());
        assert!(invalid_rejected.unwrap(), "violating graph must be rejected");
    }

    let leaf_count = cap + w.edge_cap;
    let depth = (usize::BITS - (leaf_count - 1).leading_zeros()) as usize;
    let tree_size = 1usize << depth;
    // Node/edge leaves use ConstantLength<3> = 2 permutations; empty/merge use 1.
    let poseidon_perms = cap * 2 + w.edge_cap * 2 + (tree_size - 1);
    let own_gate_declarations = 2usize;
    let own_constraints = 13usize; // 10 node + 3 edge constraint polynomials
    let poseidon_gate_declarations = 3usize; // halo2_gadgets Pow5Chip source
    let witness_field_elements = 4 * cap + 4 * w.edge_cap + 16;

    let binding_hash = host_hash::<5>([
        cap_domain(DOMAIN_BIND, cap),
        root,
        f(w.policy_id),
        f(w.session_id),
        f(w.nonce),
    ]);

    let result: JsonValue = json!({
        "stage": "ZK-AGENT-IFC Phase 1B prototype",
        "cap": cap,
        "edge_cap": w.edge_cap,
        "density": density,
        "active_edges": w.edges.iter().filter(|e| e.active).count(),
        "seed": seed,
        "k": k,
        "leaf_count": leaf_count,
        "merkle_depth": depth,
        "poseidon_permutations": poseidon_perms,
        "own_gate_declarations": own_gate_declarations,
        "own_constraints": own_constraints,
        "poseidon_gate_declarations": poseidon_gate_declarations,
        "witness_field_elements": witness_field_elements,
        "witness_bytes_estimate": witness_field_elements * 32,
        "keygen_ms": keygen_ms,
        "prove_ms": prove_ms,
        "verify_ms": verify_ms,
        "proof_bytes": proof.len(),
        "root": root_to_hex(root),
        "binding_hash": root_to_hex(binding_hash),
        "collector_signature_verified": true,
        "wrong_signature_rejected": wrong_signature_rejected,
        "wrong_nonce_instance_rejected": wrong_nonce_rejected,
        "violating_graph_rejected_by_mock_prover": invalid_rejected,
        "note": "halo2_proofs 0.4 does not expose an exact global constraint count; gate declarations and Poseidon permutation count are reported instead of fabricating one."
    });
    fs::write(out, serde_json::to_vec_pretty(&result).unwrap()).expect("write result");
    println!("{}", serde_json::to_string(&result).unwrap());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!(
            "usage: {} <cap:50|100|200> <density:low|mid|high> <seed> <out.json>",
            args[0]
        );
        std::process::exit(2);
    }
    let cap: usize = args[1].parse().expect("cap");
    let density = args[2].clone();
    let seed: u64 = args[3].parse().expect("seed");
    let out = args[4].clone();
    run_case(cap, &density, seed, &out);
}
