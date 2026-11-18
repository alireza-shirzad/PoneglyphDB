//! TPC-H Q3, Q5, Q8, Q9 and Q18 (TruthTable's `_pgn` variants; Q1 is in
//! `q1_fixed_kzg`) rebuilt from sound gadgets, in place of the `*_final_kzg`
//! circuits:
//!
//! - the tables are the circuit's first advice columns, unblinded, so the
//!   proof is bound to the data owner's commitments;
//! - a filter is a flag column constrained by its predicate;
//! - [`JoinConfig`] is the paper's primary-key/foreign-key join (§4.4), laid
//!   along the foreign-key rows: a flag says which join, the primary-key
//!   columns they need are looked up from the matching valid primary-key
//!   row, and the valid primary keys merged with the distinct keys of the
//!   valid rows that do not join strictly increase, so the primary keys are
//!   unique and no row that should join was left out;
//! - [`GroupConfig`] shuffles the valid rows into a prefix sorted by group
//!   key, restarts running sums at constrained group boundaries and shuffles
//!   each group's last row into the public output, whose order the query
//!   checks;
//! - every selector covers a range fixed by the table sizes.
//!
//! Prices and rates are integer cents, as in the `_poneglyph` tables, so
//! `1 - l_discount` is negative: the field carries a negative value `x` as
//! `p - |x|`. A string is one field element (see [`string`]).
//!
//! Every join key must lie below 2^24, every TPC-H key does at the scale
//! factors run here; a larger key fails to prove, it cannot join wrongly.

use super::micro_kzg::{
    cur, next, one, prefix_flag, prev, prove_fields, Field, MicroResult, OutputConfig,
};
use crate::chips::is_zero::{IsZeroChip, IsZeroConfig};
use crate::chips::lessthan_or_equal_generic::{
    LtEqGenericChip, LtEqGenericConfig, LtEqGenericInstruction,
};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
use std::collections::{BTreeSet, HashMap};
use std::marker::PhantomData;

/// Bytes of a comparison of keys (below 2^24).
const KEY_BYTES: usize = 3;
/// Bytes of a comparison of a packed sort key.
const SORT_BYTES: usize = 10;

/// A table column as the data owner commits it.
#[derive(Clone, Debug)]
pub enum Col {
    Int(Vec<i64>),
    Str(Vec<String>),
}

impl Col {
    pub fn len(&self) -> usize {
        match self {
            Col::Int(v) => v.len(),
            Col::Str(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn values(&self) -> Vec<i128> {
        match self {
            Col::Int(v) => v.iter().map(|&x| x as i128).collect(),
            Col::Str(v) => v.iter().map(|s| string(s)).collect(),
        }
    }
}

/// A string as an integer. Up to 15 bytes it is the bytes, big-endian, so
/// such strings order as their integers do; a longer string (only compared
/// for equality or output, never ordered) is a 120-bit hash of its bytes with
/// bit 126 set, so it cannot equal a short string's.
pub fn string(s: &str) -> i128 {
    use std::hash::{Hash, Hasher};
    let bytes = s.as_bytes();
    if bytes.len() <= 15 {
        return bytes.iter().fold(0i128, |acc, &b| (acc << 8) | b as i128);
    }
    let half = |seed: u8| {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        seed.hash(&mut h);
        bytes.hash(&mut h);
        h.finish() as i128
    };
    let hash = ((half(0) << 56) ^ half(1)) & ((1i128 << 120) - 1);
    hash | (1i128 << 126)
}

/// A signed integer as a field element.
pub fn signed<F: Field>(v: i128) -> F {
    let f = F::from_u128(v.unsigned_abs());
    if v < 0 {
        -f
    } else {
        f
    }
}

/// Loads every comparison chip's `u8` table and returns the chips.
fn comparisons<F: Field, const N: usize>(
    configs: &[LtEqGenericConfig<F, N>],
    layouter: &mut impl Layouter<F>,
) -> Result<Vec<LtEqGenericChip<F, N>>, Error> {
    configs
        .iter()
        .map(|c| {
            let chip = LtEqGenericChip::construct(*c);
            chip.load(layouter)?;
            Ok(chip)
        })
        .collect()
}

fn constant<F: Field>(v: i128) -> Expression<F> {
    Expression::Constant(signed(v))
}

fn put<F: Field>(
    region: &mut Region<'_, F>,
    column: Column<Advice>,
    row: usize,
    v: i128,
) -> Result<AssignedCell<F, F>, Error> {
    region.assign_advice(|| "", column, row, || Value::known(signed(v)))
}

/// A relation laid along a range of rows: its selector, its validity flag and
/// its columns.
#[derive(Clone, Debug)]
pub struct Rel {
    pub q: Selector,
    pub valid: Column<Advice>,
    pub cols: Vec<Column<Advice>>,
}

/// The paper's primary-key/foreign-key join, along the foreign-key rows.
#[derive(Clone, Debug)]
pub struct JoinConfig<F: Field, const N: usize = KEY_BYTES> {
    /// The foreign-key rows that join.
    pub joins: Column<Advice>,
    other: Column<Advice>,
    /// The joined primary-key row's looked-up columns, per foreign-key row.
    pub attrs: Vec<Column<Advice>>,
    q_src: Selector,
    q_src_next: Selector,
    q_tail: Selector,
    src: Column<Advice>,
    src_flag: Column<Advice>,
    distinct: Column<Advice>,
    merged: Column<Advice>,
    merged_flag: Column<Advice>,
    lt: LtEqGenericConfig<F, N>,
}

impl<F: Field, const N: usize> JoinConfig<F, N> {
    /// Joins `fk` (its `fk_key` column, its rows valid by `fk.valid`) to `pk`
    /// (its `pk_key`, valid by `pk.valid`), looking up `pk_attrs`.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        fk: &Rel,
        fk_key: Column<Advice>,
        pk: &Rel,
        pk_key: Column<Advice>,
        pk_attrs: &[Column<Advice>],
    ) -> Self {
        let (joins, other) = (meta.advice_column(), meta.advice_column());
        let attrs: Vec<_> = pk_attrs.iter().map(|_| meta.advice_column()).collect();
        let q_src = meta.complex_selector();
        let (q_src_next, q_tail) = (meta.selector(), meta.selector());
        let (src, src_flag, distinct) = (
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        );
        let (merged, merged_flag) = (meta.advice_column(), meta.advice_column());
        let (q_fk, fk_valid, q_pk, pk_valid) = (fk.q, fk.valid, pk.q, pk.valid);

        meta.create_gate("join flags", move |m| {
            let q = m.query_selector(q_fk);
            let (j, v) = (cur(m, joins), cur(m, fk_valid));
            vec![
                q.clone() * j.clone() * (one() - j.clone()),
                q.clone() * j.clone() * (one() - v.clone()),
                q * (cur(m, other) - (v - j)),
            ]
        });
        let (out_attrs, in_attrs) = (attrs.clone(), pk_attrs.to_vec());
        meta.lookup_any(
            "a joining row's key and columns are a valid primary-key row's",
            move |m| {
                let g = m.query_selector(q_fk) * cur(m, joins);
                let h = m.query_selector(q_pk) * cur(m, pk_valid);
                let mut pairs = vec![
                    (g.clone(), h.clone()),
                    (g.clone() * cur(m, fk_key), h.clone() * cur(m, pk_key)),
                ];
                for (&o, &i) in out_attrs.iter().zip(&in_attrs) {
                    pairs.push((g.clone() * cur(m, o), h.clone() * cur(m, i)));
                }
                pairs
            },
        );
        meta.create_gate("src starts with the valid primary keys", move |m| {
            let q = m.query_selector(q_pk);
            vec![
                q.clone() * (cur(m, src) - cur(m, pk_key)),
                q.clone() * (cur(m, src_flag) - cur(m, pk_valid)),
                q * cur(m, distinct),
            ]
        });
        meta.create_gate("distinct is boolean", move |m| {
            let d = cur(m, distinct);
            vec![m.query_selector(q_src) * d.clone() * (one() - d)]
        });
        meta.create_gate(
            "after the primary keys, src holds the distinct keys",
            move |m| vec![m.query_selector(q_tail) * (cur(m, src_flag) - cur(m, distinct))],
        );
        meta.lookup_any("a non-joining key is among the distinct ones", move |m| {
            let o = m.query_selector(q_fk) * cur(m, other);
            let d = cur(m, distinct);
            vec![
                (o.clone(), d.clone()),
                (o * cur(m, fk_key), d * cur(m, src)),
            ]
        });
        prefix_flag(meta, q_src, q_src_next, merged_flag);
        meta.shuffle("merged is a shuffle of the flagged src", move |m| {
            let q = m.query_selector(q_src);
            let f = q.clone() * cur(m, src_flag);
            let g = q * cur(m, merged_flag);
            vec![
                (f.clone(), g.clone()),
                (f * cur(m, src), g * cur(m, merged)),
            ]
        });
        let lt = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(q_src_next),
            |m| vec![prev(m, merged), one()],
            |m| vec![cur(m, merged)],
        );
        meta.create_gate("merged strictly increases", move |m| {
            vec![m.query_selector(q_src_next) * cur(m, merged_flag) * (lt.is_lt(m, None) - one())]
        });
        JoinConfig {
            joins,
            other,
            attrs,
            q_src,
            q_src_next,
            q_tail,
            src,
            src_flag,
            distinct,
            merged,
            merged_flag,
            lt,
        }
    }

    /// Assigns the join of `fk_keys` (valid by `fk_valid`) to the rows
    /// `pk_keys` (valid by `pk_valid`) with columns `pk_attrs`, over a merge
    /// region of `capacity` rows; returns, per foreign-key row, whether it
    /// joins and the joined row's columns.
    #[allow(clippy::too_many_arguments)]
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        lt: &LtEqGenericChip<F, N>,
        fk_keys: &[i128],
        fk_valid: &[bool],
        pk_keys: &[i128],
        pk_valid: &[bool],
        pk_attrs: &[Vec<i128>],
        capacity: usize,
    ) -> Result<Vec<Option<Vec<i128>>>, Error> {
        let index: HashMap<i128, usize> = pk_keys
            .iter()
            .enumerate()
            .filter(|&(r, _)| pk_valid[r])
            .map(|(r, &k)| (k, r))
            .collect();
        let mut joined = Vec::with_capacity(fk_keys.len());
        let mut others = BTreeSet::new();
        for (row, &k) in fk_keys.iter().enumerate() {
            let hit = if fk_valid[row] { index.get(&k) } else { None };
            put(region, self.joins, row, hit.is_some() as i128)?;
            put(
                region,
                self.other,
                row,
                (fk_valid[row] && hit.is_none()) as i128,
            )?;
            if fk_valid[row] && hit.is_none() {
                others.insert(k);
            }
            let attrs: Vec<i128> = match hit {
                Some(&p) => pk_attrs.iter().map(|c| c[p]).collect(),
                None => vec![0; self.attrs.len()],
            };
            for (&c, &v) in self.attrs.iter().zip(&attrs) {
                put(region, c, row, v)?;
            }
            joined.push(hit.map(|_| attrs));
        }
        let mut src: Vec<(i128, bool, bool)> = pk_keys
            .iter()
            .enumerate()
            .map(|(r, &k)| (k, pk_valid[r], false))
            .collect();
        src.extend(others.iter().map(|&k| (k, true, true)));
        assert!(
            src.len() <= capacity,
            "the join's merge region is too small"
        );
        let mut merged: Vec<i128> = src.iter().filter(|s| s.1).map(|s| s.0).collect();
        merged.sort();
        for row in 0..capacity {
            self.q_src.enable(region, row)?;
            if row >= pk_keys.len() {
                self.q_tail.enable(region, row)?;
            }
            let (k, f, d) = src.get(row).copied().unwrap_or((0, false, false));
            put(region, self.src, row, k)?;
            put(region, self.src_flag, row, f as i128)?;
            put(region, self.distinct, row, d as i128)?;
            let m = merged.get(row);
            put(region, self.merged, row, m.copied().unwrap_or(0))?;
            put(region, self.merged_flag, row, m.is_some() as i128)?;
            if row > 0 {
                self.q_src_next.enable(region, row)?;
                let p = merged.get(row - 1).copied().unwrap_or(0);
                lt.assign(
                    region,
                    row,
                    &[signed(p), F::ONE],
                    &[signed(m.copied().unwrap_or(0))],
                )?;
            }
        }
        Ok(joined)
    }
}

/// GROUP BY a key with running sums, over a relation's valid rows.
#[derive(Clone, Debug)]
pub struct GroupConfig<F: Field, const N: usize = SORT_BYTES> {
    q_s: Selector,
    q_s_next: Selector,
    q_first: Selector,
    q_last: Selector,
    q_not_last: Selector,
    /// Sorted: valid flag, key, carried columns, terms.
    sorted: Vec<Column<Advice>>,
    same: Column<Advice>,
    end: Column<Advice>,
    sums: Vec<Column<Advice>>,
    order: LtEqGenericConfig<F, N>,
    same_key: IsZeroConfig<F>,
    pub output: OutputConfig,
    carries: usize,
}

impl<F: Field, const N: usize> GroupConfig<F, N> {
    /// Groups `rel`'s valid rows by `key` (below 2^80); `carry` are columns
    /// constant within a group, output beside the key, and `terms` the summed
    /// columns. The output is (key, carries..., sums...).
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        rel: &Rel,
        key: Column<Advice>,
        carry: &[Column<Advice>],
        terms: &[Column<Advice>],
    ) -> Self {
        let q_s = meta.complex_selector();
        let (q_s_next, q_first) = (meta.selector(), meta.selector());
        let (q_last, q_not_last) = (meta.selector(), meta.selector());
        let width = 2 + carry.len() + terms.len();
        let sorted: Vec<_> = (0..width).map(|_| meta.advice_column()).collect();
        let (same, end) = (meta.advice_column(), meta.advice_column());
        let sums: Vec<_> = terms.iter().map(|_| meta.advice_column()).collect();
        let output = OutputConfig::configure(
            meta,
            1 + carry.len() + terms.len(),
            1 + carry.len() + terms.len(),
        );
        let (q_in, valid) = (rel.q, rel.valid);
        let inputs: Vec<_> = [key].iter().chain(carry).chain(terms).copied().collect();
        let s = sorted.clone();
        meta.shuffle("sorted is a shuffle of the valid rows", move |m| {
            let g = m.query_selector(q_in) * cur(m, valid);
            let h = m.query_selector(q_s) * cur(m, s[0]);
            let mut pairs = vec![(g.clone(), h.clone())];
            for (&i, &o) in inputs.iter().zip(&s[1..]) {
                pairs.push((g.clone() * cur(m, i), h.clone() * cur(m, o)));
            }
            pairs
        });
        prefix_flag(meta, q_s, q_s_next, sorted[0]);
        let (sv, sk) = (sorted[0], sorted[1]);
        let order = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(q_s_next),
            |m| vec![prev(m, sk)],
            |m| vec![cur(m, sk)],
        );
        meta.create_gate("sorted by key", move |m| {
            vec![m.query_selector(q_s_next) * cur(m, sv) * (order.is_lt(m, None) - one())]
        });
        let inv = meta.advice_column();
        let same_key = IsZeroChip::configure(
            meta,
            |m| m.query_selector(q_s_next),
            |m| prev(m, sk) - cur(m, sk),
            inv,
        );
        let same_expr = same_key.expr();
        meta.create_gate("same group as the previous row", move |m| {
            vec![m.query_selector(q_s_next) * (cur(m, same) - cur(m, sv) * same_expr.clone())]
        });
        let first_terms = 2 + carry.len();
        let (sc, ss) = (sorted.clone(), sums.clone());
        meta.create_gate("first row", move |m| {
            let q = m.query_selector(q_first);
            let mut gates = vec![q.clone() * cur(m, same)];
            for (i, &c) in ss.iter().enumerate() {
                gates.push(q.clone() * (cur(m, c) - cur(m, sc[first_terms + i])));
            }
            gates
        });
        let (sc, ss) = (sorted.clone(), sums.clone());
        meta.create_gate("running sums per group", move |m| {
            let q = m.query_selector(q_s_next);
            let sm = cur(m, same);
            ss.iter()
                .enumerate()
                .map(|(i, &c)| {
                    q.clone() * (cur(m, c) - sm.clone() * prev(m, c) - cur(m, sc[first_terms + i]))
                })
                .collect::<Vec<_>>()
        });
        meta.create_gate("a group ends where the next starts", move |m| {
            vec![m.query_selector(q_not_last) * (cur(m, end) - (cur(m, sv) - next(m, same)))]
        });
        meta.create_gate("the last row ends a group if valid", move |m| {
            vec![m.query_selector(q_last) * (cur(m, end) - cur(m, sv))]
        });
        let (sc, ss, out) = (sorted.clone(), sums.clone(), output.clone());
        let carried = carry.len();
        meta.shuffle("group ends are the output", move |m| {
            let g = m.query_selector(q_s) * cur(m, end);
            let mut input = vec![g.clone(), g.clone() * cur(m, sc[1])];
            input.extend((0..carried).map(|i| g.clone() * cur(m, sc[2 + i])));
            input.extend(ss.iter().map(|&c| g.clone() * cur(m, c)));
            input.into_iter().zip(out.tuple(m)).collect()
        });
        GroupConfig {
            q_s,
            q_s_next,
            q_first,
            q_last,
            q_not_last,
            sorted,
            same,
            end,
            sums,
            order,
            same_key,
            output,
            carries: carry.len(),
        }
    }

    /// Assigns the grouping of `rows` (valid flag, key, carries..., terms...)
    /// over `n` rows; returns the groups, (key, carries..., sums...), in key
    /// order.
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        order: &LtEqGenericChip<F, N>,
        rows: &[(bool, Vec<i128>)],
        n: usize,
    ) -> Result<Vec<Vec<i128>>, Error> {
        let same_key = IsZeroChip::construct(self.same_key.clone());
        let mut sorted: Vec<&Vec<i128>> = rows.iter().filter(|r| r.0).map(|r| &r.1).collect();
        sorted.sort_by_key(|r| r[0]);
        let width = 1 + self.carries;
        let mut groups: Vec<Vec<i128>> = Vec::new();
        let mut sums = vec![0i128; self.sums.len()];
        self.q_first.enable(region, 0)?;
        self.q_last.enable(region, n - 1)?;
        for row in 0..n {
            self.q_s.enable(region, row)?;
            let r = sorted.get(row);
            let valid = r.is_some();
            put(region, self.sorted[0], row, valid as i128)?;
            let values: Vec<i128> = r.map_or(vec![0; self.sorted.len() - 1], |r| r.to_vec());
            for (c, &v) in self.sorted[1..].iter().zip(&values) {
                put(region, *c, row, v)?;
            }
            let prev_key = if row > 0 {
                sorted.get(row - 1).map_or(0, |p| p[0])
            } else {
                0
            };
            let same = row > 0 && valid && prev_key == values[0];
            if row > 0 {
                self.q_s_next.enable(region, row)?;
                order.assign(region, row, &[signed(prev_key)], &[signed(values[0])])?;
                same_key.assign(
                    region,
                    row,
                    Value::known(signed::<F>(prev_key) - signed::<F>(values[0])),
                )?;
            }
            if row + 1 < n {
                self.q_not_last.enable(region, row)?;
            }
            for (i, s) in sums.iter_mut().enumerate() {
                let t = values[width + i];
                *s = if same { *s + t } else { t };
                put(region, self.sums[i], row, *s)?;
            }
            let next_same = sorted
                .get(row + 1)
                .is_some_and(|nx| valid && nx[0] == values[0]);
            let end = valid && !next_same;
            put(region, self.same, row, same as i128)?;
            put(region, self.end, row, end as i128)?;
            if end {
                let mut g = values[..width].to_vec();
                g.extend(&sums);
                groups.push(g);
            }
        }
        Ok(groups)
    }
}

/// The output order: per output row, a value that must not decrease. `key`
/// packs the order columns, each made non-negative and below its bound.
#[derive(Clone, Debug)]
pub struct OrderConfig<F: Field, const N: usize = SORT_BYTES> {
    lt: LtEqGenericConfig<F, N>,
}

impl<F: Field, const N: usize> OrderConfig<F, N> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        output: &OutputConfig,
        key: impl Fn(&mut VirtualCells<'_, F>, Rotation) -> Expression<F> + Clone + 'static,
    ) -> Self {
        let (q_next, flag) = (output.q_next, output.flag);
        let (k1, k2) = (key.clone(), key);
        let lt = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(q_next),
            move |m| vec![k1(m, Rotation::prev())],
            move |m| vec![k2(m, Rotation::cur())],
        );
        meta.create_gate("the output is ordered", move |m| {
            vec![m.query_selector(q_next) * cur(m, flag) * (lt.is_lt(m, None) - one())]
        });
        OrderConfig { lt }
    }
}

/// A packed order key: `(value + offset) * 2^shift`, summed over parts.
fn pack(parts: &[(i128, i128, u32)]) -> i128 {
    parts
        .iter()
        .map(|&(v, offset, shift)| (v + offset) << shift)
        .sum()
}

// ---------------------------------------------------------------------------
// Q3: customer ⋈ orders ⋈ lineitem, grouped by order, by revenue descending.
// ---------------------------------------------------------------------------

/// `DATE '1995-03-15'`.
const Q3_DATE: i128 = 9204;
const BUILDING: &str = "BUILDING";
/// Revenue offset: revenues lie in (-2^59, 2^59).
const REV_OFFSET: i128 = 1 << 59;

/// The tables, in commitment order.
pub struct Q3Tables {
    pub customer: [Col; 2], // c_custkey, c_mktsegment
    pub orders: [Col; 4],   // o_orderkey, o_custkey, o_orderdate, o_shippriority
    pub lineitem: [Col; 4], // l_orderkey, l_extendedprice, l_discount, l_shipdate
}

#[derive(Clone, Debug)]
pub struct Q3Config<F: Field> {
    table: Vec<Column<Advice>>,
    customer: Rel,
    orders: Rel,
    lineitem: Rel,
    segment: IsZeroConfig<F>,
    o_date: LtEqGenericConfig<F, KEY_BYTES>,
    l_date: LtEqGenericConfig<F, KEY_BYTES>,
    revenue: Column<Advice>,
    join_c: JoinConfig<F>,
    join_o: JoinConfig<F>,
    group: GroupConfig<F>,
    order: OrderConfig<F>,
}

#[derive(Clone, Default)]
pub struct Q3Circuit<F> {
    pub columns: Vec<Vec<i128>>,
    pub sizes: [usize; 3],
    _f: PhantomData<F>,
}

impl<F: Field> Q3Circuit<F> {
    pub fn new(t: &Q3Tables) -> Self {
        let columns: Vec<Vec<i128>> = t
            .customer
            .iter()
            .chain(&t.orders)
            .chain(&t.lineitem)
            .map(Col::values)
            .collect();
        Self {
            sizes: [t.customer[0].len(), t.orders[0].len(), t.lineitem[0].len()],
            columns,
            _f: PhantomData,
        }
    }

    /// The rows the circuit needs: every table, and each join's merge region
    /// of as many rows as its two tables.
    pub fn rows(&self) -> usize {
        let [c, o, l] = self.sizes;
        l.max(c + o).max(o + l)
    }

    /// (l_orderkey, o_orderdate, o_shippriority, revenue), ordered by revenue
    /// descending, then date.
    pub fn result(&self) -> Vec<Vec<i128>> {
        let c = &self.columns;
        let building = string(BUILDING);
        let customers: BTreeSet<i128> = (0..self.sizes[0])
            .filter(|&r| c[1][r] == building)
            .map(|r| c[0][r])
            .collect();
        let orders: HashMap<i128, (i128, i128)> = (0..self.sizes[1])
            .filter(|&r| c[4][r] < Q3_DATE && customers.contains(&c[3][r]))
            .map(|r| (c[2][r], (c[4][r], c[5][r])))
            .collect();
        let mut groups: std::collections::BTreeMap<i128, (i128, i128, i128)> = Default::default();
        for r in 0..self.sizes[2] {
            if c[9][r] <= Q3_DATE {
                continue;
            }
            if let Some(&(date, prio)) = orders.get(&c[6][r]) {
                let g = groups.entry(c[6][r]).or_insert((date, prio, 0));
                g.2 += c[7][r] * (1 - c[8][r]);
            }
        }
        let mut out: Vec<Vec<i128>> = groups
            .into_iter()
            .map(|(k, (d, p, rev))| vec![k, d, p, rev])
            .collect();
        out.sort_by_key(|g| (-g[3], g[1]));
        out
    }
}

impl<F: Field> Circuit<F> for Q3Circuit<F> {
    type Config = Q3Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            columns: vec![],
            sizes: [0; 3],
            _f: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let table: Vec<_> = (0..10).map(|_| meta.unblinded_advice_column()).collect();
        let rel = |meta: &mut ConstraintSystem<F>, cols: &[Column<Advice>]| Rel {
            q: meta.complex_selector(),
            valid: meta.advice_column(),
            cols: cols.to_vec(),
        };
        let customer = rel(meta, &table[0..2]);
        let orders = rel(meta, &table[2..6]);
        let lineitem = rel(meta, &table[6..10]);

        let seg = table[1];
        let inv = meta.advice_column();
        let qc = customer.q;
        let segment = IsZeroChip::configure(
            meta,
            |m| m.query_selector(qc),
            |m| cur(m, seg) - constant(string(BUILDING)),
            inv,
        );
        let (cv, seg_expr) = (customer.valid, segment.expr());
        meta.create_gate("customer filter", move |m| {
            vec![m.query_selector(qc) * (cur(m, cv) - seg_expr.clone())]
        });
        let (qo, od) = (orders.q, table[4]);
        let o_date = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(qo),
            |m| vec![cur(m, od), one()],
            |_| vec![constant(Q3_DATE)],
        );
        let ov = orders.valid;
        meta.create_gate("orders filter", move |m| {
            vec![m.query_selector(qo) * (cur(m, ov) - o_date.is_lt(m, None))]
        });
        let (ql, ld) = (lineitem.q, table[9]);
        let l_date = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(ql),
            |_| vec![constant(Q3_DATE + 1)],
            |m| vec![cur(m, ld)],
        );
        let lv = lineitem.valid;
        meta.create_gate("lineitem filter", move |m| {
            vec![m.query_selector(ql) * (cur(m, lv) - l_date.is_lt(m, None))]
        });

        let join_c = JoinConfig::configure(meta, &orders, table[3], &customer, table[0], &[]);
        let joined_orders = Rel {
            q: orders.q,
            valid: join_c.joins,
            cols: orders.cols.clone(),
        };
        let join_o = JoinConfig::configure(
            meta,
            &lineitem,
            table[6],
            &joined_orders,
            table[2],
            &[table[4], table[5]],
        );
        let revenue = meta.advice_column();
        let (price, disc) = (table[7], table[8]);
        meta.create_gate("revenue", move |m| {
            vec![m.query_selector(ql) * (cur(m, revenue) - cur(m, price) * (one() - cur(m, disc)))]
        });
        let joined = Rel {
            q: lineitem.q,
            valid: join_o.joins,
            cols: vec![],
        };
        let group = GroupConfig::configure(meta, &joined, table[6], &join_o.attrs, &[revenue]);
        // Output (orderkey, date, priority, revenue): revenue descending, then
        // date.
        let out = group.output.columns.clone();
        let order = OrderConfig::configure(meta, &group.output, move |m, rot| {
            let rev = m.query_advice(out[3], rot);
            let date = m.query_advice(out[1], rot);
            (constant(REV_OFFSET) - rev) * constant(1 << 16) + date
        });
        Q3Config {
            table,
            customer,
            orders,
            lineitem,
            segment,
            o_date,
            l_date,
            revenue,
            join_c,
            join_o,
            group,
            order,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let key_chips = comparisons(
            &[
                config.o_date,
                config.l_date,
                config.join_c.lt,
                config.join_o.lt,
            ],
            &mut layouter,
        )?;
        let sort_chips = comparisons(&[config.group.order, config.order.lt], &mut layouter)?;
        let segment = IsZeroChip::construct(config.segment.clone());
        let [nc, no, nl] = self.sizes;
        let n = self.rows();
        let c = &self.columns;
        let result: Vec<Vec<F>> = self
            .result()
            .iter()
            .map(|g| g.iter().map(|&v| signed(v)).collect())
            .collect();
        let cells = layouter.assign_region(
            || "q3",
            |mut region| {
                for (i, col) in c.iter().enumerate() {
                    for (row, &v) in col.iter().enumerate() {
                        put(&mut region, config.table[i], row, v)?;
                    }
                }
                let building = string(BUILDING);
                let mut c_valid = vec![false; nc];
                for row in 0..nc {
                    config.customer.q.enable(&mut region, row)?;
                    segment.assign(
                        &mut region,
                        row,
                        Value::known(signed::<F>(c[1][row] - building)),
                    )?;
                    c_valid[row] = c[1][row] == building;
                    put(
                        &mut region,
                        config.customer.valid,
                        row,
                        c_valid[row] as i128,
                    )?;
                }
                let mut o_valid = vec![false; no];
                for row in 0..no {
                    config.orders.q.enable(&mut region, row)?;
                    key_chips[0].assign(
                        &mut region,
                        row,
                        &[signed(c[4][row]), F::ONE],
                        &[signed(Q3_DATE)],
                    )?;
                    o_valid[row] = c[4][row] < Q3_DATE;
                    put(&mut region, config.orders.valid, row, o_valid[row] as i128)?;
                }
                let mut l_valid = vec![false; nl];
                for row in 0..nl {
                    config.lineitem.q.enable(&mut region, row)?;
                    key_chips[1].assign(
                        &mut region,
                        row,
                        &[signed(Q3_DATE + 1)],
                        &[signed(c[9][row])],
                    )?;
                    l_valid[row] = c[9][row] > Q3_DATE;
                    put(
                        &mut region,
                        config.lineitem.valid,
                        row,
                        l_valid[row] as i128,
                    )?;
                    put(
                        &mut region,
                        config.revenue,
                        row,
                        c[7][row] * (1 - c[8][row]),
                    )?;
                }
                let o_joins = config.join_c.assign(
                    &mut region,
                    &key_chips[2],
                    &c[3],
                    &o_valid,
                    &c[0],
                    &c_valid,
                    &[],
                    nc + no,
                )?;
                let o_joined: Vec<bool> = o_joins.iter().map(Option::is_some).collect();
                let l_joins = config.join_o.assign(
                    &mut region,
                    &key_chips[3],
                    &c[6],
                    &l_valid,
                    &c[2],
                    &o_joined,
                    &[c[4].clone(), c[5].clone()],
                    no + nl,
                )?;
                let rows: Vec<(bool, Vec<i128>)> = (0..nl)
                    .map(|r| match &l_joins[r] {
                        Some(a) => (true, vec![c[6][r], a[0], a[1], c[7][r] * (1 - c[8][r])]),
                        None => (false, vec![0; 4]),
                    })
                    .collect();
                config.group.assign(&mut region, &sort_chips[0], &rows, n)?;
                // The order key of each output row, empty rows' from zeros.
                let groups = self.result();
                let key = |r: usize| {
                    let (rev, date) = groups.get(r).map_or((0, 0), |g| (g[3], g[1]));
                    pack(&[(-rev, REV_OFFSET, 16), (date, 0, 0)])
                };
                for row in 1..n {
                    sort_chips[1].assign(
                        &mut region,
                        row,
                        &[signed(key(row - 1))],
                        &[signed(key(row))],
                    )?;
                }
                config.group.output.assign_fields(&mut region, n, &result)
            },
        )?;
        config.group.output.publish(&mut layouter, &cells)
    }
}

// ---------------------------------------------------------------------------
// Q18: customer ⋈ orders ⋈ lineitem, grouped by order, by price descending.
// ---------------------------------------------------------------------------

/// Price offset: total prices lie below 2^59.
const PRICE_OFFSET: i128 = 1 << 59;

/// The tables, in commitment order.
pub struct Q18Tables {
    pub customer: [Col; 2], // c_custkey, c_name
    pub orders: [Col; 4],   // o_orderkey, o_custkey, o_orderdate, o_totalprice
    pub lineitem: [Col; 2], // l_orderkey, l_quantity
}

#[derive(Clone, Debug)]
pub struct Q18Config<F: Field> {
    table: Vec<Column<Advice>>,
    rels: [Rel; 3],
    join_c: JoinConfig<F>,
    join_o: JoinConfig<F>,
    group: GroupConfig<F>,
    order: OrderConfig<F>,
}

#[derive(Clone, Default)]
pub struct Q18Circuit<F> {
    pub columns: Vec<Vec<i128>>,
    pub sizes: [usize; 3],
    _f: PhantomData<F>,
}

impl<F: Field> Q18Circuit<F> {
    pub fn new(t: &Q18Tables) -> Self {
        let columns = t
            .customer
            .iter()
            .chain(&t.orders)
            .chain(&t.lineitem)
            .map(Col::values)
            .collect();
        Self {
            sizes: [t.customer[0].len(), t.orders[0].len(), t.lineitem[0].len()],
            columns,
            _f: PhantomData,
        }
    }

    pub fn rows(&self) -> usize {
        let [c, o, l] = self.sizes;
        l.max(c + o).max(o + l)
    }

    /// (o_orderkey, c_custkey, o_orderdate, o_totalprice, c_name,
    /// sum(l_quantity)), by price descending, then date.
    pub fn result(&self) -> Vec<Vec<i128>> {
        let c = &self.columns;
        let names: HashMap<i128, i128> = (0..self.sizes[0]).map(|r| (c[0][r], c[1][r])).collect();
        let orders: HashMap<i128, Vec<i128>> = (0..self.sizes[1])
            .filter_map(|r| {
                names
                    .get(&c[3][r])
                    .map(|&name| (c[2][r], vec![c[3][r], c[4][r], c[5][r], name]))
            })
            .collect();
        let mut groups: std::collections::BTreeMap<i128, (Vec<i128>, i128)> = Default::default();
        for r in 0..self.sizes[2] {
            if let Some(o) = orders.get(&c[6][r]) {
                groups.entry(c[6][r]).or_insert((o.clone(), 0)).1 += c[7][r];
            }
        }
        let mut out: Vec<Vec<i128>> = groups
            .into_iter()
            .map(|(k, (o, q))| [vec![k], o, vec![q]].concat())
            .collect();
        out.sort_by_key(|g| (-g[3], g[2]));
        out
    }
}

impl<F: Field> Circuit<F> for Q18Circuit<F> {
    type Config = Q18Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            columns: vec![],
            sizes: [0; 3],
            _f: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let table: Vec<_> = (0..8).map(|_| meta.unblinded_advice_column()).collect();
        let rels = [&table[0..2], &table[2..6], &table[6..8]].map(|cols| Rel {
            q: meta.complex_selector(),
            valid: meta.advice_column(),
            cols: cols.to_vec(),
        });
        for rel in &rels {
            let (q, v) = (rel.q, rel.valid);
            meta.create_gate("every row is valid", move |m| {
                vec![m.query_selector(q) * (cur(m, v) - one())]
            });
        }
        let join_c =
            JoinConfig::configure(meta, &rels[1], table[3], &rels[0], table[0], &[table[1]]);
        let joined_orders = Rel {
            q: rels[1].q,
            valid: join_c.joins,
            cols: vec![],
        };
        let join_o = JoinConfig::configure(
            meta,
            &rels[2],
            table[6],
            &joined_orders,
            table[2],
            &[table[3], table[4], table[5], join_c.attrs[0]],
        );
        let joined = Rel {
            q: rels[2].q,
            valid: join_o.joins,
            cols: vec![],
        };
        let group = GroupConfig::configure(meta, &joined, table[6], &join_o.attrs, &[table[7]]);
        let out = group.output.columns.clone();
        let order = OrderConfig::configure(meta, &group.output, move |m, rot| {
            let price = m.query_advice(out[3], rot);
            let date = m.query_advice(out[2], rot);
            (constant(PRICE_OFFSET) - price) * constant(1 << 16) + date
        });
        Q18Config {
            table,
            rels,
            join_c,
            join_o,
            group,
            order,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let key_chips = comparisons(&[config.join_c.lt, config.join_o.lt], &mut layouter)?;
        let sort_chips = comparisons(&[config.group.order, config.order.lt], &mut layouter)?;
        let [nc, no, nl] = self.sizes;
        let n = self.rows();
        let c = &self.columns;
        let groups = self.result();
        let result: Vec<Vec<F>> = groups
            .iter()
            .map(|g| g.iter().map(|&v| signed(v)).collect())
            .collect();
        let cells = layouter.assign_region(
            || "q18",
            |mut region| {
                for (i, col) in c.iter().enumerate() {
                    for (row, &v) in col.iter().enumerate() {
                        put(&mut region, config.table[i], row, v)?;
                    }
                }
                for (rel, &size) in config.rels.iter().zip(&self.sizes) {
                    for row in 0..size {
                        rel.q.enable(&mut region, row)?;
                        put(&mut region, rel.valid, row, 1)?;
                    }
                }
                let o_joins = config.join_c.assign(
                    &mut region,
                    &key_chips[0],
                    &c[3],
                    &vec![true; no],
                    &c[0],
                    &vec![true; nc],
                    &[c[1].clone()],
                    nc + no,
                )?;
                let o_joined: Vec<bool> = o_joins.iter().map(Option::is_some).collect();
                let names: Vec<i128> = o_joins
                    .iter()
                    .map(|j| j.as_ref().map_or(0, |a| a[0]))
                    .collect();
                let l_joins = config.join_o.assign(
                    &mut region,
                    &key_chips[1],
                    &c[6],
                    &vec![true; nl],
                    &c[2],
                    &o_joined,
                    &[c[3].clone(), c[4].clone(), c[5].clone(), names],
                    no + nl,
                )?;
                let rows: Vec<(bool, Vec<i128>)> = (0..nl)
                    .map(|r| match &l_joins[r] {
                        Some(a) => (true, vec![c[6][r], a[0], a[1], a[2], a[3], c[7][r]]),
                        None => (false, vec![0; 6]),
                    })
                    .collect();
                config.group.assign(&mut region, &sort_chips[0], &rows, n)?;
                let key = |r: usize| {
                    let (price, date) = groups.get(r).map_or((0, 0), |g| (g[3], g[2]));
                    pack(&[(-price, PRICE_OFFSET, 16), (date, 0, 0)])
                };
                for row in 1..n {
                    sort_chips[1].assign(
                        &mut region,
                        row,
                        &[signed(key(row - 1))],
                        &[signed(key(row))],
                    )?;
                }
                config.group.output.assign_fields(&mut region, n, &result)
            },
        )?;
        config.group.output.publish(&mut layouter, &cells)
    }
}

/// Proves and verifies Q18 at degree `k`, bound to the data owner's
/// commitments to the tables.
pub fn run_q18(k: u32, tables: &Q18Tables, proof_path: &str) -> MicroResult {
    let circuit = Q18Circuit::<Fp>::new(tables);
    let public = transpose(&circuit.result(), 6);
    let table = circuit.columns.iter().map(|c| pad(c)).collect();
    prove_fields(circuit, k, public, Some(table), proof_path)
}

// ---------------------------------------------------------------------------
// Q5: six tables, revenue per ASIA nation where customer and supplier share
// it, by revenue descending.
// ---------------------------------------------------------------------------

/// `DATE '1994-01-01'` and `DATE '1995-01-01'`.
const Q5_FROM: i128 = 8766;
const Q5_TO: i128 = 9131;

/// The tables, in commitment order.
pub struct Q5Tables {
    pub customer: [Col; 2], // c_custkey, c_nationkey
    pub orders: [Col; 3],   // o_orderkey, o_custkey, o_orderdate
    pub lineitem: [Col; 4], // l_orderkey, l_suppkey, l_extendedprice, l_discount
    pub supplier: [Col; 2], // s_suppkey, s_nationkey
    pub nation: [Col; 3],   // n_nationkey, n_name, n_regionkey
    pub region: [Col; 2],   // r_regionkey, r_name
}

#[derive(Clone, Debug)]
pub struct Q5Config<F: Field> {
    table: Vec<Column<Advice>>,
    rels: [Rel; 6],
    from: LtEqGenericConfig<F, KEY_BYTES>,
    to: LtEqGenericConfig<F, KEY_BYTES>,
    asia: IsZeroConfig<F>,
    same_nation: IsZeroConfig<F>,
    shared: Column<Advice>,
    revenue: Column<Advice>,
    joins: [JoinConfig<F>; 5],
    group: GroupConfig<F, 15>,
    order: OrderConfig<F, 10>,
}

#[derive(Clone, Default)]
pub struct Q5Circuit<F> {
    pub columns: Vec<Vec<i128>>,
    pub sizes: [usize; 6],
    _f: PhantomData<F>,
}

const Q5_TABLES: [std::ops::Range<usize>; 6] = [0..2, 2..5, 5..9, 9..11, 11..14, 14..16];

impl<F: Field> Q5Circuit<F> {
    pub fn new(t: &Q5Tables) -> Self {
        let tables: [&[Col]; 6] = [
            &t.customer,
            &t.orders,
            &t.lineitem,
            &t.supplier,
            &t.nation,
            &t.region,
        ];
        Self {
            sizes: tables.map(|cols| cols[0].len()),
            columns: tables
                .iter()
                .flat_map(|cols| cols.iter().map(Col::values))
                .collect(),
            _f: PhantomData,
        }
    }

    pub fn rows(&self) -> usize {
        let [c, o, l, s, n, r] = self.sizes;
        [l, r + n, c + o, o + l, s + l, n + l]
            .into_iter()
            .max()
            .unwrap()
    }

    /// (n_name, revenue), by revenue descending.
    pub fn result(&self) -> Vec<Vec<i128>> {
        let c = &self.columns;
        let [nc, no, nl, ns, nn, nr] = self.sizes;
        let asia = string("ASIA");
        let regions: BTreeSet<i128> = (0..nr)
            .filter(|&r| c[15][r] == asia)
            .map(|r| c[14][r])
            .collect();
        let nations: HashMap<i128, i128> = (0..nn)
            .filter(|&r| regions.contains(&c[13][r]))
            .map(|r| (c[11][r], c[12][r]))
            .collect();
        let customers: HashMap<i128, i128> = (0..nc).map(|r| (c[0][r], c[1][r])).collect();
        let orders: HashMap<i128, i128> = (0..no)
            .filter(|&r| (Q5_FROM..Q5_TO).contains(&c[4][r]))
            .filter_map(|r| customers.get(&c[3][r]).map(|&n| (c[2][r], n)))
            .collect();
        let suppliers: HashMap<i128, i128> = (0..ns).map(|r| (c[9][r], c[10][r])).collect();
        let mut groups: std::collections::BTreeMap<i128, i128> = Default::default();
        for r in 0..nl {
            let (Some(&cn), Some(&sn)) = (orders.get(&c[5][r]), suppliers.get(&c[6][r])) else {
                continue;
            };
            if cn != sn {
                continue;
            }
            if let Some(&name) = nations.get(&sn) {
                *groups.entry(name).or_default() += c[7][r] * (1 - c[8][r]);
            }
        }
        let mut out: Vec<Vec<i128>> = groups.into_iter().map(|(n, rev)| vec![n, rev]).collect();
        out.sort_by_key(|g| -g[1]);
        out
    }
}

impl<F: Field> Circuit<F> for Q5Circuit<F> {
    type Config = Q5Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            columns: vec![],
            sizes: [0; 6],
            _f: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let table: Vec<_> = (0..16).map(|_| meta.unblinded_advice_column()).collect();
        let rels = Q5_TABLES.map(|range| Rel {
            q: meta.complex_selector(),
            valid: meta.advice_column(),
            cols: table[range].to_vec(),
        });
        let [customer, orders, lineitem, supplier, nation, region] = rels.clone();
        for rel in [&customer, &lineitem, &supplier, &nation] {
            let (q, v) = (rel.q, rel.valid);
            meta.create_gate("every row is valid", move |m| {
                vec![m.query_selector(q) * (cur(m, v) - one())]
            });
        }
        let (qo, od) = (orders.q, table[4]);
        let from = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(qo),
            |_| vec![constant(Q5_FROM)],
            |m| vec![cur(m, od)],
        );
        let to = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(qo),
            |m| vec![cur(m, od), one()],
            |_| vec![constant(Q5_TO)],
        );
        let ov = orders.valid;
        meta.create_gate("orders filter", move |m| {
            vec![m.query_selector(qo) * (cur(m, ov) - from.is_lt(m, None) * to.is_lt(m, None))]
        });
        let (qr, rn, rv) = (region.q, table[15], region.valid);
        let inv = meta.advice_column();
        let asia = IsZeroChip::configure(
            meta,
            |m| m.query_selector(qr),
            |m| cur(m, rn) - constant(string("ASIA")),
            inv,
        );
        let asia_expr = asia.expr();
        meta.create_gate("region filter", move |m| {
            vec![m.query_selector(qr) * (cur(m, rv) - asia_expr.clone())]
        });

        let j_nr = JoinConfig::configure(meta, &nation, table[13], &region, table[14], &[]);
        let j_oc = JoinConfig::configure(meta, &orders, table[3], &customer, table[0], &[table[1]]);
        let orders_ok = Rel {
            q: orders.q,
            valid: j_oc.joins,
            cols: vec![],
        };
        let j_lo = JoinConfig::configure(
            meta,
            &lineitem,
            table[5],
            &orders_ok,
            table[2],
            &[j_oc.attrs[0]],
        );
        let lineitem_o = Rel {
            q: lineitem.q,
            valid: j_lo.joins,
            cols: vec![],
        };
        let j_ls = JoinConfig::configure(
            meta,
            &lineitem_o,
            table[6],
            &supplier,
            table[9],
            &[table[10]],
        );
        let (ql, cn, sn, ls) = (lineitem.q, j_lo.attrs[0], j_ls.attrs[0], j_ls.joins);
        let inv = meta.advice_column();
        let same_nation = IsZeroChip::configure(
            meta,
            |m| m.query_selector(ql),
            |m| cur(m, cn) - cur(m, sn),
            inv,
        );
        let shared = meta.advice_column();
        let same_expr = same_nation.expr();
        meta.create_gate("customer and supplier share a nation", move |m| {
            vec![m.query_selector(ql) * (cur(m, shared) - cur(m, ls) * same_expr.clone())]
        });
        let lineitem_s = Rel {
            q: lineitem.q,
            valid: shared,
            cols: vec![],
        };
        let nation_ok = Rel {
            q: nation.q,
            valid: j_nr.joins,
            cols: vec![],
        };
        let j_ln =
            JoinConfig::configure(meta, &lineitem_s, sn, &nation_ok, table[11], &[table[12]]);
        let revenue = meta.advice_column();
        let (price, disc) = (table[7], table[8]);
        meta.create_gate("revenue", move |m| {
            vec![m.query_selector(ql) * (cur(m, revenue) - cur(m, price) * (one() - cur(m, disc)))]
        });
        let joined = Rel {
            q: lineitem.q,
            valid: j_ln.joins,
            cols: vec![],
        };
        let group = GroupConfig::configure(meta, &joined, j_ln.attrs[0], &[], &[revenue]);
        let out = group.output.columns.clone();
        let order = OrderConfig::configure(meta, &group.output, move |m, rot| {
            constant(REV_OFFSET) - m.query_advice(out[1], rot)
        });
        Q5Config {
            table,
            rels,
            from,
            to,
            asia,
            same_nation,
            shared,
            revenue,
            joins: [j_nr, j_oc, j_lo, j_ls, j_ln],
            group,
            order,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let j = &config.joins;
        let key_chips = comparisons(
            &[
                config.from,
                config.to,
                j[0].lt,
                j[1].lt,
                j[2].lt,
                j[3].lt,
                j[4].lt,
            ],
            &mut layouter,
        )?;
        let group_chip = &comparisons(&[config.group.order], &mut layouter)?[0];
        let order_chip = &comparisons(&[config.order.lt], &mut layouter)?[0];
        let asia = IsZeroChip::construct(config.asia.clone());
        let same_nation = IsZeroChip::construct(config.same_nation.clone());
        let [nc, no, nl, ns, nn, nr] = self.sizes;
        let n = self.rows();
        let c = &self.columns;
        let groups = self.result();
        let result: Vec<Vec<F>> = groups
            .iter()
            .map(|g| g.iter().map(|&v| signed(v)).collect())
            .collect();
        let cells = layouter.assign_region(
            || "q5",
            |mut region| {
                for (i, col) in c.iter().enumerate() {
                    for (row, &v) in col.iter().enumerate() {
                        put(&mut region, config.table[i], row, v)?;
                    }
                }
                let asia_code = string("ASIA");
                let mut valid: Vec<Vec<bool>> = self.sizes.iter().map(|&s| vec![true; s]).collect();
                for (t, rel) in config.rels.iter().enumerate() {
                    for row in 0..self.sizes[t] {
                        rel.q.enable(&mut region, row)?;
                    }
                }
                for row in 0..no {
                    let d = c[4][row];
                    key_chips[0].assign(&mut region, row, &[signed(Q5_FROM)], &[signed(d)])?;
                    key_chips[1].assign(
                        &mut region,
                        row,
                        &[signed(d), F::ONE],
                        &[signed(Q5_TO)],
                    )?;
                    valid[1][row] = (Q5_FROM..Q5_TO).contains(&d);
                }
                for row in 0..nr {
                    asia.assign(
                        &mut region,
                        row,
                        Value::known(signed::<F>(c[15][row] - asia_code)),
                    )?;
                    valid[5][row] = c[15][row] == asia_code;
                }
                for (t, rel) in config.rels.iter().enumerate() {
                    for row in 0..self.sizes[t] {
                        put(&mut region, rel.valid, row, valid[t][row] as i128)?;
                    }
                }
                let flags =
                    |j: &[Option<Vec<i128>>]| j.iter().map(Option::is_some).collect::<Vec<bool>>();
                let attr = |j: &[Option<Vec<i128>>]| {
                    j.iter()
                        .map(|a| a.as_ref().map_or(0, |a| a[0]))
                        .collect::<Vec<i128>>()
                };
                let nr_j = j[0].assign(
                    &mut region,
                    &key_chips[2],
                    &c[13],
                    &valid[4],
                    &c[14],
                    &valid[5],
                    &[],
                    nr + nn,
                )?;
                let oc_j = j[1].assign(
                    &mut region,
                    &key_chips[3],
                    &c[3],
                    &valid[1],
                    &c[0],
                    &valid[0],
                    &[c[1].clone()],
                    nc + no,
                )?;
                let lo_j = j[2].assign(
                    &mut region,
                    &key_chips[4],
                    &c[5],
                    &valid[2],
                    &c[2],
                    &flags(&oc_j),
                    &[attr(&oc_j)],
                    no + nl,
                )?;
                let ls_j = j[3].assign(
                    &mut region,
                    &key_chips[5],
                    &c[6],
                    &flags(&lo_j),
                    &c[9],
                    &valid[3],
                    &[c[10].clone()],
                    ns + nl,
                )?;
                let (cn, sn) = (attr(&lo_j), attr(&ls_j));
                let mut shared = vec![false; nl];
                for row in 0..nl {
                    same_nation.assign(
                        &mut region,
                        row,
                        Value::known(signed::<F>(cn[row] - sn[row])),
                    )?;
                    shared[row] = ls_j[row].is_some() && cn[row] == sn[row];
                    put(&mut region, config.shared, row, shared[row] as i128)?;
                    put(
                        &mut region,
                        config.revenue,
                        row,
                        c[7][row] * (1 - c[8][row]),
                    )?;
                }
                let ln_j = j[4].assign(
                    &mut region,
                    &key_chips[6],
                    &sn,
                    &shared,
                    &c[11],
                    &flags(&nr_j),
                    &[c[12].clone()],
                    nn + nl,
                )?;
                let rows: Vec<(bool, Vec<i128>)> = (0..nl)
                    .map(|r| match &ln_j[r] {
                        Some(a) => (true, vec![a[0], c[7][r] * (1 - c[8][r])]),
                        None => (false, vec![0; 2]),
                    })
                    .collect();
                config.group.assign(&mut region, group_chip, &rows, n)?;
                let key = |r: usize| REV_OFFSET - groups.get(r).map_or(0, |g| g[1]);
                for row in 1..n {
                    order_chip.assign(
                        &mut region,
                        row,
                        &[signed(key(row - 1))],
                        &[signed(key(row))],
                    )?;
                }
                config.group.output.assign_fields(&mut region, n, &result)
            },
        )?;
        config.group.output.publish(&mut layouter, &cells)
    }
}

/// Proves and verifies Q5 at degree `k`, bound to the data owner's
/// commitments to the tables.
pub fn run_q5(k: u32, tables: &Q5Tables, proof_path: &str) -> MicroResult {
    let circuit = Q5Circuit::<Fp>::new(tables);
    let public = transpose(&circuit.result(), 2);
    let table = circuit.columns.iter().map(|c| pad(c)).collect();
    prove_fields(circuit, k, public, Some(table), proof_path)
}

// ---------------------------------------------------------------------------
// Q9: profit per nation and year, over every lineitem.
// ---------------------------------------------------------------------------

/// The largest order year; years lie within 255 below it, so a group key
/// `name * 2^8 + (YEAR_TOP - year)` is injective and orders by name, then
/// year descending.
const YEAR_TOP: i128 = 2047;
/// Bytes of a comparison of a partsupp key `partkey * 2^24 + suppkey`.
const PAIR_BYTES: usize = 6;
/// Bytes of a comparison of a Q9 group key: a nation name of at most 15
/// ASCII bytes and the year byte.
const NAME_YEAR_BYTES: usize = 16;

/// The tables, in commitment order.
pub struct Q9Tables {
    pub part: [Col; 1],     // p_partkey
    pub supplier: [Col; 2], // s_suppkey, s_nationkey
    // l_orderkey, l_partkey, l_suppkey, l_quantity, l_extendedprice, l_discount
    pub lineitem: [Col; 6],
    pub partsupp: [Col; 3], // ps_partkey, ps_suppkey, ps_supplycost
    pub orders: [Col; 2],   // o_orderkey, o_orderdate_year
    pub nation: [Col; 2],   // n_nationkey, n_name
}

#[derive(Clone, Debug)]
pub struct Q9Config<F: Field> {
    table: Vec<Column<Advice>>,
    rels: [Rel; 6],
    year: LtEqGenericConfig<F, 1>,
    l_pair: Column<Advice>,
    ps_pair: Column<Advice>,
    amount: Column<Advice>,
    key: Column<Advice>,
    joins: [JoinConfig<F>; 4],
    join_ps: JoinConfig<F, PAIR_BYTES>,
    group: GroupConfig<F, NAME_YEAR_BYTES>,
    order: OrderConfig<F, NAME_YEAR_BYTES>,
}

#[derive(Clone, Default)]
pub struct Q9Circuit<F> {
    pub columns: Vec<Vec<i128>>,
    pub sizes: [usize; 6],
    _f: PhantomData<F>,
}

const Q9_TABLES: [std::ops::Range<usize>; 6] = [0..1, 1..3, 3..9, 9..12, 12..14, 14..16];

impl<F: Field> Q9Circuit<F> {
    pub fn new(t: &Q9Tables) -> Self {
        let tables: [&[Col]; 6] = [
            &t.part,
            &t.supplier,
            &t.lineitem,
            &t.partsupp,
            &t.orders,
            &t.nation,
        ];
        Self {
            sizes: tables.map(|cols| cols[0].len()),
            columns: tables
                .iter()
                .flat_map(|cols| cols.iter().map(Col::values))
                .collect(),
            _f: PhantomData,
        }
    }

    pub fn rows(&self) -> usize {
        let [p, s, l, ps, o, n] = self.sizes;
        [l + p, l + s, l + ps, l + o, l + n]
            .into_iter()
            .max()
            .unwrap()
    }

    /// (group key, n_name, o_orderdate_year, sum_profit), by name, then year
    /// descending.
    pub fn result(&self) -> Vec<Vec<i128>> {
        let c = &self.columns;
        let [np, ns, nl, nps, no, nn] = self.sizes;
        let parts: BTreeSet<i128> = c[0][..np].iter().copied().collect();
        let suppliers: HashMap<i128, i128> = (0..ns).map(|r| (c[1][r], c[2][r])).collect();
        let costs: HashMap<(i128, i128), i128> =
            (0..nps).map(|r| ((c[9][r], c[10][r]), c[11][r])).collect();
        let years: HashMap<i128, i128> = (0..no).map(|r| (c[12][r], c[13][r])).collect();
        let names: HashMap<i128, i128> = (0..nn).map(|r| (c[14][r], c[15][r])).collect();
        let mut groups: std::collections::BTreeMap<i128, (i128, i128, i128)> = Default::default();
        for r in 0..nl {
            let (Some(&nation), Some(&cost), Some(&year)) = (
                suppliers.get(&c[5][r]),
                costs.get(&(c[4][r], c[5][r])),
                years.get(&c[3][r]),
            ) else {
                continue;
            };
            let Some(&name) = names.get(&nation) else {
                continue;
            };
            if !parts.contains(&c[4][r]) {
                continue;
            }
            let amount = c[7][r] * (1 - c[8][r]) - cost * c[6][r];
            groups
                .entry((name << 8) + YEAR_TOP - year)
                .or_insert((name, year, 0))
                .2 += amount;
        }
        groups
            .into_iter()
            .map(|(k, (n, y, s))| vec![k, n, y, s])
            .collect()
    }
}

impl<F: Field> Circuit<F> for Q9Circuit<F> {
    type Config = Q9Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            columns: vec![],
            sizes: [0; 6],
            _f: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let table: Vec<_> = (0..16).map(|_| meta.unblinded_advice_column()).collect();
        let rels = Q9_TABLES.map(|range| Rel {
            q: meta.complex_selector(),
            valid: meta.advice_column(),
            cols: table[range].to_vec(),
        });
        let [part, supplier, lineitem, partsupp, orders, nation] = rels.clone();
        for rel in &rels {
            let (q, v) = (rel.q, rel.valid);
            meta.create_gate("every row is valid", move |m| {
                vec![m.query_selector(q) * (cur(m, v) - one())]
            });
        }
        let (qo, oy) = (orders.q, table[13]);
        let year = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(qo),
            |_| vec![constant(YEAR_TOP - 255)],
            |m| vec![cur(m, oy)],
        );
        meta.create_gate("years lie in the key's year byte", move |m| {
            vec![m.query_selector(qo) * (year.is_lt(m, None) - one())]
        });
        let (l_pair, ps_pair) = (meta.advice_column(), meta.advice_column());
        let (ql, lp, ls) = (lineitem.q, table[4], table[5]);
        meta.create_gate("lineitem's partsupp key", move |m| {
            vec![
                m.query_selector(ql)
                    * (cur(m, l_pair) - cur(m, lp) * constant(1 << 24) - cur(m, ls)),
            ]
        });
        let (qps, pp, psu) = (partsupp.q, table[9], table[10]);
        meta.create_gate("partsupp's key", move |m| {
            vec![
                m.query_selector(qps)
                    * (cur(m, ps_pair) - cur(m, pp) * constant(1 << 24) - cur(m, psu)),
            ]
        });

        let j_lp = JoinConfig::configure(meta, &lineitem, table[4], &part, table[0], &[]);
        let after = |j: &Column<Advice>| Rel {
            q: lineitem.q,
            valid: *j,
            cols: vec![],
        };
        let j_ls = JoinConfig::configure(
            meta,
            &after(&j_lp.joins),
            table[5],
            &supplier,
            table[1],
            &[table[2]],
        );
        let join_ps = JoinConfig::configure(
            meta,
            &after(&j_ls.joins),
            l_pair,
            &partsupp,
            ps_pair,
            &[table[11]],
        );
        let j_lo = JoinConfig::configure(
            meta,
            &after(&join_ps.joins),
            table[3],
            &orders,
            table[12],
            &[table[13]],
        );
        let j_ln = JoinConfig::configure(
            meta,
            &after(&j_lo.joins),
            j_ls.attrs[0],
            &nation,
            table[14],
            &[table[15]],
        );

        let amount = meta.advice_column();
        let (qty, price, disc, cost) = (table[6], table[7], table[8], join_ps.attrs[0]);
        meta.create_gate("amount", move |m| {
            let volume = cur(m, price) * (one() - cur(m, disc));
            vec![m.query_selector(ql) * (cur(m, amount) - volume + cur(m, cost) * cur(m, qty))]
        });
        let key = meta.advice_column();
        let (name, y) = (j_ln.attrs[0], j_lo.attrs[0]);
        meta.create_gate("group key", move |m| {
            let packed = cur(m, name) * constant(1 << 8) + constant(YEAR_TOP) - cur(m, y);
            vec![m.query_selector(ql) * (cur(m, key) - packed)]
        });
        let group = GroupConfig::configure(meta, &after(&j_ln.joins), key, &[name, y], &[amount]);
        let out = group.output.columns.clone();
        let order = OrderConfig::configure(meta, &group.output, move |m, rot| {
            m.query_advice(out[0], rot)
        });
        Q9Config {
            table,
            rels,
            year,
            l_pair,
            ps_pair,
            amount,
            key,
            joins: [j_lp, j_ls, j_lo, j_ln],
            join_ps,
            group,
            order,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let j = &config.joins;
        let key_chips = comparisons(&[j[0].lt, j[1].lt, j[2].lt, j[3].lt], &mut layouter)?;
        let pair_chip = &comparisons(&[config.join_ps.lt], &mut layouter)?[0];
        let year_chip = &comparisons(&[config.year], &mut layouter)?[0];
        let sort_chips = comparisons(&[config.group.order, config.order.lt], &mut layouter)?;
        let [np, ns, nl, nps, no, nn] = self.sizes;
        let n = self.rows();
        let c = &self.columns;
        let groups = self.result();
        let result: Vec<Vec<F>> = groups
            .iter()
            .map(|g| g.iter().map(|&v| signed(v)).collect())
            .collect();
        let cells = layouter.assign_region(
            || "q9",
            |mut region| {
                for (i, col) in c.iter().enumerate() {
                    for (row, &v) in col.iter().enumerate() {
                        put(&mut region, config.table[i], row, v)?;
                    }
                }
                for (rel, &size) in config.rels.iter().zip(&self.sizes) {
                    for row in 0..size {
                        rel.q.enable(&mut region, row)?;
                        put(&mut region, rel.valid, row, 1)?;
                    }
                }
                for row in 0..no {
                    year_chip.assign(
                        &mut region,
                        row,
                        &[signed(YEAR_TOP - 255)],
                        &[signed(c[13][row])],
                    )?;
                }
                let l_pairs: Vec<i128> = (0..nl).map(|r| (c[4][r] << 24) + c[5][r]).collect();
                let ps_pairs: Vec<i128> = (0..nps).map(|r| (c[9][r] << 24) + c[10][r]).collect();
                for (row, &v) in l_pairs.iter().enumerate() {
                    put(&mut region, config.l_pair, row, v)?;
                }
                for (row, &v) in ps_pairs.iter().enumerate() {
                    put(&mut region, config.ps_pair, row, v)?;
                }
                let flags =
                    |j: &[Option<Vec<i128>>]| j.iter().map(Option::is_some).collect::<Vec<bool>>();
                let attr = |j: &[Option<Vec<i128>>]| {
                    j.iter()
                        .map(|a| a.as_ref().map_or(0, |a| a[0]))
                        .collect::<Vec<i128>>()
                };
                let all = |size: usize| vec![true; size];
                let lp = j[0].assign(
                    &mut region,
                    &key_chips[0],
                    &c[4],
                    &all(nl),
                    &c[0],
                    &all(np),
                    &[],
                    np + nl,
                )?;
                let ls = j[1].assign(
                    &mut region,
                    &key_chips[1],
                    &c[5],
                    &flags(&lp),
                    &c[1],
                    &all(ns),
                    &[c[2].clone()],
                    ns + nl,
                )?;
                let lps = config.join_ps.assign(
                    &mut region,
                    pair_chip,
                    &l_pairs,
                    &flags(&ls),
                    &ps_pairs,
                    &all(nps),
                    &[c[11].clone()],
                    nps + nl,
                )?;
                let lo = j[2].assign(
                    &mut region,
                    &key_chips[2],
                    &c[3],
                    &flags(&lps),
                    &c[12],
                    &all(no),
                    &[c[13].clone()],
                    no + nl,
                )?;
                let nation = attr(&ls);
                let ln = j[3].assign(
                    &mut region,
                    &key_chips[3],
                    &nation,
                    &flags(&lo),
                    &c[14],
                    &all(nn),
                    &[c[15].clone()],
                    nn + nl,
                )?;
                let (cost, year, name) = (attr(&lps), attr(&lo), attr(&ln));
                let mut rows = Vec::with_capacity(nl);
                for r in 0..nl {
                    let amount = c[7][r] * (1 - c[8][r]) - cost[r] * c[6][r];
                    let key = (name[r] << 8) + YEAR_TOP - year[r];
                    put(&mut region, config.amount, r, amount)?;
                    put(&mut region, config.key, r, key)?;
                    rows.push((ln[r].is_some(), vec![key, name[r], year[r], amount]));
                }
                config.group.assign(&mut region, &sort_chips[0], &rows, n)?;
                let key = |r: usize| groups.get(r).map_or(0, |g| g[0]);
                for row in 1..n {
                    sort_chips[1].assign(
                        &mut region,
                        row,
                        &[signed(key(row - 1))],
                        &[signed(key(row))],
                    )?;
                }
                config.group.output.assign_fields(&mut region, n, &result)
            },
        )?;
        config.group.output.publish(&mut layouter, &cells)
    }
}

/// Proves and verifies Q9 at degree `k`, bound to the data owner's
/// commitments to the tables.
pub fn run_q9(k: u32, tables: &Q9Tables, proof_path: &str) -> MicroResult {
    let circuit = Q9Circuit::<Fp>::new(tables);
    let public = transpose(&circuit.result(), 4);
    let table = circuit.columns.iter().map(|c| pad(c)).collect();
    prove_fields(circuit, k, public, Some(table), proof_path)
}

// ---------------------------------------------------------------------------
// Q8: Brazil's share of American volume for one part type, per year.
// ---------------------------------------------------------------------------

/// `DATE '1995-01-01'` and `DATE '1996-12-31'`, both included.
const Q8_FROM: i128 = 9131;
const Q8_TO: i128 = 9861;
const Q8_TYPE: &str = "ECONOMY ANODIZED STEEL";

/// The tables, in commitment order.
pub struct Q8Tables {
    pub part: [Col; 2],     // p_partkey, p_type
    pub supplier: [Col; 2], // s_suppkey, s_nationkey
    // l_orderkey, l_partkey, l_suppkey, l_extendedprice, l_discount
    pub lineitem: [Col; 5],
    pub orders: [Col; 4], // o_orderkey, o_custkey, o_orderdate, o_orderdate_year
    pub customer: [Col; 2], // c_custkey, c_nationkey
    pub nation: [Col; 3], // n_nationkey, n_name, n_regionkey
    pub region: [Col; 2], // r_regionkey, r_name
}

#[derive(Clone, Debug)]
pub struct Q8Config<F: Field> {
    table: Vec<Column<Advice>>,
    rels: [Rel; 7],
    part_type: IsZeroConfig<F>,
    america: IsZeroConfig<F>,
    brazil: IsZeroConfig<F>,
    from: LtEqGenericConfig<F, KEY_BYTES>,
    to: LtEqGenericConfig<F, KEY_BYTES>,
    volume: Column<Advice>,
    brazil_volume: Column<Advice>,
    joins: [JoinConfig<F>; 7],
    group: GroupConfig<F, KEY_BYTES>,
    order: OrderConfig<F, KEY_BYTES>,
}

#[derive(Clone, Default)]
pub struct Q8Circuit<F> {
    pub columns: Vec<Vec<i128>>,
    pub sizes: [usize; 7],
    _f: PhantomData<F>,
}

const Q8_TABLES: [std::ops::Range<usize>; 7] = [0..2, 2..4, 4..9, 9..13, 13..15, 15..18, 18..20];

impl<F: Field> Q8Circuit<F> {
    pub fn new(t: &Q8Tables) -> Self {
        let tables: [&[Col]; 7] = [
            &t.part,
            &t.supplier,
            &t.lineitem,
            &t.orders,
            &t.customer,
            &t.nation,
            &t.region,
        ];
        Self {
            sizes: tables.map(|cols| cols[0].len()),
            columns: tables
                .iter()
                .flat_map(|cols| cols.iter().map(Col::values))
                .collect(),
            _f: PhantomData,
        }
    }

    pub fn rows(&self) -> usize {
        let [p, s, l, o, c, n, r] = self.sizes;
        [n + r, c + n, o + c, l + p, l + o, l + s, l + n]
            .into_iter()
            .max()
            .unwrap()
    }

    /// (o_orderdate_year, Brazil's volume, all volume), by year.
    pub fn result(&self) -> Vec<Vec<i128>> {
        let c = &self.columns;
        let [np, ns, nl, no, nc, nn, nr] = self.sizes;
        let america = string("AMERICA");
        let regions: BTreeSet<i128> = (0..nr)
            .filter(|&r| c[19][r] == america)
            .map(|r| c[18][r])
            .collect();
        let american: BTreeSet<i128> = (0..nn)
            .filter(|&r| regions.contains(&c[17][r]))
            .map(|r| c[15][r])
            .collect();
        let names: HashMap<i128, i128> = (0..nn).map(|r| (c[15][r], c[16][r])).collect();
        let customers: BTreeSet<i128> = (0..nc)
            .filter(|&r| american.contains(&c[14][r]))
            .map(|r| c[13][r])
            .collect();
        let orders: HashMap<i128, i128> = (0..no)
            .filter(|&r| (Q8_FROM..=Q8_TO).contains(&c[11][r]) && customers.contains(&c[10][r]))
            .map(|r| (c[9][r], c[12][r]))
            .collect();
        let kind = string(Q8_TYPE);
        let parts: BTreeSet<i128> = (0..np)
            .filter(|&r| c[1][r] == kind)
            .map(|r| c[0][r])
            .collect();
        let suppliers: HashMap<i128, i128> = (0..ns).map(|r| (c[2][r], c[3][r])).collect();
        let brazil = string("BRAZIL");
        let mut groups: std::collections::BTreeMap<i128, (i128, i128)> = Default::default();
        for r in 0..nl {
            let (Some(&year), Some(nation)) = (orders.get(&c[4][r]), suppliers.get(&c[6][r]))
            else {
                continue;
            };
            let Some(&name) = names.get(nation) else {
                continue;
            };
            if !parts.contains(&c[5][r]) {
                continue;
            }
            let volume = c[7][r] * (1 - c[8][r]);
            let g = groups.entry(year).or_default();
            g.0 += if name == brazil { volume } else { 0 };
            g.1 += volume;
        }
        groups
            .into_iter()
            .map(|(y, (b, v))| vec![y, b, v])
            .collect()
    }
}

impl<F: Field> Circuit<F> for Q8Circuit<F> {
    type Config = Q8Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            columns: vec![],
            sizes: [0; 7],
            _f: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let table: Vec<_> = (0..20).map(|_| meta.unblinded_advice_column()).collect();
        let rels = Q8_TABLES.map(|range| Rel {
            q: meta.complex_selector(),
            valid: meta.advice_column(),
            cols: table[range].to_vec(),
        });
        let [part, supplier, lineitem, orders, customer, nation, region] = rels.clone();
        for rel in [&supplier, &lineitem, &customer, &nation] {
            let (q, v) = (rel.q, rel.valid);
            meta.create_gate("every row is valid", move |m| {
                vec![m.query_selector(q) * (cur(m, v) - one())]
            });
        }
        let equals =
            |meta: &mut ConstraintSystem<F>, rel: &Rel, col: Column<Advice>, value: &str| {
                let (q, v, value) = (rel.q, rel.valid, string(value));
                let inv = meta.advice_column();
                let chip = IsZeroChip::configure(
                    meta,
                    |m| m.query_selector(q),
                    |m| cur(m, col) - constant(value),
                    inv,
                );
                let expr = chip.expr();
                meta.create_gate("equality filter", move |m| {
                    vec![m.query_selector(q) * (cur(m, v) - expr.clone())]
                });
                chip
            };
        let part_type = equals(meta, &part, table[1], Q8_TYPE);
        let america = equals(meta, &region, table[19], "AMERICA");
        let (qo, od) = (orders.q, table[11]);
        let from = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(qo),
            |_| vec![constant(Q8_FROM)],
            |m| vec![cur(m, od)],
        );
        let to = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(qo),
            |m| vec![cur(m, od)],
            |_| vec![constant(Q8_TO)],
        );
        let ov = orders.valid;
        meta.create_gate("orders filter", move |m| {
            vec![m.query_selector(qo) * (cur(m, ov) - from.is_lt(m, None) * to.is_lt(m, None))]
        });

        let only = |rel: &Rel, valid: Column<Advice>| Rel {
            q: rel.q,
            valid,
            cols: vec![],
        };
        let j_nr = JoinConfig::configure(meta, &nation, table[17], &region, table[18], &[]);
        let j_cn = JoinConfig::configure(
            meta,
            &customer,
            table[14],
            &only(&nation, j_nr.joins),
            table[15],
            &[],
        );
        let j_oc = JoinConfig::configure(
            meta,
            &orders,
            table[10],
            &only(&customer, j_cn.joins),
            table[13],
            &[],
        );
        let j_lp = JoinConfig::configure(meta, &lineitem, table[5], &part, table[0], &[]);
        let j_lo = JoinConfig::configure(
            meta,
            &only(&lineitem, j_lp.joins),
            table[4],
            &only(&orders, j_oc.joins),
            table[9],
            &[table[12]],
        );
        let j_ls = JoinConfig::configure(
            meta,
            &only(&lineitem, j_lo.joins),
            table[6],
            &supplier,
            table[2],
            &[table[3]],
        );
        let j_ln = JoinConfig::configure(
            meta,
            &only(&lineitem, j_ls.joins),
            j_ls.attrs[0],
            &nation,
            table[15],
            &[table[16]],
        );

        let ql = lineitem.q;
        let (volume, brazil_volume) = (meta.advice_column(), meta.advice_column());
        let (price, disc) = (table[7], table[8]);
        meta.create_gate("volume", move |m| {
            vec![m.query_selector(ql) * (cur(m, volume) - cur(m, price) * (one() - cur(m, disc)))]
        });
        let name = j_ln.attrs[0];
        let inv = meta.advice_column();
        let brazil = IsZeroChip::configure(
            meta,
            |m| m.query_selector(ql),
            |m| cur(m, name) - constant(string("BRAZIL")),
            inv,
        );
        let brazil_expr = brazil.expr();
        meta.create_gate("Brazil's volume", move |m| {
            vec![
                m.query_selector(ql)
                    * (cur(m, brazil_volume) - brazil_expr.clone() * cur(m, volume)),
            ]
        });
        let group = GroupConfig::configure(
            meta,
            &only(&lineitem, j_ln.joins),
            j_lo.attrs[0],
            &[],
            &[brazil_volume, volume],
        );
        let out = group.output.columns.clone();
        let order = OrderConfig::configure(meta, &group.output, move |m, rot| {
            m.query_advice(out[0], rot)
        });
        Q8Config {
            table,
            rels,
            part_type,
            america,
            brazil,
            from,
            to,
            volume,
            brazil_volume,
            joins: [j_nr, j_cn, j_oc, j_lp, j_lo, j_ls, j_ln],
            group,
            order,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let j = &config.joins;
        let mut chips = vec![config.from, config.to];
        chips.extend(j.iter().map(|j| j.lt));
        chips.extend([config.group.order, config.order.lt]);
        let chips = comparisons(&chips, &mut layouter)?;
        let (part_type, america, brazil) = (
            IsZeroChip::construct(config.part_type.clone()),
            IsZeroChip::construct(config.america.clone()),
            IsZeroChip::construct(config.brazil.clone()),
        );
        let [np, ns, nl, no, nc, nn, nr] = self.sizes;
        let n = self.rows();
        let c = &self.columns;
        let groups = self.result();
        let result: Vec<Vec<F>> = groups
            .iter()
            .map(|g| g.iter().map(|&v| signed(v)).collect())
            .collect();
        let cells = layouter.assign_region(
            || "q8",
            |mut region| {
                for (i, col) in c.iter().enumerate() {
                    for (row, &v) in col.iter().enumerate() {
                        put(&mut region, config.table[i], row, v)?;
                    }
                }
                let mut valid: Vec<Vec<bool>> = self.sizes.iter().map(|&s| vec![true; s]).collect();
                for (t, rel) in config.rels.iter().enumerate() {
                    for row in 0..self.sizes[t] {
                        rel.q.enable(&mut region, row)?;
                    }
                }
                let kind = string(Q8_TYPE);
                for row in 0..np {
                    part_type.assign(
                        &mut region,
                        row,
                        Value::known(signed::<F>(c[1][row] - kind)),
                    )?;
                    valid[0][row] = c[1][row] == kind;
                }
                for row in 0..no {
                    let d = c[11][row];
                    chips[0].assign(&mut region, row, &[signed(Q8_FROM)], &[signed(d)])?;
                    chips[1].assign(&mut region, row, &[signed(d)], &[signed(Q8_TO)])?;
                    valid[3][row] = (Q8_FROM..=Q8_TO).contains(&d);
                }
                let code = string("AMERICA");
                for row in 0..nr {
                    america.assign(
                        &mut region,
                        row,
                        Value::known(signed::<F>(c[19][row] - code)),
                    )?;
                    valid[6][row] = c[19][row] == code;
                }
                for (t, rel) in config.rels.iter().enumerate() {
                    for row in 0..self.sizes[t] {
                        put(&mut region, rel.valid, row, valid[t][row] as i128)?;
                    }
                }
                let flags =
                    |j: &[Option<Vec<i128>>]| j.iter().map(Option::is_some).collect::<Vec<bool>>();
                let attr = |j: &[Option<Vec<i128>>]| {
                    j.iter()
                        .map(|a| a.as_ref().map_or(0, |a| a[0]))
                        .collect::<Vec<i128>>()
                };
                let nr_j = j[0].assign(
                    &mut region,
                    &chips[2],
                    &c[17],
                    &valid[5],
                    &c[18],
                    &valid[6],
                    &[],
                    nn + nr,
                )?;
                let cn_j = j[1].assign(
                    &mut region,
                    &chips[3],
                    &c[14],
                    &valid[4],
                    &c[15],
                    &flags(&nr_j),
                    &[],
                    nc + nn,
                )?;
                let oc_j = j[2].assign(
                    &mut region,
                    &chips[4],
                    &c[10],
                    &valid[3],
                    &c[13],
                    &flags(&cn_j),
                    &[],
                    no + nc,
                )?;
                let lp_j = j[3].assign(
                    &mut region,
                    &chips[5],
                    &c[5],
                    &valid[2],
                    &c[0],
                    &valid[0],
                    &[],
                    nl + np,
                )?;
                let lo_j = j[4].assign(
                    &mut region,
                    &chips[6],
                    &c[4],
                    &flags(&lp_j),
                    &c[9],
                    &flags(&oc_j),
                    &[c[12].clone()],
                    nl + no,
                )?;
                let ls_j = j[5].assign(
                    &mut region,
                    &chips[7],
                    &c[6],
                    &flags(&lo_j),
                    &c[2],
                    &valid[1],
                    &[c[3].clone()],
                    nl + ns,
                )?;
                let ln_j = j[6].assign(
                    &mut region,
                    &chips[8],
                    &attr(&ls_j),
                    &flags(&ls_j),
                    &c[15],
                    &valid[5],
                    &[c[16].clone()],
                    nl + nn,
                )?;
                let (year, name) = (attr(&lo_j), attr(&ln_j));
                let code = string("BRAZIL");
                let mut rows = Vec::with_capacity(nl);
                for r in 0..nl {
                    let volume = c[7][r] * (1 - c[8][r]);
                    let share = if name[r] == code { volume } else { 0 };
                    brazil.assign(&mut region, r, Value::known(signed::<F>(name[r] - code)))?;
                    put(&mut region, config.volume, r, volume)?;
                    put(&mut region, config.brazil_volume, r, share)?;
                    rows.push((ln_j[r].is_some(), vec![year[r], share, volume]));
                }
                config.group.assign(&mut region, &chips[9], &rows, n)?;
                let key = |r: usize| groups.get(r).map_or(0, |g| g[0]);
                for row in 1..n {
                    chips[10].assign(
                        &mut region,
                        row,
                        &[signed(key(row - 1))],
                        &[signed(key(row))],
                    )?;
                }
                config.group.output.assign_fields(&mut region, n, &result)
            },
        )?;
        config.group.output.publish(&mut layouter, &cells)
    }
}

/// Proves and verifies Q8 at degree `k`, bound to the data owner's
/// commitments to the tables.
pub fn run_q8(k: u32, tables: &Q8Tables, proof_path: &str) -> MicroResult {
    let circuit = Q8Circuit::<Fp>::new(tables);
    let public = transpose(&circuit.result(), 3);
    let table = circuit.columns.iter().map(|c| pad(c)).collect();
    prove_fields(circuit, k, public, Some(table), proof_path)
}

/// Proves and verifies Q3 at degree `k`, bound to the data owner's
/// commitments to the tables.
pub fn run_q3(k: u32, tables: &Q3Tables, proof_path: &str) -> MicroResult {
    let circuit = Q3Circuit::<Fp>::new(tables);
    let public = transpose(&circuit.result(), 4);
    let table = circuit.columns.iter().map(|c| pad(c)).collect();
    prove_fields(circuit, k, public, Some(table), proof_path)
}

fn transpose(rows: &[Vec<i128>], width: usize) -> Vec<Vec<Fp>> {
    (0..width)
        .map(|c| rows.iter().map(|r| signed::<Fp>(r[c])).collect())
        .collect()
}

fn pad(column: &[i128]) -> Vec<Fp> {
    column.iter().map(|&v| signed::<Fp>(v)).collect()
}

/// The degree a circuit of `rows` rows needs (halo2 keeps a few rows for
/// blinding).
pub fn degree(rows: usize) -> u32 {
    (rows + 16).next_power_of_two().trailing_zeros()
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    fn lcg(seed: u64) -> impl FnMut(u64) -> i64 {
        let mut s = seed;
        move |b| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((s >> 33) % b) as i64
        }
    }

    fn q3_tables() -> Q3Tables {
        let mut r = lcg(3);
        let segments = ["BUILDING", "MACHINERY", "AUTOMOBILE"];
        let (nc, no, nl) = (30usize, 80usize, 240usize);
        let customer = [
            Col::Int((1..=nc as i64).collect()),
            Col::Str(
                (0..nc)
                    .map(|_| segments[r(3) as usize].to_string())
                    .collect(),
            ),
        ];
        let orders = [
            Col::Int((1..=no as i64).map(|k| k * 4).collect()),
            Col::Int((0..no).map(|_| 1 + r(nc as u64 + 5)).collect()),
            Col::Int((0..no).map(|_| Q3_DATE as i64 - 100 + r(200)).collect()),
            Col::Int((0..no).map(|_| r(2)).collect()),
        ];
        let lineitem = [
            Col::Int((0..nl).map(|_| 4 * (1 + r(no as u64 + 10))).collect()),
            Col::Int((0..nl).map(|_| 100 + r(10_000)).collect()),
            Col::Int((0..nl).map(|_| r(11)).collect()),
            Col::Int((0..nl).map(|_| Q3_DATE as i64 - 100 + r(200)).collect()),
        ];
        Q3Tables {
            customer,
            orders,
            lineitem,
        }
    }

    fn mock(circuit: &Q3Circuit<Fp>, result: &[Vec<i128>]) -> bool {
        let k = degree(circuit.rows());
        MockProver::run(k, circuit, transpose(result, 4))
            .unwrap()
            .verify()
            .is_ok()
    }

    fn q18_tables() -> Q18Tables {
        let mut r = lcg(18);
        let (nc, no, nl) = (25usize, 70usize, 220usize);
        Q18Tables {
            customer: [
                Col::Int((1..=nc as i64).collect()),
                Col::Str((1..=nc).map(|k| format!("Customer#{k:09}")).collect()),
            ],
            orders: [
                Col::Int((1..=no as i64).map(|k| k * 4).collect()),
                Col::Int((0..no).map(|_| 1 + r(nc as u64)).collect()),
                Col::Int((0..no).map(|_| 9000 + r(400)).collect()),
                Col::Int((0..no).map(|_| 1000 + r(5_000_000)).collect()),
            ],
            lineitem: [
                Col::Int((0..nl).map(|_| 4 * (1 + r(no as u64))).collect()),
                Col::Int((0..nl).map(|_| 1 + r(50)).collect()),
            ],
        }
    }

    #[test]
    fn q18_accepts_its_result_only() {
        let circuit = Q18Circuit::<Fp>::new(&q18_tables());
        let result = circuit.result();
        let k = degree(circuit.rows());
        let ok = |res: &[Vec<i128>]| {
            MockProver::run(k, &circuit, transpose(res, 6))
                .unwrap()
                .verify()
                .is_ok()
        };
        assert!(result.len() > 3);
        assert!(ok(&result));
        let mut wrong = result.clone();
        wrong[0][5] += 1;
        assert!(!ok(&wrong));
        assert!(!ok(&result[1..]));
    }

    fn q5_tables() -> Q5Tables {
        let mut r = lcg(5);
        let (nc, no, nl, ns) = (30usize, 80usize, 300usize, 10usize);
        let names = ["ALGERIA", "CHINA", "INDIA", "JAPAN", "VIETNAM", "FRANCE"];
        Q5Tables {
            customer: [
                Col::Int((1..=nc as i64).collect()),
                Col::Int((0..nc).map(|_| r(6)).collect()),
            ],
            orders: [
                Col::Int((1..=no as i64).collect()),
                Col::Int((0..no).map(|_| 1 + r(nc as u64)).collect()),
                Col::Int((0..no).map(|_| Q5_FROM as i64 - 100 + r(600)).collect()),
            ],
            lineitem: [
                Col::Int((0..nl).map(|_| 1 + r(no as u64)).collect()),
                Col::Int((0..nl).map(|_| 1 + r(ns as u64)).collect()),
                Col::Int((0..nl).map(|_| 100 + r(10_000)).collect()),
                Col::Int((0..nl).map(|_| r(11)).collect()),
            ],
            supplier: [
                Col::Int((1..=ns as i64).collect()),
                Col::Int((0..ns).map(|_| r(6)).collect()),
            ],
            nation: [
                Col::Int((0..6).collect()),
                Col::Str(names.iter().map(|s| s.to_string()).collect()),
                Col::Int(vec![0, 1, 1, 1, 1, 2]),
            ],
            region: [
                Col::Int((0..3).collect()),
                Col::Str(
                    ["AFRICA", "ASIA", "EUROPE"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                ),
            ],
        }
    }

    fn q9_tables() -> Q9Tables {
        let mut r = lcg(9);
        let (np, ns, no, nl) = (20i64, 8i64, 40usize, 300usize);
        let pairs: Vec<(i64, i64)> = (1..=np)
            .flat_map(|p| [(p, 1 + (p % ns)), (p, 1 + ((p + 3) % ns))])
            .collect();
        let names = [
            "ALGERIA",
            "BRAZIL",
            "CHINA",
            "UNITED KINGDOM",
            "VIETNAM",
            "FRANCE",
        ];
        // A few lineitems name a part or a pair that does not exist.
        let items: Vec<(i64, i64)> = (0..nl)
            .map(|i| {
                if i % 37 == 0 {
                    (np + 1 + r(3), 1)
                } else {
                    pairs[r(pairs.len() as u64) as usize]
                }
            })
            .collect();
        Q9Tables {
            part: [Col::Int((1..=np).collect())],
            supplier: [
                Col::Int((1..=ns).collect()),
                Col::Int((0..ns).map(|_| r(6)).collect()),
            ],
            lineitem: [
                Col::Int((0..nl).map(|_| 1 + r(no as u64)).collect()),
                Col::Int(items.iter().map(|p| p.0).collect()),
                Col::Int(items.iter().map(|p| p.1).collect()),
                Col::Int((0..nl).map(|_| 100 * (1 + r(50))).collect()),
                Col::Int((0..nl).map(|_| 100 + r(10_000)).collect()),
                Col::Int((0..nl).map(|_| r(11)).collect()),
            ],
            partsupp: [
                Col::Int(pairs.iter().map(|p| p.0).collect()),
                Col::Int(pairs.iter().map(|p| p.1).collect()),
                Col::Int(pairs.iter().map(|_| 100 + r(100_000)).collect()),
            ],
            orders: [
                Col::Int((1..=no as i64).collect()),
                Col::Int((0..no).map(|_| 1992 + r(7)).collect()),
            ],
            nation: [
                Col::Int((0..6).collect()),
                Col::Str(names.iter().map(|s| s.to_string()).collect()),
            ],
        }
    }

    #[test]
    fn q9_accepts_its_result_only() {
        let circuit = Q9Circuit::<Fp>::new(&q9_tables());
        let result = circuit.result();
        let k = degree(circuit.rows());
        let ok = |res: &[Vec<i128>]| {
            MockProver::run(k, &circuit, transpose(res, 4))
                .unwrap()
                .verify()
                .is_ok()
        };
        assert!(result.len() > 1, "too few groups to test with");
        assert!(ok(&result));
        let mut wrong = result.clone();
        wrong[0][3] += 1;
        assert!(!ok(&wrong));
        assert!(!ok(&result[1..]));
        let mut swapped = result.clone();
        swapped.swap(0, 1);
        assert!(!ok(&swapped));
    }

    fn q8_tables() -> Q8Tables {
        let mut r = lcg(8);
        let (np, ns, no, nc, nl) = (20usize, 8usize, 60usize, 25usize, 300usize);
        let types = [Q8_TYPE, "PROMO BRUSHED TIN", "ECONOMY ANODIZED"];
        let names = ["ARGENTINA", "BRAZIL", "CANADA", "CHINA", "FRANCE", "PERU"];
        Q8Tables {
            part: [
                Col::Int((1..=np as i64).collect()),
                Col::Str((0..np).map(|_| types[r(3) as usize].to_string()).collect()),
            ],
            supplier: [
                Col::Int((1..=ns as i64).collect()),
                Col::Int((0..ns).map(|_| r(6)).collect()),
            ],
            lineitem: [
                Col::Int((0..nl).map(|_| 1 + r(no as u64 + 3)).collect()),
                Col::Int((0..nl).map(|_| 1 + r(np as u64)).collect()),
                Col::Int((0..nl).map(|_| 1 + r(ns as u64)).collect()),
                Col::Int((0..nl).map(|_| 100 + r(10_000)).collect()),
                Col::Int((0..nl).map(|_| r(11)).collect()),
            ],
            orders: {
                let dates: Vec<i64> = (0..no).map(|_| Q8_FROM as i64 - 200 + r(1200)).collect();
                [
                    Col::Int((1..=no as i64).collect()),
                    Col::Int((0..no).map(|_| 1 + r(nc as u64)).collect()),
                    Col::Int(dates.clone()),
                    Col::Int(dates.iter().map(|d| 1970 + d / 365).collect()),
                ]
            },
            customer: [
                Col::Int((1..=nc as i64).collect()),
                Col::Int((0..nc).map(|_| r(6)).collect()),
            ],
            nation: [
                Col::Int((0..6).collect()),
                Col::Str(names.iter().map(|s| s.to_string()).collect()),
                Col::Int(vec![1, 1, 1, 2, 3, 1]),
            ],
            region: [
                Col::Int((0..4).collect()),
                Col::Str(
                    ["AFRICA", "AMERICA", "ASIA", "EUROPE"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                ),
            ],
        }
    }

    #[test]
    fn q8_accepts_its_result_only() {
        let circuit = Q8Circuit::<Fp>::new(&q8_tables());
        let result = circuit.result();
        let k = degree(circuit.rows());
        let ok = |res: &[Vec<i128>]| {
            MockProver::run(k, &circuit, transpose(res, 3))
                .unwrap()
                .verify()
                .is_ok()
        };
        assert!(result.len() > 1, "too few groups to test with");
        assert!(
            result.iter().any(|g| g[1] != 0 && g[1] != g[2]),
            "no mixed share to test with"
        );
        assert!(ok(&result));
        let mut wrong = result.clone();
        wrong[0][1] += 1;
        assert!(!ok(&wrong));
        assert!(!ok(&result[1..]));
        let mut swapped = result.clone();
        swapped.swap(0, 1);
        assert!(!ok(&swapped));
    }

    /// Every query through the real prover and verifier.
    #[test]
    fn prove_and_verify() {
        let path = |q: &str| {
            std::env::temp_dir()
                .join(format!("fixed_{q}.proof"))
                .display()
                .to_string()
        };
        let k = |rows: usize| degree(rows);
        let q3 = q3_tables();
        assert!(
            run_q3(k(Q3Circuit::<Fp>::new(&q3).rows()), &q3, &path("q3"))
                .bench
                .verified
        );
        let q5 = q5_tables();
        assert!(
            run_q5(k(Q5Circuit::<Fp>::new(&q5).rows()), &q5, &path("q5"))
                .bench
                .verified
        );
        let q8 = q8_tables();
        assert!(
            run_q8(k(Q8Circuit::<Fp>::new(&q8).rows()), &q8, &path("q8"))
                .bench
                .verified
        );
        let q9 = q9_tables();
        assert!(
            run_q9(k(Q9Circuit::<Fp>::new(&q9).rows()), &q9, &path("q9"))
                .bench
                .verified
        );
        let q18 = q18_tables();
        assert!(
            run_q18(k(Q18Circuit::<Fp>::new(&q18).rows()), &q18, &path("q18"))
                .bench
                .verified
        );
    }

    #[test]
    fn q5_accepts_its_result_only() {
        let circuit = Q5Circuit::<Fp>::new(&q5_tables());
        let result = circuit.result();
        let k = degree(circuit.rows());
        let ok = |res: &[Vec<i128>]| {
            MockProver::run(k, &circuit, transpose(res, 2))
                .unwrap()
                .verify()
                .is_ok()
        };
        assert!(result.len() > 1, "too few groups to test with");
        assert!(ok(&result));
        let mut wrong = result.clone();
        wrong[0][1] += 1;
        assert!(!ok(&wrong));
        assert!(!ok(&result[1..]));
    }

    #[test]
    fn q3_accepts_its_result_only() {
        let circuit = Q3Circuit::<Fp>::new(&q3_tables());
        let result = circuit.result();
        assert!(result.len() > 3, "too few groups to test with");
        assert!(mock(&circuit, &result));
        let mut wrong = result.clone();
        wrong[0][3] += 1;
        assert!(!mock(&circuit, &wrong));
        assert!(!mock(&circuit, &result[1..]));
    }
}
