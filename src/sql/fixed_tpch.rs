//! TPC-H queries (TruthTable's `_pgn` variants) rebuilt from sound gadgets,
//! in place of the `*_final_kzg` circuits:
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
//! `p - |x|`. A string is its bytes, big-endian, as one field element: every
//! string here has at most 31 bytes, so equal strings are equal elements and
//! strings order as their elements do.

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
pub struct JoinConfig<F: Field> {
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
    lt: LtEqGenericConfig<F, KEY_BYTES>,
}

impl<F: Field> JoinConfig<F> {
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
        lt: &LtEqGenericChip<F, KEY_BYTES>,
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
pub struct GroupConfig<F: Field> {
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
    order: LtEqGenericConfig<F, SORT_BYTES>,
    same_key: IsZeroConfig<F>,
    pub output: OutputConfig,
    carries: usize,
}

impl<F: Field> GroupConfig<F> {
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
        order: &LtEqGenericChip<F, SORT_BYTES>,
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
pub struct OrderConfig<F: Field> {
    lt: LtEqGenericConfig<F, SORT_BYTES>,
}

impl<F: Field> OrderConfig<F> {
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
