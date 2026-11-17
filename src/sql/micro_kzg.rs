//! The micro-benchmark queries of TruthTable's `third-party-bench/src/micro.rs`
//! as Poneglyph circuits, built from the gadgets and gate patterns of the
//! TPC-H circuits in this module:
//!
//! - an equality is an [`IsZeroChip`] on `value - constant`;
//! - a comparison, and the order of adjacent rows of a sorted column, is an
//!   [`LtEqGenericChip`] (bytes of the difference against a `u8` table);
//! - sorting, and keeping the rows that pass a filter, is a [`PermAnyChip`]
//!   shuffle between the input rows and the output rows;
//! - SUM, COUNT and GROUP BY are running-sum gates, a group starting where an
//!   [`IsZeroChip`] on adjacent keys reports a change (Q1);
//! - a join splits each table into its joining and its other rows, looks the
//!   output keys up in the joining rows of both tables, and shows the other
//!   rows' distinct keys are disjoint with a strictly increasing merge (Q3).
//!
//! As in the TPC-H circuits, the witness decides which rows the selectors of
//! kept, output and group-end rows enable, and the query's result is the
//! public input. Every value of the micro tables is below 2^24.

use crate::chips::is_zero::{IsZeroChip, IsZeroConfig};
use crate::chips::lessthan_or_equal_generic::{
    LtEqGenericChip, LtEqGenericConfig, LtEqGenericInstruction,
};
use crate::chips::permutation_any::PermAnyChip;
use crate::circuits::utils::{full_prover, BenchResult};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::{circuit::*, halo2curves::ff::PrimeField, plonk::*, poly::Rotation};
use std::collections::{BTreeSet, HashMap};
use std::marker::PhantomData;

const N_BYTES: usize = 3;

pub trait Field: PrimeField<Repr = [u8; 32]> + Ord {}

impl<F> Field for F where F: PrimeField<Repr = [u8; 32]> + Ord {}

// The constants of the micro queries.
const FILTER: (u64, u64) = (1, 2);
const AGG_B: u64 = 1;
const RANGE: (u64, u64) = (100, 199);
const ARITH_C: u64 = 1;
const IN_VALUES: [u64; 16] = [
    0, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400, 1500,
];
const ORDER_LIMIT: usize = 10;

fn constant<F: Field>(v: u64) -> Expression<F> {
    Expression::Constant(F::from(v))
}

fn one<F: Field>() -> Expression<F> {
    Expression::Constant(F::ONE)
}

fn cur<F: Field>(m: &mut VirtualCells<'_, F>, c: Column<Advice>) -> Expression<F> {
    m.query_advice(c, Rotation::cur())
}

fn prev<F: Field>(m: &mut VirtualCells<'_, F>, c: Column<Advice>) -> Expression<F> {
    m.query_advice(c, Rotation::prev())
}

fn next<F: Field>(m: &mut VirtualCells<'_, F>, c: Column<Advice>) -> Expression<F> {
    m.query_advice(c, Rotation::next())
}

fn assign<F: Field>(
    region: &mut Region<'_, F>,
    column: Column<Advice>,
    row: usize,
    v: u64,
) -> Result<AssignedCell<F, F>, Error> {
    region.assign_advice(|| "", column, row, || Value::known(F::from(v)))
}

/// An [`IsZeroChip`] on `column - v`, enabled by `q`.
fn equality<F: Field>(
    meta: &mut ConstraintSystem<F>,
    q: Selector,
    column: Column<Advice>,
    v: u64,
) -> IsZeroConfig<F> {
    let inv = meta.advice_column();
    IsZeroChip::configure(
        meta,
        |m| m.query_selector(q),
        |m| cur(m, column) - constant(v),
        inv,
    )
}

/// Loads every comparison chip's `u8` table and returns the chips.
fn comparisons<F: Field>(
    configs: &[LtEqGenericConfig<F, N_BYTES>],
    layouter: &mut impl Layouter<F>,
) -> Result<Vec<LtEqGenericChip<F, N_BYTES>>, Error> {
    configs
        .iter()
        .map(|c| {
            let chip = LtEqGenericChip::construct(*c);
            chip.load(layouter)?;
            Ok(chip)
        })
        .collect()
}

fn publish<F: Field>(
    layouter: &mut impl Layouter<F>,
    instance: Column<Instance>,
    cells: &[AssignedCell<F, F>],
) -> Result<(), Error> {
    for (i, cell) in cells.iter().enumerate() {
        layouter.constrain_instance(cell.cell(), instance, i)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Selections: the equality filters, the range and the IN list.
// ---------------------------------------------------------------------------

/// Which rows a selection keeps.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Predicate {
    /// `a = 1 AND b = 2`
    EqAnd,
    /// `a >= 100 AND a <= 199`
    Range,
    /// `a IN (16 values)`
    InList,
}

const EQ_AND: u8 = 0;
const RANGE_PRED: u8 = 1;
const IN_LIST: u8 = 2;

const fn predicate(p: u8) -> Predicate {
    match p {
        EQ_AND => Predicate::EqAnd,
        RANGE_PRED => Predicate::Range,
        _ => Predicate::InList,
    }
}

impl Predicate {
    fn keeps(self, row: &[u64]) -> bool {
        match self {
            Predicate::EqAnd => (row[0], row[1]) == FILTER,
            Predicate::Range => (RANGE.0..=RANGE.1).contains(&row[0]),
            Predicate::InList => IN_VALUES.contains(&row[0]),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SelectConfig<F: Field> {
    q_enable: Selector,
    q_keep: Selector,
    q_out: Selector,
    table: Vec<Column<Advice>>,
    check: Column<Advice>,
    out: Vec<Column<Advice>>,
    eq: Vec<IsZeroConfig<F>>,
    lt: Vec<LtEqGenericConfig<F, N_BYTES>>,
    instance: Column<Instance>,
}

/// `SELECT * FROM t WHERE <PRED>` over `W` columns: the predicate sets `check`
/// on every row, and the rows with `check` set are shuffled into `out`, which
/// is public. `PRED` is a [`Predicate`] as `u8`: `configure` has no circuit
/// to read it from.
#[derive(Clone, Default)]
pub struct SelectCircuit<F, const PRED: u8, const W: usize> {
    pub rows: Vec<Vec<u64>>,
    _f: PhantomData<F>,
}

impl<F: Field, const PRED: u8, const W: usize> SelectCircuit<F, PRED, W> {
    pub fn new(rows: Vec<Vec<u64>>) -> Self {
        Self {
            rows,
            _f: PhantomData,
        }
    }

    pub fn result(&self) -> Vec<Vec<u64>> {
        let p = predicate(PRED);
        self.rows.iter().filter(|r| p.keeps(r)).cloned().collect()
    }
}

impl<F: Field, const PRED: u8, const W: usize> Circuit<F> for SelectCircuit<F, PRED, W> {
    type Config = SelectConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::new(vec![])
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let q_enable = meta.selector();
        let q_keep = meta.complex_selector();
        let q_out = meta.complex_selector();
        let table: Vec<_> = (0..W).map(|_| meta.advice_column()).collect();
        let out: Vec<_> = (0..W).map(|_| meta.advice_column()).collect();
        let check = meta.advice_column();
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let a = table[0];
        let mut eq = Vec::new();
        let mut lt = Vec::new();
        match predicate(PRED) {
            Predicate::EqAnd => {
                eq.push(equality(meta, q_enable, table[0], FILTER.0));
                eq.push(equality(meta, q_enable, table[1], FILTER.1));
            }
            Predicate::InList => {
                for v in IN_VALUES {
                    eq.push(equality(meta, q_enable, a, v));
                }
            }
            Predicate::Range => {
                lt.push(LtEqGenericChip::configure(
                    meta,
                    |m| m.query_selector(q_enable),
                    |_| vec![constant(RANGE.0)],
                    |m| vec![cur(m, a)],
                ));
                lt.push(LtEqGenericChip::configure(
                    meta,
                    |m| m.query_selector(q_enable),
                    |m| vec![cur(m, a)],
                    |_| vec![constant(RANGE.1)],
                ));
            }
        }

        let eq_exprs: Vec<_> = eq.iter().map(|c| c.expr()).collect();
        let lts = lt.clone();
        meta.create_gate("check is the predicate", |m| {
            let keep = match predicate(PRED) {
                Predicate::EqAnd => eq_exprs[0].clone() * eq_exprs[1].clone(),
                // The listed values are distinct: at most one equality holds.
                Predicate::InList => eq_exprs
                    .iter()
                    .fold(Expression::Constant(F::ZERO), |acc, e| acc + e.clone()),
                Predicate::Range => lts[0].is_lt(m, None) * lts[1].is_lt(m, None),
            };
            vec![m.query_selector(q_enable) * (keep - cur(m, check))]
        });
        meta.create_gate("kept rows pass", |m| {
            vec![m.query_selector(q_keep) * (cur(m, check) - one())]
        });
        PermAnyChip::configure(meta, q_keep, q_out, table.clone(), out.clone());

        SelectConfig {
            q_enable,
            q_keep,
            q_out,
            table,
            check,
            out,
            eq,
            lt,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let lt_chips = comparisons(&config.lt, &mut layouter)?;
        let eq_chips: Vec<_> = config
            .eq
            .iter()
            .map(|c| IsZeroChip::construct(c.clone()))
            .collect();
        let p = predicate(PRED);
        let result = self.result();
        let cells = layouter.assign_region(
            || "select",
            |mut region| {
                for (row, values) in self.rows.iter().enumerate() {
                    config.q_enable.enable(&mut region, row)?;
                    let keep = p.keeps(values);
                    if keep {
                        config.q_keep.enable(&mut region, row)?;
                    }
                    for (c, &v) in values.iter().enumerate() {
                        assign(&mut region, config.table[c], row, v)?;
                    }
                    assign(&mut region, config.check, row, keep as u64)?;
                    let a = F::from(values[0]);
                    match p {
                        Predicate::EqAnd => {
                            eq_chips[0].assign(
                                &mut region,
                                row,
                                Value::known(a - F::from(FILTER.0)),
                            )?;
                            eq_chips[1].assign(
                                &mut region,
                                row,
                                Value::known(F::from(values[1]) - F::from(FILTER.1)),
                            )?;
                        }
                        Predicate::InList => {
                            for (chip, v) in eq_chips.iter().zip(IN_VALUES) {
                                chip.assign(&mut region, row, Value::known(a - F::from(v)))?;
                            }
                        }
                        Predicate::Range => {
                            lt_chips[0].assign(&mut region, row, &[F::from(RANGE.0)], &[a])?;
                            lt_chips[1].assign(&mut region, row, &[a], &[F::from(RANGE.1)])?;
                        }
                    }
                }
                let mut cells = Vec::new();
                for (row, values) in result.iter().enumerate() {
                    config.q_out.enable(&mut region, row)?;
                    for (c, &v) in values.iter().enumerate() {
                        cells.push(assign(&mut region, config.out[c], row, v)?);
                    }
                }
                Ok(cells)
            },
        )?;
        publish(&mut layouter, config.instance, &cells)
    }
}

// ---------------------------------------------------------------------------
// Ungrouped aggregates: SUM(a), COUNT(*) WHERE b = 1, and SUM(a * b) WHERE c = 1.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SumConfig<F: Field> {
    q_enable: Selector,
    q_first: Selector,
    table: Vec<Column<Advice>>,
    sum: Column<Advice>,
    count: Column<Advice>,
    eq: IsZeroConfig<F>,
    instance: Column<Instance>,
}

/// `ARITH` false: `SELECT SUM(a), COUNT(*) FROM t WHERE b = 1` over (a, b);
/// true: `SELECT SUM(a * b) FROM t WHERE c = 1` over (a, b, c). Row `i + 1` of
/// `sum` and `count` holds the running total over rows `0..=i`.
#[derive(Clone, Default)]
pub struct SumCircuit<F, const ARITH: bool> {
    pub rows: Vec<Vec<u64>>,
    _f: PhantomData<F>,
}

impl<F: Field, const ARITH: bool> SumCircuit<F, ARITH> {
    pub fn new(rows: Vec<Vec<u64>>) -> Self {
        Self {
            rows,
            _f: PhantomData,
        }
    }

    fn term(row: &[u64]) -> (bool, u64) {
        if ARITH {
            (row[2] == ARITH_C, row[0] * row[1])
        } else {
            (row[1] == AGG_B, row[0])
        }
    }

    pub fn result(&self) -> Vec<u64> {
        let (mut sum, mut count) = (0, 0);
        for row in &self.rows {
            let (keep, term) = Self::term(row);
            if keep {
                sum += term;
                count += 1;
            }
        }
        if ARITH {
            vec![sum]
        } else {
            vec![sum, count]
        }
    }
}

impl<F: Field, const ARITH: bool> Circuit<F> for SumCircuit<F, ARITH> {
    type Config = SumConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::new(vec![])
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let q_enable = meta.selector();
        let q_first = meta.selector();
        let width = if ARITH { 3 } else { 2 };
        let table: Vec<_> = (0..width).map(|_| meta.advice_column()).collect();
        let (sum, count) = (meta.advice_column(), meta.advice_column());
        meta.enable_equality(sum);
        meta.enable_equality(count);
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let key = if ARITH { table[2] } else { table[1] };
        let eq = equality(meta, q_enable, key, if ARITH { ARITH_C } else { AGG_B });
        let keep = eq.expr();
        let (a, b) = (table[0], table[1]);
        meta.create_gate("running sums", |m| {
            let q = m.query_selector(q_enable);
            let term = if ARITH {
                cur(m, a) * cur(m, b)
            } else {
                cur(m, a)
            };
            vec![
                q.clone() * (next(m, sum) - cur(m, sum) - keep.clone() * term),
                q * (next(m, count) - cur(m, count) - keep.clone()),
            ]
        });
        meta.create_gate("sums start at zero", |m| {
            let q = m.query_selector(q_first);
            vec![q.clone() * cur(m, sum), q * cur(m, count)]
        });

        SumConfig {
            q_enable,
            q_first,
            table,
            sum,
            count,
            eq,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let eq = IsZeroChip::construct(config.eq.clone());
        let key_value = if ARITH { ARITH_C } else { AGG_B };
        let cells = layouter.assign_region(
            || "sum",
            |mut region| {
                config.q_first.enable(&mut region, 0)?;
                let (mut sum, mut count) = (F::ZERO, F::ZERO);
                let mut totals = (
                    assign(&mut region, config.sum, 0, 0)?,
                    assign(&mut region, config.count, 0, 0)?,
                );
                for (row, values) in self.rows.iter().enumerate() {
                    config.q_enable.enable(&mut region, row)?;
                    for (c, &v) in values.iter().enumerate() {
                        assign(&mut region, config.table[c], row, v)?;
                    }
                    let key = if ARITH { values[2] } else { values[1] };
                    eq.assign(
                        &mut region,
                        row,
                        Value::known(F::from(key) - F::from(key_value)),
                    )?;
                    let (keep, term) = Self::term(values);
                    if keep {
                        sum += F::from(term);
                        count += F::ONE;
                    }
                    totals = (
                        region.assign_advice(
                            || "sum",
                            config.sum,
                            row + 1,
                            || Value::known(sum),
                        )?,
                        region.assign_advice(
                            || "count",
                            config.count,
                            row + 1,
                            || Value::known(count),
                        )?,
                    );
                }
                Ok(if ARITH {
                    vec![totals.0]
                } else {
                    vec![totals.0, totals.1]
                })
            },
        )?;
        publish(&mut layouter, config.instance, &cells)
    }
}

// ---------------------------------------------------------------------------
// GROUP BY: SELECT b, SUM(a), COUNT(*) FROM t GROUP BY b (Q1's pattern).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct GroupByConfig<F: Field> {
    q_in: Selector,
    q_sorted: Selector,
    q_first: Selector,
    q_adjacent: Selector,
    q_end: Selector,
    table: Vec<Column<Advice>>,
    sorted: Vec<Column<Advice>>,
    same: Column<Advice>,
    sum: Column<Advice>,
    count: Column<Advice>,
    eq: IsZeroConfig<F>,
    lt: LtEqGenericConfig<F, N_BYTES>,
    instance: Column<Instance>,
}

/// The rows (a, b) are shuffled into `sorted`, ordered by b. `same` is set
/// where a row's b equals the previous row's; `sum` and `count` restart where
/// it is not, and the last row of each group, whose next row starts another,
/// is public as (b, sum, count).
#[derive(Clone, Default)]
pub struct GroupByCircuit<F> {
    pub rows: Vec<Vec<u64>>,
    _f: PhantomData<F>,
}

impl<F: Field> GroupByCircuit<F> {
    pub fn new(rows: Vec<Vec<u64>>) -> Self {
        Self {
            rows,
            _f: PhantomData,
        }
    }

    fn sorted(&self) -> Vec<Vec<u64>> {
        let mut sorted = self.rows.clone();
        sorted.sort_by_key(|r| r[1]);
        sorted
    }

    pub fn result(&self) -> Vec<u64> {
        let mut groups: Vec<(u64, u64, u64)> = Vec::new();
        for r in self.sorted() {
            match groups.last_mut() {
                Some(g) if g.0 == r[1] => {
                    g.1 += r[0];
                    g.2 += 1;
                }
                _ => groups.push((r[1], r[0], 1)),
            }
        }
        groups.into_iter().flat_map(|(b, s, c)| [b, s, c]).collect()
    }
}

impl<F: Field> Circuit<F> for GroupByCircuit<F> {
    type Config = GroupByConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::new(vec![])
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let q_in = meta.complex_selector();
        let q_sorted = meta.complex_selector();
        let q_first = meta.selector();
        let q_adjacent = meta.selector();
        let q_end = meta.selector();
        let table: Vec<_> = (0..2).map(|_| meta.advice_column()).collect();
        let sorted: Vec<_> = (0..2).map(|_| meta.advice_column()).collect();
        let (same, sum, count) = (
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        );
        for c in [sorted[1], sum, count] {
            meta.enable_equality(c);
        }
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let (a, b) = (sorted[0], sorted[1]);

        PermAnyChip::configure(meta, q_in, q_sorted, table.clone(), sorted.clone());
        let lt = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(q_adjacent),
            |m| vec![prev(m, b)],
            |m| vec![cur(m, b)],
        );
        let inv = meta.advice_column();
        let eq = IsZeroChip::configure(
            meta,
            |m| m.query_selector(q_adjacent),
            |m| prev(m, b) - cur(m, b),
            inv,
        );
        let same_expr = eq.expr();
        meta.create_gate("sorted by b", |m| {
            vec![m.query_selector(q_adjacent) * (lt.is_lt(m, None) - one())]
        });
        meta.create_gate("same group as the previous row", |m| {
            vec![m.query_selector(q_adjacent) * (cur(m, same) - same_expr.clone())]
        });
        meta.create_gate("first row", |m| {
            let q = m.query_selector(q_first);
            vec![
                q.clone() * cur(m, same),
                q.clone() * (cur(m, sum) - cur(m, a)),
                q * (cur(m, count) - one()),
            ]
        });
        meta.create_gate("running sums per group", |m| {
            let q = m.query_selector(q_adjacent);
            let s = cur(m, same);
            vec![
                q.clone() * (cur(m, sum) - s.clone() * prev(m, sum) - cur(m, a)),
                q * (cur(m, count) - s * prev(m, count) - one()),
            ]
        });
        meta.create_gate("a group ends where the next starts", |m| {
            vec![m.query_selector(q_end) * next(m, same)]
        });

        GroupByConfig {
            q_in,
            q_sorted,
            q_first,
            q_adjacent,
            q_end,
            table,
            sorted,
            same,
            sum,
            count,
            eq,
            lt,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let lt = &comparisons(&[config.lt], &mut layouter)?[0];
        let eq = IsZeroChip::construct(config.eq.clone());
        let sorted = self.sorted();
        let cells = layouter.assign_region(
            || "group by",
            |mut region| {
                for (row, values) in self.rows.iter().enumerate() {
                    config.q_in.enable(&mut region, row)?;
                    for c in 0..2 {
                        assign(&mut region, config.table[c], row, values[c])?;
                    }
                }
                config.q_first.enable(&mut region, 0)?;
                let mut cells = Vec::new();
                let (mut sum, mut count) = (0u64, 0u64);
                for (row, values) in sorted.iter().enumerate() {
                    config.q_sorted.enable(&mut region, row)?;
                    let b_cell = assign(&mut region, config.sorted[1], row, values[1])?;
                    assign(&mut region, config.sorted[0], row, values[0])?;
                    let same = row > 0 && sorted[row - 1][1] == values[1];
                    if row > 0 {
                        config.q_adjacent.enable(&mut region, row)?;
                        let (p, c) = (F::from(sorted[row - 1][1]), F::from(values[1]));
                        lt.assign(&mut region, row, &[p], &[c])?;
                        eq.assign(&mut region, row, Value::known(p - c))?;
                    }
                    (sum, count) = if same {
                        (sum + values[0], count + 1)
                    } else {
                        (values[0], 1)
                    };
                    assign(&mut region, config.same, row, same as u64)?;
                    let sum_cell = assign(&mut region, config.sum, row, sum)?;
                    let count_cell = assign(&mut region, config.count, row, count)?;
                    let ends = sorted.get(row + 1).map_or(true, |n| n[1] != values[1]);
                    if ends {
                        if row + 1 < sorted.len() {
                            config.q_end.enable(&mut region, row)?;
                        }
                        cells.extend([b_cell, sum_cell, count_cell]);
                    }
                }
                Ok(cells)
            },
        )?;
        publish(&mut layouter, config.instance, &cells)
    }
}

// ---------------------------------------------------------------------------
// ORDER BY: SELECT a, b FROM t ORDER BY a LIMIT 10.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct OrderByConfig<F: Field> {
    q_in: Selector,
    q_sorted: Selector,
    q_adjacent: Selector,
    table: Vec<Column<Advice>>,
    sorted: Vec<Column<Advice>>,
    lt: LtEqGenericConfig<F, N_BYTES>,
    instance: Column<Instance>,
}

/// The rows (a, b) are shuffled into `sorted`, ordered by a; its first rows
/// are public.
#[derive(Clone, Default)]
pub struct OrderByCircuit<F> {
    pub rows: Vec<Vec<u64>>,
    _f: PhantomData<F>,
}

impl<F: Field> OrderByCircuit<F> {
    pub fn new(rows: Vec<Vec<u64>>) -> Self {
        Self {
            rows,
            _f: PhantomData,
        }
    }

    fn sorted(&self) -> Vec<Vec<u64>> {
        let mut sorted = self.rows.clone();
        sorted.sort_by_key(|r| r[0]);
        sorted
    }

    pub fn result(&self) -> Vec<u64> {
        self.sorted()
            .into_iter()
            .take(ORDER_LIMIT)
            .flatten()
            .collect()
    }
}

impl<F: Field> Circuit<F> for OrderByCircuit<F> {
    type Config = OrderByConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::new(vec![])
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let q_in = meta.complex_selector();
        let q_sorted = meta.complex_selector();
        let q_adjacent = meta.selector();
        let table: Vec<_> = (0..2).map(|_| meta.advice_column()).collect();
        let sorted: Vec<_> = (0..2).map(|_| meta.advice_column()).collect();
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let a = sorted[0];

        PermAnyChip::configure(meta, q_in, q_sorted, table.clone(), sorted.clone());
        let lt = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(q_adjacent),
            |m| vec![prev(m, a)],
            |m| vec![cur(m, a)],
        );
        meta.create_gate("sorted by a", |m| {
            vec![m.query_selector(q_adjacent) * (lt.is_lt(m, None) - one())]
        });

        OrderByConfig {
            q_in,
            q_sorted,
            q_adjacent,
            table,
            sorted,
            lt,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let lt = &comparisons(&[config.lt], &mut layouter)?[0];
        let sorted = self.sorted();
        let cells = layouter.assign_region(
            || "order by",
            |mut region| {
                for (row, values) in self.rows.iter().enumerate() {
                    config.q_in.enable(&mut region, row)?;
                    for c in 0..2 {
                        assign(&mut region, config.table[c], row, values[c])?;
                    }
                }
                let mut cells = Vec::new();
                for (row, values) in sorted.iter().enumerate() {
                    config.q_sorted.enable(&mut region, row)?;
                    let row_cells = [
                        assign(&mut region, config.sorted[0], row, values[0])?,
                        assign(&mut region, config.sorted[1], row, values[1])?,
                    ];
                    if row > 0 {
                        config.q_adjacent.enable(&mut region, row)?;
                        lt.assign(
                            &mut region,
                            row,
                            &[F::from(sorted[row - 1][0])],
                            &[F::from(values[0])],
                        )?;
                    }
                    if row < ORDER_LIMIT {
                        cells.extend(row_cells);
                    }
                }
                Ok(cells)
            },
        )?;
        publish(&mut layouter, config.instance, &cells)
    }
}

// ---------------------------------------------------------------------------
// Join: SELECT l.a, r.a FROM l, r WHERE l.a = r.a (Q3's pattern).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct JoinConfig<F: Field> {
    q_in: [Selector; 2],
    q_split: [Selector; 2],
    q_join: [Selector; 2],
    q_other: [Selector; 2],
    q_out: Selector,
    q_dedup: [Selector; 2],
    q_dedup_all: Selector,
    q_merged: Selector,
    q_increasing: Selector,
    input: [Column<Advice>; 2],
    split: [Column<Advice>; 2],
    out: [Column<Advice>; 2],
    dedup: Column<Advice>,
    merged: Column<Advice>,
    lt: LtEqGenericConfig<F, N_BYTES>,
    instance: Column<Instance>,
}

/// For each table, `split` holds its joining rows (keys the other table has)
/// and then its other rows, shuffled from `input`. Every output row's two keys
/// are equal and found among both tables' joining rows. `dedup` holds the
/// distinct keys of l's other rows and then of r's; every other row's key is
/// among its table's, and `merged`, their shuffle, strictly increases, so no
/// key is in both. The output's l.a column is public (r.a equals it).
#[derive(Clone, Default)]
pub struct JoinCircuit<F> {
    pub tables: [Vec<u64>; 2],
    _f: PhantomData<F>,
}

struct JoinWitness {
    split: [(Vec<u64>, Vec<u64>); 2],
    dedup: [Vec<u64>; 2],
    out: Vec<u64>,
}

impl<F: Field> JoinCircuit<F> {
    pub fn new(l: Vec<u64>, r: Vec<u64>) -> Self {
        Self {
            tables: [l, r],
            _f: PhantomData,
        }
    }

    fn witness(&self) -> JoinWitness {
        let keys: [BTreeSet<u64>; 2] = [
            self.tables[0].iter().copied().collect(),
            self.tables[1].iter().copied().collect(),
        ];
        let split = [0, 1].map(|t| {
            let (join, other): (Vec<u64>, Vec<u64>) =
                self.tables[t].iter().partition(|k| keys[1 - t].contains(k));
            (join, other)
        });
        let dedup = [0, 1].map(|t| {
            split[t]
                .1
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        });
        let mut right: HashMap<u64, usize> = HashMap::new();
        for &k in &self.tables[1] {
            *right.entry(k).or_default() += 1;
        }
        let out = self.tables[0]
            .iter()
            .flat_map(|k| std::iter::repeat(*k).take(*right.get(k).unwrap_or(&0)))
            .collect();
        JoinWitness { split, dedup, out }
    }

    pub fn result(&self) -> Vec<u64> {
        self.witness().out
    }
}

impl<F: Field> Circuit<F> for JoinCircuit<F> {
    type Config = JoinConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::new(vec![], vec![])
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let pair =
            |meta: &mut ConstraintSystem<F>| [meta.complex_selector(), meta.complex_selector()];
        let (q_in, q_split, q_join, q_other, q_dedup) =
            (pair(meta), pair(meta), pair(meta), pair(meta), pair(meta));
        let (q_out, q_dedup_all, q_merged) = (
            meta.complex_selector(),
            meta.complex_selector(),
            meta.complex_selector(),
        );
        let q_increasing = meta.selector();
        let columns = |meta: &mut ConstraintSystem<F>| [meta.advice_column(), meta.advice_column()];
        let (input, split, out) = (columns(meta), columns(meta), columns(meta));
        let (dedup, merged) = (meta.advice_column(), meta.advice_column());
        meta.enable_equality(out[0]);
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        for t in 0..2 {
            PermAnyChip::configure(meta, q_in[t], q_split[t], vec![input[t]], vec![split[t]]);
            meta.lookup_any("output key among the joining rows", |m| {
                let key = m.query_selector(q_out) * cur(m, out[t]);
                let joining = m.query_selector(q_join[t]) * cur(m, split[t]);
                vec![(key, joining)]
            });
            meta.lookup_any("other key among the distinct other keys", |m| {
                let key = m.query_selector(q_other[t]) * cur(m, split[t]);
                let distinct = m.query_selector(q_dedup[t]) * cur(m, dedup);
                vec![(key, distinct)]
            });
        }
        meta.create_gate("output keys equal", |m| {
            vec![m.query_selector(q_out) * (cur(m, out[0]) - cur(m, out[1]))]
        });
        PermAnyChip::configure(meta, q_dedup_all, q_merged, vec![dedup], vec![merged]);
        let lt = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(q_increasing),
            |m| vec![prev(m, merged), one()],
            |m| vec![cur(m, merged)],
        );
        meta.create_gate("merged keys strictly increase", |m| {
            vec![m.query_selector(q_increasing) * (lt.is_lt(m, None) - one())]
        });

        JoinConfig {
            q_in,
            q_split,
            q_join,
            q_other,
            q_out,
            q_dedup,
            q_dedup_all,
            q_merged,
            q_increasing,
            input,
            split,
            out,
            dedup,
            merged,
            lt,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let lt = &comparisons(&[config.lt], &mut layouter)?[0];
        let w = self.witness();
        let cells = layouter.assign_region(
            || "join",
            |mut region| {
                for t in 0..2 {
                    for (row, &k) in self.tables[t].iter().enumerate() {
                        config.q_in[t].enable(&mut region, row)?;
                        assign(&mut region, config.input[t], row, k)?;
                    }
                    let (join, other) = &w.split[t];
                    for (row, &k) in join.iter().chain(other).enumerate() {
                        config.q_split[t].enable(&mut region, row)?;
                        if row < join.len() {
                            config.q_join[t].enable(&mut region, row)?;
                        } else {
                            config.q_other[t].enable(&mut region, row)?;
                        }
                        assign(&mut region, config.split[t], row, k)?;
                    }
                }
                let mut dedup_row = 0;
                for t in 0..2 {
                    for &k in &w.dedup[t] {
                        config.q_dedup[t].enable(&mut region, dedup_row)?;
                        config.q_dedup_all.enable(&mut region, dedup_row)?;
                        assign(&mut region, config.dedup, dedup_row, k)?;
                        dedup_row += 1;
                    }
                }
                let mut merged: Vec<u64> = w.dedup.iter().flatten().copied().collect();
                merged.sort();
                for (row, &k) in merged.iter().enumerate() {
                    config.q_merged.enable(&mut region, row)?;
                    assign(&mut region, config.merged, row, k)?;
                    if row > 0 {
                        config.q_increasing.enable(&mut region, row)?;
                        lt.assign(
                            &mut region,
                            row,
                            &[F::from(merged[row - 1]), F::ONE],
                            &[F::from(k)],
                        )?;
                    }
                }
                let mut cells = Vec::new();
                for (row, &k) in w.out.iter().enumerate() {
                    config.q_out.enable(&mut region, row)?;
                    cells.push(assign(&mut region, config.out[0], row, k)?);
                    assign(&mut region, config.out[1], row, k)?;
                }
                Ok(cells)
            },
        )?;
        publish(&mut layouter, config.instance, &cells)
    }
}

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------

/// What a micro run produced: the prover's numbers and the result's size.
pub struct MicroResult {
    pub bench: BenchResult,
    pub public_inputs: usize,
}

/// Proves and verifies `query` (a name from `micro.rs`) over `tables`, each a
/// list of rows, at Halo2 degree `k`.
pub fn run(query: &str, k: u32, tables: &[Vec<Vec<u64>>], proof_path: &str) -> MicroResult {
    fn go<C: Circuit<Fp>>(circuit: C, k: u32, public: Vec<u64>, proof_path: &str) -> MicroResult {
        let public: Vec<Fp> = public.into_iter().map(Fp::from).collect();
        MicroResult {
            bench: full_prover(circuit, k, &public, proof_path),
            public_inputs: public.len(),
        }
    }
    let rows = || tables[0].clone();
    match query {
        "filter_0p1" | "filter_1" | "filter_10" => {
            let c = SelectCircuit::<Fp, EQ_AND, 4>::new(rows());
            let public = c.result().concat();
            go(c, k, public, proof_path)
        }
        "range" => {
            let c = SelectCircuit::<Fp, RANGE_PRED, 2>::new(rows());
            let public = c.result().concat();
            go(c, k, public, proof_path)
        }
        "in_list" => {
            let c = SelectCircuit::<Fp, IN_LIST, 4>::new(rows());
            let public = c.result().concat();
            go(c, k, public, proof_path)
        }
        "aggregate" => {
            let c = SumCircuit::<Fp, false>::new(rows());
            let public = c.result();
            go(c, k, public, proof_path)
        }
        "arithmetic" => {
            let c = SumCircuit::<Fp, true>::new(rows());
            let public = c.result();
            go(c, k, public, proof_path)
        }
        "group_by" => {
            let c = GroupByCircuit::<Fp>::new(rows());
            let public = c.result();
            go(c, k, public, proof_path)
        }
        "order_by" => {
            let c = OrderByCircuit::<Fp>::new(rows());
            let public = c.result();
            go(c, k, public, proof_path)
        }
        "join_pk_fk" | "join_m2m" => {
            let key = |t: &Vec<Vec<u64>>| t.iter().map(|r| r[0]).collect();
            let c = JoinCircuit::<Fp>::new(key(&tables[0]), key(&tables[1]));
            let public = c.result();
            go(c, k, public, proof_path)
        }
        other => panic!("unknown micro query {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    /// A small table in the shape of the micro tables, from a fixed LCG.
    fn rows(n: usize, bounds: &[u64], seed: u64) -> Vec<Vec<u64>> {
        let mut s = seed;
        (0..n)
            .map(|_| {
                bounds
                    .iter()
                    .map(|&b| {
                        s = s
                            .wrapping_mul(6364136223846793005)
                            .wrapping_add(1442695040888963407);
                        (s >> 33) % b
                    })
                    .collect()
            })
            .collect()
    }

    fn check<C: Circuit<Fp>>(circuit: C, public: Vec<u64>) {
        let public: Vec<Fp> = public.into_iter().map(Fp::from).collect();
        let prover = MockProver::run(10, &circuit, vec![public.clone()]).unwrap();
        prover.assert_satisfied();
        // A wrong result must not verify.
        let mut wrong = public;
        if let Some(v) = wrong.first_mut() {
            *v += Fp::from(1);
        } else {
            wrong.push(Fp::from(1));
        }
        let prover = MockProver::run(10, &circuit, vec![wrong]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn selections() {
        let mut t = rows(200, &[4, 4, 1000, 1000], 1);
        t[3][0] = 1;
        t[3][1] = 2;
        let c = SelectCircuit::<Fp, EQ_AND, 4>::new(t);
        let public = c.result().concat();
        assert!(!public.is_empty());
        check(c, public);

        let c = SelectCircuit::<Fp, RANGE_PRED, 2>::new(rows(200, &[1000, 1000], 2));
        let public = c.result().concat();
        assert!(!public.is_empty());
        check(c, public);

        let c = SelectCircuit::<Fp, IN_LIST, 4>::new(
            rows(200, &[1600, 9, 9, 9], 3)
                .into_iter()
                .enumerate()
                .map(|(i, mut r)| {
                    if i % 10 == 0 {
                        r[0] = 300;
                    }
                    r
                })
                .collect(),
        );
        let public = c.result().concat();
        assert!(!public.is_empty());
        check(c, public);
    }

    #[test]
    fn sums() {
        let c = SumCircuit::<Fp, false>::new(rows(200, &[1000, 3], 4));
        let public = c.result();
        check(c, public);
        let c = SumCircuit::<Fp, true>::new(rows(200, &[1000, 1000, 3], 5));
        let public = c.result();
        check(c, public);
    }

    #[test]
    fn group_and_order() {
        let c = GroupByCircuit::<Fp>::new(rows(200, &[1000, 7], 6));
        let public = c.result();
        assert_eq!(public.len(), 21);
        check(c, public);
        let c = OrderByCircuit::<Fp>::new(rows(200, &[100000, 1000], 7));
        let public = c.result();
        check(c, public);
    }

    /// Every circuit through the real prover and verifier at k = 10.
    #[test]
    fn prove_and_verify() {
        let dir = std::env::temp_dir();
        let path = |q: &str| dir.join(format!("micro_{q}.proof")).display().to_string();
        let table = |bounds: &[u64], seed| vec![rows(200, bounds, seed)];
        let mut eq = rows(200, &[4, 4, 1000, 1000], 11);
        eq[0] = vec![1, 2, 5, 6];
        let keys = |seed| rows(200, &[300], seed);
        for (q, tables) in [
            ("filter_1", vec![eq]),
            ("range", table(&[1000, 1000], 12)),
            ("in_list", table(&[1600, 9, 9, 9], 13)),
            ("aggregate", table(&[1000, 3], 14)),
            ("arithmetic", table(&[1000, 1000, 3], 15)),
            ("group_by", table(&[1000, 7], 16)),
            ("order_by", table(&[100000, 1000], 17)),
            ("join_m2m", vec![keys(18), keys(19)]),
        ] {
            assert!(
                run(q, 10, &tables, &path(q)).bench.verified,
                "{q} did not verify"
            );
        }
    }

    #[test]
    fn joins() {
        let l: Vec<u64> = (0..100).collect();
        let r: Vec<u64> = rows(100, &[150], 8).into_iter().map(|r| r[0]).collect();
        let c = JoinCircuit::<Fp>::new(l, r);
        let public = c.result();
        assert!(!public.is_empty());
        check(c, public);
        let l: Vec<u64> = rows(100, &[100], 9).into_iter().map(|r| r[0]).collect();
        let r: Vec<u64> = rows(100, &[100], 10).into_iter().map(|r| r[0]).collect();
        let c = JoinCircuit::<Fp>::new(l, r);
        let public = c.result();
        check(c, public);
    }
}
