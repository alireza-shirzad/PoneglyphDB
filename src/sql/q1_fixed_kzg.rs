//! TPC-H Q1 (TruthTable's `_pgn` variant) with the micro circuits' sound
//! gadgets, in place of `q1_final_kzg`:
//!
//! ```sql
//! SELECT l_returnflag, sum(l_quantity), sum(l_extendedprice),
//!        sum(l_extendedprice * (1 - l_discount)),
//!        sum(l_extendedprice * (1 - l_discount) * (1 + l_tax)), count(*)
//! FROM lineitem_poneglyph WHERE l_shipdate <= DATE '1998-09-02'
//! GROUP BY l_returnflag ORDER BY l_returnflag
//! ```
//!
//! Prices and rates are integer cents, as in `lineitem_poneglyph`, so
//! `1 - l_discount` is negative and so are the two discounted sums: the field
//! carries them as `p - |x|`.
//!
//! - The table (quantity, price, discount, tax, return flag, ship date) is
//!   the circuit's first advice columns, unblinded, so the proof is bound to
//!   the data owner's commitments.
//! - `sorted` is a shuffle of the table ordered by return flag (adjacent rows
//!   compared); `keep` is the ship-date predicate on every sorted row.
//! - `same` (an [`IsZeroChip`] on adjacent flags) restarts five running sums
//!   of the kept rows; `end` marks a group's last row, `emit` those with a
//!   kept row, and the emitted rows are shuffled into the public output,
//!   whose flags strictly increase.
//!
//! Every selector covers a range fixed by the row count.

use super::micro_kzg::{
    comparisons, cur, next, one, prev, prove_fields, Field, MicroResult, OutputConfig, N_BYTES,
};
use crate::chips::is_zero::{IsZeroChip, IsZeroConfig};
use crate::chips::lessthan_or_equal_generic::{
    LtEqGenericChip, LtEqGenericConfig, LtEqGenericInstruction,
};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::{circuit::*, plonk::*};
use std::marker::PhantomData;

/// `DATE '1998-09-02'`, in days since 1970-01-01.
const SHIP_DATE: u64 = 10471;
/// Quantity, price, discount, tax, return flag, ship date.
const WIDTH: usize = 6;
const FLAG: usize = 4;
const SHIPDATE: usize = 5;
/// The output: flag, four sums, count.
const OUT: usize = 6;

/// A signed integer as a field element.
fn signed<F: Field>(v: i128) -> F {
    let f = F::from_u128(v.unsigned_abs());
    if v < 0 {
        -f
    } else {
        f
    }
}

#[derive(Clone, Debug)]
pub struct Q1Config<F: Field> {
    q_in: Selector,
    q_sorted: Selector,
    q_first: Selector,
    q_adjacent: Selector,
    q_last: Selector,
    q_not_last: Selector,
    table: Vec<Column<Advice>>,
    sorted: Vec<Column<Advice>>,
    same: Column<Advice>,
    end: Column<Advice>,
    emit: Column<Advice>,
    sums: Vec<Column<Advice>>,
    keep: LtEqGenericConfig<F, N_BYTES>,
    order: LtEqGenericConfig<F, N_BYTES>,
    out_order: LtEqGenericConfig<F, N_BYTES>,
    same_flag: IsZeroConfig<F>,
    empty: IsZeroConfig<F>,
    output: OutputConfig,
}

#[derive(Clone, Default)]
pub struct Q1Circuit<F> {
    /// (quantity, price, discount, tax, return flag, ship date) per row.
    pub rows: Vec<[u64; WIDTH]>,
    _f: PhantomData<F>,
}

/// The five sums of a row, kept or not: quantity, price, discounted price,
/// charge, and one for the count.
fn terms(r: &[u64; WIDTH]) -> [i128; 5] {
    let (qty, price, disc, tax) = (r[0] as i128, r[1] as i128, r[2] as i128, r[3] as i128);
    let disc_price = price * (1 - disc);
    [qty, price, disc_price, disc_price * (1 + tax), 1]
}

impl<F: Field> Q1Circuit<F> {
    pub fn new(rows: Vec<[u64; WIDTH]>) -> Self {
        Self {
            rows,
            _f: PhantomData,
        }
    }

    fn sorted(&self) -> Vec<[u64; WIDTH]> {
        let mut sorted = self.rows.clone();
        sorted.sort_by_key(|r| r[FLAG]);
        sorted
    }

    /// (flag, sum_qty, sum_base_price, sum_disc_price, sum_charge, count) per
    /// group with a kept row, ordered by flag.
    pub fn result(&self) -> Vec<[i128; OUT]> {
        let mut groups: Vec<[i128; OUT]> = Vec::new();
        for r in self.sorted().iter().filter(|r| r[SHIPDATE] <= SHIP_DATE) {
            let t = terms(r);
            match groups.last_mut() {
                Some(g) if g[0] == r[FLAG] as i128 => (0..5).for_each(|i| g[i + 1] += t[i]),
                _ => groups.push([r[FLAG] as i128, t[0], t[1], t[2], t[3], t[4]]),
            }
        }
        groups
    }
}

impl<F: Field> Circuit<F> for Q1Circuit<F> {
    type Config = Q1Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::new(vec![])
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let table: Vec<_> = (0..WIDTH).map(|_| meta.unblinded_advice_column()).collect();
        let q_in = meta.complex_selector();
        let q_sorted = meta.complex_selector();
        let (q_first, q_adjacent) = (meta.selector(), meta.selector());
        let (q_last, q_not_last) = (meta.selector(), meta.selector());
        let sorted: Vec<_> = (0..WIDTH).map(|_| meta.advice_column()).collect();
        let (same, end, emit) = (
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        );
        let sums: Vec<_> = (0..5).map(|_| meta.advice_column()).collect();
        let output = OutputConfig::configure(meta, OUT, OUT);
        let (flag, ship) = (sorted[FLAG], sorted[SHIPDATE]);

        let (t, s) = (table.clone(), sorted.clone());
        meta.shuffle("sorted rows are the table's", move |m| {
            let (qi, qs) = (m.query_selector(q_in), m.query_selector(q_sorted));
            t.iter()
                .zip(&s)
                .map(|(&t, &s)| (qi.clone() * cur(m, t), qs.clone() * cur(m, s)))
                .collect()
        });
        let keep = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(q_sorted),
            |m| vec![cur(m, ship)],
            |_| vec![Expression::Constant(F::from(SHIP_DATE))],
        );
        let order = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(q_adjacent),
            |m| vec![prev(m, flag)],
            |m| vec![cur(m, flag)],
        );
        meta.create_gate("sorted by return flag", move |m| {
            vec![m.query_selector(q_adjacent) * (order.is_lt(m, None) - one())]
        });
        let inv = meta.advice_column();
        let same_flag = IsZeroChip::configure(
            meta,
            |m| m.query_selector(q_adjacent),
            |m| prev(m, flag) - cur(m, flag),
            inv,
        );
        let same_expr = same_flag.expr();
        meta.create_gate("same group as the previous row", move |m| {
            vec![m.query_selector(q_adjacent) * (cur(m, same) - same_expr.clone())]
        });

        // A row's term for each running sum, times its keep flag.
        let values = [sorted[0], sorted[1], sorted[2], sorted[3]];
        let term = move |m: &mut VirtualCells<'_, F>, i: usize| -> Expression<F> {
            let k = keep.is_lt(m, None);
            let [qty, price, disc, tax] = values.map(|c| cur(m, c));
            let disc_price = price.clone() * (one() - disc);
            k * match i {
                0 => qty,
                1 => price,
                2 => disc_price,
                3 => disc_price * (one() + tax),
                _ => one(),
            }
        };
        let sum_cols = sums.clone();
        meta.create_gate("first row starts the sums", move |m| {
            let q = m.query_selector(q_first);
            let mut gates = vec![q.clone() * cur(m, same)];
            for (i, &c) in sum_cols.iter().enumerate() {
                gates.push(q.clone() * (cur(m, c) - term(m, i)));
            }
            gates
        });
        let sum_cols = sums.clone();
        meta.create_gate("running sums per group", move |m| {
            let q = m.query_selector(q_adjacent);
            let s = cur(m, same);
            sum_cols
                .iter()
                .enumerate()
                .map(|(i, &c)| q.clone() * (cur(m, c) - s.clone() * prev(m, c) - term(m, i)))
                .collect::<Vec<_>>()
        });
        meta.create_gate("a group ends where the next starts", move |m| {
            vec![m.query_selector(q_not_last) * (cur(m, end) - (one() - next(m, same)))]
        });
        meta.create_gate("the last row ends a group", move |m| {
            vec![m.query_selector(q_last) * (cur(m, end) - one())]
        });
        let inv = meta.advice_column();
        let count = sums[4];
        let empty =
            IsZeroChip::configure(meta, |m| m.query_selector(q_sorted), |m| cur(m, count), inv);
        let empty_expr = empty.expr();
        meta.create_gate("a group with a kept row is emitted", move |m| {
            vec![
                m.query_selector(q_sorted)
                    * (cur(m, emit) - cur(m, end) * (one() - empty_expr.clone())),
            ]
        });
        let (sum_cols, out) = (sums.clone(), output.clone());
        meta.shuffle("emitted groups are the output", move |m| {
            let gated = m.query_selector(q_sorted) * cur(m, emit);
            let mut input = vec![gated.clone(), gated.clone() * cur(m, flag)];
            input.extend(sum_cols.iter().map(|&c| gated.clone() * cur(m, c)));
            input.into_iter().zip(out.tuple(m)).collect()
        });
        let out = output.clone();
        let out_order = LtEqGenericChip::configure(
            meta,
            |m| m.query_selector(out.q_next),
            |m| vec![prev(m, out.columns[0]), one()],
            |m| vec![cur(m, out.columns[0])],
        );
        let out = output.clone();
        meta.create_gate("output flags strictly increase", move |m| {
            vec![
                m.query_selector(out.q_next)
                    * cur(m, out.flag)
                    * (out_order.is_lt(m, None) - one()),
            ]
        });

        Q1Config {
            q_in,
            q_sorted,
            q_first,
            q_adjacent,
            q_last,
            q_not_last,
            table,
            sorted,
            same,
            end,
            emit,
            sums,
            keep,
            order,
            out_order,
            same_flag,
            empty,
            output,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chips = comparisons(
            &[config.keep, config.order, config.out_order],
            &mut layouter,
        )?;
        let (keep, order, out_order) = (&chips[0], &chips[1], &chips[2]);
        let same_flag = IsZeroChip::construct(config.same_flag.clone());
        let empty = IsZeroChip::construct(config.empty.clone());
        let sorted = self.sorted();
        let result: Vec<Vec<F>> = self
            .result()
            .iter()
            .map(|g| g.iter().map(|&v| signed(v)).collect())
            .collect();
        let n = sorted.len();
        let cells = layouter.assign_region(
            || "q1",
            |mut region| {
                let field = |v: u64| Value::known(F::from(v));
                for (row, values) in self.rows.iter().enumerate() {
                    config.q_in.enable(&mut region, row)?;
                    for (c, &v) in values.iter().enumerate() {
                        region.assign_advice(|| "", config.table[c], row, || field(v))?;
                    }
                }
                config.q_first.enable(&mut region, 0)?;
                config.q_last.enable(&mut region, n - 1)?;
                let mut totals = [0i128; 5];
                for (row, r) in sorted.iter().enumerate() {
                    config.q_sorted.enable(&mut region, row)?;
                    for (c, &v) in r.iter().enumerate() {
                        region.assign_advice(|| "", config.sorted[c], row, || field(v))?;
                    }
                    keep.assign(
                        &mut region,
                        row,
                        &[F::from(r[SHIPDATE])],
                        &[F::from(SHIP_DATE)],
                    )?;
                    let same = row > 0 && sorted[row - 1][FLAG] == r[FLAG];
                    if row > 0 {
                        config.q_adjacent.enable(&mut region, row)?;
                        let (p, c) = (F::from(sorted[row - 1][FLAG]), F::from(r[FLAG]));
                        order.assign(&mut region, row, &[p], &[c])?;
                        same_flag.assign(&mut region, row, Value::known(p - c))?;
                    }
                    if row + 1 < n {
                        config.q_not_last.enable(&mut region, row)?;
                    }
                    let kept = r[SHIPDATE] <= SHIP_DATE;
                    let t = terms(r);
                    for i in 0..5 {
                        let term = if kept { t[i] } else { 0 };
                        totals[i] = if same { totals[i] + term } else { term };
                        region.assign_advice(
                            || "",
                            config.sums[i],
                            row,
                            || Value::known(signed::<F>(totals[i])),
                        )?;
                    }
                    empty.assign(&mut region, row, Value::known(signed::<F>(totals[4])))?;
                    let end = sorted.get(row + 1).map_or(true, |n| n[FLAG] != r[FLAG]);
                    region.assign_advice(|| "", config.same, row, || field(same as u64))?;
                    region.assign_advice(|| "", config.end, row, || field(end as u64))?;
                    let emit = end && totals[4] > 0;
                    region.assign_advice(|| "", config.emit, row, || field(emit as u64))?;
                }
                for row in 1..n {
                    let flag = |r: usize| result.get(r).map_or(F::ZERO, |g| g[0]);
                    out_order.assign(&mut region, row, &[flag(row - 1), F::ONE], &[flag(row)])?;
                }
                config.output.assign_fields(&mut region, n, &result)
            },
        )?;
        config.output.publish(&mut layouter, &cells)
    }
}

/// Proves and verifies Q1 over `rows` at Halo2 degree `k`, the proof bound to
/// the data owner's commitments to the table.
pub fn run(k: u32, rows: Vec<[u64; WIDTH]>, proof_path: &str) -> MicroResult {
    let circuit = Q1Circuit::<Fp>::new(rows.clone());
    let result = circuit.result();
    let public = (0..OUT)
        .map(|c| result.iter().map(|g| signed::<Fp>(g[c])).collect())
        .collect();
    let table = (0..WIDTH)
        .map(|c| rows.iter().map(|r| Fp::from(r[c])).collect())
        .collect();
    prove_fields(circuit, k, public, Some(table), proof_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    fn rows(n: usize) -> Vec<[u64; WIDTH]> {
        let mut s = 7u64;
        let mut next = |b: u64| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (s >> 33) % b
        };
        let flags = [b'A' as u64, b'N' as u64, b'R' as u64];
        (0..n)
            .map(|_| {
                [
                    1 + next(50),
                    100 + next(10_000),
                    next(11),
                    next(9),
                    flags[next(3) as usize],
                    SHIP_DATE - 200 + next(400),
                ]
            })
            .collect()
    }

    fn mock(circuit: &Q1Circuit<Fp>, result: &[[i128; OUT]]) -> bool {
        let public = (0..OUT)
            .map(|c| result.iter().map(|g| signed::<Fp>(g[c])).collect())
            .collect();
        MockProver::run(11, circuit, public)
            .unwrap()
            .verify()
            .is_ok()
    }

    #[test]
    fn q1_accepts_its_result_only() {
        let circuit = Q1Circuit::<Fp>::new(rows(300));
        let result = circuit.result();
        assert_eq!(result.len(), 3);
        assert!(mock(&circuit, &result));
        let mut wrong = result.clone();
        wrong[1][3] += 1;
        assert!(!mock(&circuit, &wrong));
        assert!(!mock(&circuit, &result[..2]));
    }
}
