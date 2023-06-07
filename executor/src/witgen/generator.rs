use itertools::Itertools;
use parser_util::lines::indent;
use pil_analyzer::{Expression, Identity, IdentityKind, PolynomialReference};
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};
// TODO should use finite field instead of abstract number
use number::{DegreeType, FieldElement};

use super::affine_expression::{AffineExpression, AffineResult};
use super::bit_constraints::{BitConstraint, BitConstraintSet};

use super::expression_evaluator::ExpressionEvaluator;
use super::machines::{FixedLookup, Machine};
use super::symbolic_witness_evaluator::{SymoblicWitnessEvaluator, WitnessColumnEvaluator};
use super::{Constraint, EvalResult, EvalValue, FixedData, IncompleteCause, WitnessColumn};

pub struct Generator<'a, T: FieldElement, QueryCallback> {
    fixed_data: &'a FixedData<'a, T>,
    fixed_lookup: &'a mut FixedLookup<T>,
    identities: &'a [IdentityData<'a, T>],
    machines: Vec<Box<dyn Machine<T>>>,
    query_callback: Option<QueryCallback>,
    global_bit_constraints: BTreeMap<&'a PolynomialReference, BitConstraint<T>>,
    /// Values of the witness polynomials
    current: Vec<Option<T>>,
    /// Values of the witness polynomials in the next row
    next: Vec<Option<T>>,
    /// Bit constraints on the witness polynomials in the next row.
    next_bit_constraints: Vec<Option<BitConstraint<T>>>,
    next_row: DegreeType,
    failure_reasons: Vec<String>,
    progress: bool,
    last_report: DegreeType,
    last_report_time: Instant,
    identity_performance_data: Vec<IdentityPerformanceData>,
}

pub struct IdentityData<'a, T> {
    identity: &'a Identity<T>,
    contains_next_witness_ref: bool,
}

#[derive(Default, Clone)]
struct IdentityPerformanceData {
    calls: u64,
    total_time: u128,
}

impl<'a, T> From<&'a Identity<T>> for IdentityData<'a, T> {
    fn from(identity: &'a Identity<T>) -> Self {
        let contains_next_witness_ref = match identity.kind {
            IdentityKind::Polynomial => identity
                .left
                .selector
                .as_ref()
                .unwrap()
                .contains_next_witness_ref(),
            IdentityKind::Plookup | IdentityKind::Permutation | IdentityKind::Connect => false,
        };
        IdentityData {
            identity,
            contains_next_witness_ref,
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum EvaluationRow {
    /// p is p[next_row - 1], p' is p[next_row]
    Current,
    /// p is p[next_row], p' is p[next_row + 1]
    Next,
}

impl<'a, T: FieldElement, QueryCallback> Generator<'a, T, QueryCallback>
where
    QueryCallback: FnMut(&str) -> Option<T>,
{
    pub fn new(
        fixed_data: &'a FixedData<'a, T>,
        fixed_lookup: &'a mut FixedLookup<T>,
        identities: &'a [IdentityData<'a, T>],
        global_bit_constraints: BTreeMap<&'a PolynomialReference, BitConstraint<T>>,
        machines: Vec<Box<dyn Machine<T>>>,
        query_callback: Option<QueryCallback>,
    ) -> Self {
        let witness_cols_len = fixed_data.witness_cols.len();

        Generator {
            fixed_data,
            fixed_lookup,
            identities,
            machines,
            query_callback,
            global_bit_constraints,
            current: vec![None; witness_cols_len],
            next: vec![None; witness_cols_len],
            next_bit_constraints: vec![None; witness_cols_len],
            next_row: 0,
            failure_reasons: vec![],
            progress: true,
            last_report: 0,
            last_report_time: Instant::now(),
            identity_performance_data: vec![Default::default(); identities.len()],
        }
    }

    pub fn compute_next_row(&mut self, next_row: DegreeType) -> Vec<T> {
        self.set_next_row_and_log(next_row);

        // TODO maybe better to generate a dependency graph than looping multiple times.
        // TODO at least we could cache the affine expressions between loops.

        let mut complete_identities = vec![false; self.identities.len()];
        let mut performance_data = std::mem::take(&mut self.identity_performance_data);

        let mut identity_failed;
        loop {
            identity_failed = false;
            self.progress = false;
            self.failure_reasons.clear();

            for ((identity, performance), complete) in self
                .identities
                .iter()
                .zip(performance_data.iter_mut())
                .zip(complete_identities.iter_mut())
                .filter(|(_, complete)| !**complete)
            {
                performance.calls += 1;
                let start = Instant::now();
                let IdentityData {
                    identity,
                    contains_next_witness_ref,
                } = identity;
                let result = match identity.kind {
                    IdentityKind::Polynomial => self.process_polynomial_identity(
                        identity.left.selector.as_ref().unwrap(),
                        *contains_next_witness_ref,
                    ),
                    IdentityKind::Plookup | IdentityKind::Permutation => {
                        self.process_plookup(identity)
                    }
                    kind => {
                        unimplemented!("Identity of kind {kind:?} is not supported in the executor")
                    }
                }
                .map_err(|err| {
                    format!(
                        "No progress on {identity}:\n{}",
                        indent(&format!("{err}"), "    ")
                    )
                    .into()
                });

                match &result {
                    Ok(e) => {
                        *complete = e.is_complete();
                    }
                    Err(_) => {
                        identity_failed = true;
                    }
                };

                self.handle_eval_result(result);
                let taken = start.elapsed().as_nanos();
                performance.total_time += taken;
            }

            if self.query_callback.is_some() {
                for column in self.fixed_data.witness_cols() {
                    // TODO we should actually query even if it is already known, to check
                    // if the value would be different.
                    if !self.has_known_next_value(column.poly.poly_id() as usize)
                        && column.query.is_some()
                    {
                        let result = self.process_witness_query(&column);
                        self.handle_eval_result(result)
                    }
                }
            }

            if !self.progress {
                break;
            }
            if self.next.iter().all(|v| v.is_some()) {
                break;
            }
        }
        self.identity_performance_data = performance_data;

        if identity_failed {
            log::error!(
                "\nError: Row {next_row}: Identity check failed or unable to derive values for some witness columns.\nSet RUST_LOG=debug for more information.");
            log::debug!(
                "The following columns are still undetermined: {}",
                self.next
                    .iter()
                    .enumerate()
                    .filter_map(|(i, v)| if v.is_none() {
                        Some(self.fixed_data.witness_cols[i].poly.to_string())
                    } else {
                        None
                    })
                    .collect::<Vec<String>>()
                    .join(", ")
            );
            log::debug!("Reasons:\n{}\n", self.failure_reasons.join("\n\n"));
            log::debug!(
                "Determind bit constraints for this row:\n{}",
                self.next_bit_constraints
                    .iter()
                    .enumerate()
                    .filter_map(|(id, cons)| {
                        cons.as_ref().map(|cons| {
                            format!("  {}: {cons}", self.fixed_data.witness_cols[id].poly)
                        })
                    })
                    .join("\n")
            );
            log::debug!(
                "Current values (known nonzero first, then zero, unknown omitted):\n{}",
                indent(&self.format_next_known_values().join("\n"), "    ")
            );
            panic!();
        } else {
            log::trace!(
                "===== Row {next_row}:\n{}",
                indent(&self.format_next_values().join("\n"), "    ")
            );
            std::mem::swap(&mut self.next, &mut self.current);
            self.next = vec![None; self.current.len()];
            self.next_bit_constraints = vec![None; self.current.len()];
            // TODO check a bit better that "None" values do not
            // violate constraints.
            self.current
                .iter()
                .map(|v| (*v).unwrap_or_default())
                .collect()
        }
    }

    /// Verifies the proposed values for the next row.
    /// TODO this is bad for machines because we might introduce rows in the machine that are then
    /// not used.
    pub fn propose_next_row(&mut self, next_row: DegreeType, values: &[T]) -> bool {
        self.set_next_row_and_log(next_row);
        self.next = values.iter().cloned().map(Some).collect();

        for IdentityData {
            identity,
            contains_next_witness_ref,
        } in self.identities
        {
            let result = match identity.kind {
                IdentityKind::Polynomial => self.process_polynomial_identity(
                    identity.left.selector.as_ref().unwrap(),
                    *contains_next_witness_ref,
                ),
                IdentityKind::Plookup | IdentityKind::Permutation => self.process_plookup(identity),
                kind => {
                    unimplemented!("Identity of kind {kind:?} is not supported in the executor")
                }
            };
            if result.is_err() {
                self.next = vec![None; self.current.len()];
                self.next_bit_constraints = vec![None; self.current.len()];
                return false;
            }
        }
        std::mem::swap(&mut self.next, &mut self.current);
        self.next = vec![None; self.current.len()];
        self.next_bit_constraints = vec![None; self.current.len()];
        true
    }

    pub fn machine_witness_col_values(&mut self) -> HashMap<String, Vec<T>> {
        let mut result: HashMap<_, _> = Default::default();
        for m in &mut self.machines {
            result.extend(m.witness_col_values(self.fixed_data));
        }
        result
    }

    fn set_next_row_and_log(&mut self, next_row: DegreeType) {
        if next_row >= self.last_report + 1000 {
            let duration = self.last_report_time.elapsed();
            self.last_report_time = Instant::now();

            log::info!(
                "{next_row} of {} rows ({} %, {} rows per second)",
                self.fixed_data.degree,
                next_row * 100 / self.fixed_data.degree,
                1000000 / duration.as_millis()
            );
            self.last_report = next_row;
        }
        self.next_row = next_row;
    }

    fn format_next_values(&self) -> Vec<String> {
        self.format_next_values_iter(self.next.iter().enumerate())
    }

    fn format_next_known_values(&self) -> Vec<String> {
        self.format_next_values_iter(self.next.iter().enumerate().filter(|(_, v)| v.is_some()))
    }

    fn format_next_values_iter<'b>(
        &self,
        values: impl IntoIterator<Item = (usize, &'b Option<T>)>,
    ) -> Vec<String> {
        let mut values = values.into_iter().collect::<Vec<_>>();
        values.sort_by_key(|(i, v1)| {
            (
                match v1 {
                    Some(v) if *v == 0.into() => 1,
                    Some(_) => 0,
                    None => 2,
                },
                *i,
            )
        });
        values
            .into_iter()
            .map(|(i, v)| {
                format!(
                    "{} = {}",
                    self.fixed_data.witness_cols[i].poly,
                    v.as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "<unknown>".to_string())
                )
            })
            .collect()
    }

    fn process_witness_query(&mut self, column: &&'a WitnessColumn<T>) -> EvalResult<'a, T> {
        let query = match self.interpolate_query(column.query.unwrap()) {
            Ok(query) => query,
            Err(incomplete) => return Ok(EvalValue::incomplete(incomplete)),
        };
        if let Some(value) = self.query_callback.as_mut().and_then(|c| (c)(&query)) {
            Ok(EvalValue::complete(vec![(
                &column.poly,
                Constraint::Assignment(value),
            )]))
        } else {
            Ok(EvalValue::incomplete(IncompleteCause::NoQueryAnswer(
                query,
                column.poly.name.to_string(),
            )))
        }
    }

    fn interpolate_query<'b>(
        &self,
        query: &'b Expression<T>,
    ) -> Result<String, IncompleteCause<&'b PolynomialReference>> {
        if let Ok(v) = self.evaluate(query, EvaluationRow::Next) {
            if v.is_constant() {
                return Ok(v.to_string());
            }
        }
        // TODO combine that with the constant evaluator and the commit evaluator...
        match query {
            Expression::Tuple(items) => Ok(items
                .iter()
                .map(|i| self.interpolate_query(i))
                .collect::<Result<Vec<_>, _>>()?
                .join(", ")),
            Expression::LocalVariableReference(i) => {
                assert!(*i == 0);
                Ok(format!("{}", self.next_row))
            }
            Expression::String(s) => Ok(format!(
                "\"{}\"",
                s.replace('\\', "\\\\").replace('"', "\\\"")
            )),
            Expression::MatchExpression(scrutinee, arms) => {
                self.interpolate_match_expression_for_query(scrutinee.as_ref(), arms)
            }
            query => unimplemented!("Cannot handle / evaluate {query}"),
        }
    }

    fn interpolate_match_expression_for_query<'b>(
        &self,
        scrutinee: &'b Expression<T>,
        arms: &'b [(Option<T>, Expression<T>)],
    ) -> Result<String, IncompleteCause<&'b PolynomialReference>> {
        let v = self
            .evaluate(scrutinee, EvaluationRow::Next)?
            .constant_value()
            .ok_or(IncompleteCause::NonConstantQueryMatchScrutinee)?;
        let (_, expr) = arms
            .iter()
            .find(|(n, _)| n.is_none() || n.as_ref() == Some(&v))
            .ok_or(IncompleteCause::NoMatchArmFound)?;
        self.interpolate_query(expr)
    }

    fn process_polynomial_identity<'b>(
        &self,
        identity: &'b Expression<T>,
        contains_next_witness_ref: bool,
    ) -> EvalResult<'b, T> {
        // If there is no "next" reference in the expression,
        // we just evaluate it directly on the "next" row.
        let row = if contains_next_witness_ref {
            // TODO this is the only situation where we use "current"
            // TODO this is the only that actually uses a window.
            EvaluationRow::Current
        } else {
            EvaluationRow::Next
        };
        let evaluated = match self.evaluate(identity, row) {
            Ok(evaluated) => evaluated,
            Err(cause) => return Ok(EvalValue::incomplete(cause)),
        };
        if evaluated.constant_value() == Some(0.into()) {
            Ok(EvalValue::complete(vec![]))
        } else {
            evaluated.solve_with_bit_constraints(&self.bit_constraint_set())
        }
    }

    fn process_plookup<'b>(&mut self, identity: &'b Identity<T>) -> EvalResult<'b, T> {
        if let Some(left_selector) = &identity.left.selector {
            let value = match self.evaluate(left_selector, EvaluationRow::Next) {
                Ok(value) => value,
                Err(cause) => return Ok(EvalValue::incomplete(cause)),
            };
            match value.constant_value() {
                Some(v) if v == 0.into() => {
                    return Ok(EvalValue::complete(vec![]));
                }
                Some(v) if v == 1.into() => {}
                _ => {
                    return Ok(EvalValue::incomplete(
                        IncompleteCause::NonConstantLeftSelector,
                    ))
                }
            };
        }

        let left = identity
            .left
            .expressions
            .iter()
            .map(|e| self.evaluate(e, EvaluationRow::Next))
            .collect::<Vec<_>>();

        // Now query the machines.
        // Note that we should always query all machines that match, because they might
        // update their internal data, even if all values are already known.
        // TODO could it be that multiple machines match?

        // query the fixed lookup "machine"
        if let Some(result) = self.fixed_lookup.process_plookup(
            self.fixed_data,
            identity.kind,
            &left,
            &identity.right,
        ) {
            return result;
        }

        for m in &mut self.machines {
            // TODO also consider the reasons above.
            if let Some(result) = m.process_plookup(
                self.fixed_data,
                self.fixed_lookup,
                identity.kind,
                &left,
                &identity.right,
            ) {
                return result;
            }
        }

        unimplemented!("No executor machine matched identity `{identity}`")
    }

    fn handle_eval_result(&mut self, result: EvalResult<T>) {
        match result {
            Ok(constraints) => {
                if !constraints.is_empty() {
                    self.progress = true;
                }
                for (id, c) in constraints.constraints {
                    match c {
                        Constraint::Assignment(value) => {
                            self.next[id.poly_id() as usize] = Some(value);
                        }
                        Constraint::BitConstraint(cons) => {
                            self.next_bit_constraints[id.poly_id() as usize] = Some(cons);
                        }
                    }
                }
            }
            Err(reason) => {
                self.failure_reasons.push(format!("{reason}"));
            }
        }
    }

    fn has_known_next_value(&self, id: usize) -> bool {
        self.next[id].is_some()
    }

    /// Tries to evaluate the expression to an expression affine in the witness polynomials,
    /// taking current values of polynomials into account.
    /// @returns an expression affine in the witness polynomials
    fn evaluate<'b>(
        &self,
        expr: &'b Expression<T>,
        evaluate_row: EvaluationRow,
    ) -> AffineResult<&'b PolynomialReference, T> {
        let degree = self.fixed_data.degree;
        let fixed_row = match evaluate_row {
            EvaluationRow::Current => (self.next_row + degree - 1) % degree,
            EvaluationRow::Next => self.next_row,
        };

        ExpressionEvaluator::new(SymoblicWitnessEvaluator::new(
            self.fixed_data,
            fixed_row,
            EvaluationData {
                current_witnesses: &self.current,
                next_witnesses: &self.next,
                evaluate_row,
            },
        ))
        .evaluate(expr)
    }

    fn bit_constraint_set(&'a self) -> WitnessBitConstraintSet<'a, T> {
        WitnessBitConstraintSet {
            global_bit_constraints: &self.global_bit_constraints,
            next_bit_constraints: &self.next_bit_constraints,
        }
    }
}

struct WitnessBitConstraintSet<'a, T: FieldElement> {
    /// Global constraints on witness and fixed polynomials.
    global_bit_constraints: &'a BTreeMap<&'a PolynomialReference, BitConstraint<T>>,
    /// Bit constraints on the witness polynomials in the next row.
    next_bit_constraints: &'a Vec<Option<BitConstraint<T>>>,
}

impl<'a, T: FieldElement> BitConstraintSet<&PolynomialReference, T>
    for WitnessBitConstraintSet<'a, T>
{
    fn bit_constraint(&self, poly: &PolynomialReference) -> Option<BitConstraint<T>> {
        self.global_bit_constraints
            .get(poly)
            .or_else(|| {
                poly.is_witness()
                    .then(|| self.next_bit_constraints[poly.poly_id() as usize].as_ref())
                    .flatten()
            })
            .cloned()
    }
}

struct EvaluationData<'a, T> {
    /// Values of the witness polynomials in the current / last row
    pub current_witnesses: &'a Vec<Option<T>>,
    /// Values of the witness polynomials in the next row
    pub next_witnesses: &'a Vec<Option<T>>,
    pub evaluate_row: EvaluationRow,
}

impl<'a, T: FieldElement> WitnessColumnEvaluator<T> for EvaluationData<'a, T> {
    fn value<'b>(&self, poly: &'b PolynomialReference) -> AffineResult<&'b PolynomialReference, T> {
        let id = poly.poly_id() as usize;
        match (poly.next, self.evaluate_row) {
            (false, EvaluationRow::Current) => {
                // All values in the "current" row should usually be known.
                // The exception is when we start the analysis on the first row.
                self.current_witnesses[id]
                    .as_ref()
                    .map(|value| (*value).into())
                    .ok_or(IncompleteCause::PreviousValueUnknown(poly))
            }
            (false, EvaluationRow::Next) | (true, EvaluationRow::Current) => {
                Ok(if let Some(value) = &self.next_witnesses[id] {
                    // We already computed the concrete value
                    (*value).into()
                } else {
                    // We continue with a symbolic value
                    AffineExpression::from_variable_id(poly)
                })
            }
            (true, EvaluationRow::Next) => {
                unimplemented!(
                    "{poly} references the next-next row when evaluating on the current row."
                );
            }
        }
    }
}
