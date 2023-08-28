use ast::analyzed::{Expression, Identity, IdentityKind, PolynomialReference, SelectedExpressions};
use itertools::{Either, Itertools};
use number::FieldElement;

use super::{
    affine_expression::AffineExpression,
    machines::{FixedLookup, KnownMachine, Machine},
    rows::RowPair,
    EvalResult, EvalValue, FixedData, IncompleteCause,
};

/// Computes (value or range constraint) updates given a [RowPair] and [Identity].
pub struct IdentityProcessor<'a, 'b, T: FieldElement> {
    fixed_data: &'a FixedData<'a, T>,
    fixed_lookup: &'b mut FixedLookup<T>,
    machines: &'b mut Vec<KnownMachine<'a, T>>,
}

impl<'a, 'b, T: FieldElement> IdentityProcessor<'a, 'b, T> {
    pub fn new(
        fixed_data: &'a FixedData<'a, T>,
        fixed_lookup: &'b mut FixedLookup<T>,
        machines: &'b mut Vec<KnownMachine<'a, T>>,
    ) -> Self {
        Self {
            fixed_data,
            fixed_lookup,
            machines,
        }
    }

    /// Given an identity and a row pair, tries to figure out additional values / range constraints
    /// for the given cells.
    /// Fails if any constraint was not satisfiable.
    /// Returns the updates.
    pub fn process_identity(
        &mut self,
        identity: &'a Identity<T>,
        rows: &RowPair<'_, 'a, T>,
    ) -> EvalResult<'a, T> {
        match identity.kind {
            IdentityKind::Polynomial => self.process_polynomial_identity(identity, rows),
            IdentityKind::Plookup | IdentityKind::Permutation => {
                self.process_plookup(identity, rows)
            }
            kind => {
                unimplemented!(
                    "Identity of kind {kind:?} is not supported by the identity processor."
                )
            }
        }
    }

    fn process_polynomial_identity(
        &self,
        identity: &'a Identity<T>,
        rows: &RowPair<T>,
    ) -> EvalResult<'a, T> {
        let expression = identity.expression_for_poly_id();
        let evaluated = match rows.evaluate(expression) {
            Err(inclomplete_cause) => return Ok(EvalValue::incomplete(inclomplete_cause)),
            Ok(evaluated) => evaluated,
        };

        evaluated.solve_with_range_constraints(rows)
    }

    fn process_plookup(
        &mut self,
        identity: &'a Identity<T>,
        rows: &RowPair<'_, 'a, T>,
    ) -> EvalResult<'a, T> {
        if let Some(left_selector) = &identity.left.selector {
            if let Some(status) = self.handle_left_selector(left_selector, rows) {
                return Ok(status);
            }
        }

        let left = identity
            .left
            .expressions
            .iter()
            .map(|e| rows.evaluate(e))
            .collect::<Vec<_>>();

        // Fail if the LHS has an error.
        let (left, errors): (Vec<_>, Vec<_>) = left.into_iter().partition_map(|x| match x {
            Ok(x) => Either::Left(x),
            Err(x) => Either::Right(x),
        });
        if !errors.is_empty() {
            return Ok(EvalValue::incomplete(
                errors.into_iter().reduce(|x, y| x.combine(y)).unwrap(),
            ));
        }

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

        for m in self.machines.iter_mut() {
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

    /// Handles the lookup that connects the current machine to the calling machine.
    /// Arguments:
    /// - `left`: The evaluation of the left side of the lookup (symbolic for unknown values).
    /// - `right`: The expressions on the right side of the lookup.
    /// - `current_rows`: The [RowPair] needed to evaluate the right side of the lookup.
    /// Returns:
    /// - `Ok(updates)`: The updates for the lookup.
    /// - `Err(e)`: If the constraint system is not satisfiable.
    pub fn process_link(
        &mut self,
        left: &[AffineExpression<&'a PolynomialReference, T>],
        right: &'a SelectedExpressions<T>,
        current_rows: &RowPair<'_, 'a, T>,
    ) -> EvalResult<'a, T> {
        // sanity check that the right hand side selector is active
        let selector_value = right
            .selector
            .as_ref()
            .map(|s| current_rows.evaluate(s).unwrap().constant_value().unwrap())
            .unwrap_or(T::one());
        assert_eq!(selector_value, T::one());

        let mut updates = EvalValue::complete(vec![]);

        for (l, r) in left.iter().zip(right.expressions.iter()) {
            match current_rows.evaluate(r) {
                Ok(r) => {
                    let result = (l.clone() - r).solve()?;
                    updates.combine(result);
                }
                Err(e) => {
                    updates.status = updates.status.combine(e);
                }
            }
        }
        Ok(updates)
    }

    /// Returns updates of the left selector cannot be evaluated to 1, otherwise None.
    fn handle_left_selector(
        &mut self,
        left_selector: &'a Expression<T>,
        rows: &RowPair<T>,
    ) -> Option<EvalValue<&'a PolynomialReference, T>> {
        let value = match rows.evaluate(left_selector) {
            Err(inclomplete_cause) => return Some(EvalValue::incomplete(inclomplete_cause)),
            Ok(value) => value,
        };
        match value.constant_value() {
            Some(v) if v.is_zero() => Some(EvalValue::complete(vec![])),
            Some(v) if v.is_one() => None,
            _ => Some(EvalValue::incomplete(
                IncompleteCause::NonConstantLeftSelector,
            )),
        }
    }
}
