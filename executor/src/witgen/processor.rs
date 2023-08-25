use std::collections::HashSet;

use ast::analyzed::{Identity, PolyID, PolynomialReference, SelectedExpressions};
use number::FieldElement;

use crate::witgen::Constraint;

use super::{
    affine_expression::AffineExpression,
    identity_processor::IdentityProcessor,
    rows::{Row, RowFactory, RowPair, RowUpdater, UnknownStrategy},
    sequence_iterator::{IdentityInSequence, ProcessingSequenceIterator, SequenceStep},
    Constraints, EvalError, FixedData,
};

pub struct Calldata<'a, 'b, T: FieldElement> {
    left: &'b [AffineExpression<&'a PolynomialReference, T>],
    right: &'a SelectedExpressions<T>,
    left_mut: Vec<AffineExpression<&'a PolynomialReference, T>>,
}

impl<'a, 'b, T: FieldElement> Calldata<'a, 'b, T> {
    pub fn new(
        left: &'b [AffineExpression<&'a PolynomialReference, T>],
        right: &'a SelectedExpressions<T>,
    ) -> Self {
        Self {
            left,
            right,
            left_mut: left.to_vec(),
        }
    }
}

/// A basic processor that knows how to determine a unique satisfying witness
/// for a given list of identities.
/// This current implementation is very rudimentary and only used in the block machine
/// to "fix" the last row. However, in the future we can generalize it to be used
/// for general block machine or VM witness computation.
pub struct Processor<'a, 'b, T: FieldElement> {
    /// The global index of the first row of [Processor::data].
    row_offset: u64,
    /// The rows that are being processed.
    data: Vec<Row<'a, T>>,
    /// The list of identities
    identities: &'b [&'a Identity<T>],
    /// The identity processor
    identity_processor: IdentityProcessor<'a, 'b, T>,
    /// The fixed data (containing information about all columns)
    fixed_data: &'a FixedData<'a, T>,
    /// The row factory
    row_factory: RowFactory<'a, T>,
    /// The set of witness columns that are actually part of this machine.
    witness_cols: &'b HashSet<PolyID>,
    calldata: Option<Calldata<'a, 'b, T>>,
}

impl<'a, 'b, T: FieldElement> Processor<'a, 'b, T> {
    pub fn new(
        row_offset: u64,
        data: Vec<Row<'a, T>>,
        identity_processor: IdentityProcessor<'a, 'a, T>,
        identities: &'b [&'a Identity<T>],
        fixed_data: &'a FixedData<'a, T>,
        row_factory: RowFactory<'a, T>,
        witness_cols: &'b HashSet<PolyID>,
    ) -> Self {
        Self {
            row_offset,
            data,
            identity_processor,
            identities,
            fixed_data,
            row_factory,
            witness_cols,
            calldata: None,
        }
    }

    pub fn with_calldata(self, calldata: Calldata<'a, 'b, T>) -> Self {
        Self {
            calldata: Some(calldata),
            ..self
        }
    }

    /// Evaluate all identities on all *non-wrapping* row pairs, assuming zero for unknown values.
    /// If any identity was unsatisfied, returns an error.
    pub fn check_constraints(&mut self) -> Result<(), EvalError<T>> {
        for i in 0..(self.data.len() - 1) {
            let row_pair = RowPair::new(
                &self.data[i],
                &self.data[i + 1],
                self.row_offset + i as u64,
                self.fixed_data,
                UnknownStrategy::Zero,
            );
            for identity in self.identities {
                self.identity_processor
                    .process_identity(identity, &row_pair)?;
            }
        }
        Ok(())
    }

    /// Reset the row at the given index to a fresh row.
    pub fn clear_row(&mut self, index: usize) {
        self.data[index] = self.row_factory.fresh_row();
    }

    /// Figures out unknown values.
    pub fn solve(
        &mut self,
        sequence_iterator: &mut ProcessingSequenceIterator,
    ) -> Result<Constraints<&'a PolynomialReference, T>, EvalError<T>> {
        let mut outer_assignments = vec![];

        while let Some(step) = sequence_iterator.next() {
            let SequenceStep {
                row_delta,
                identity,
            } = step;
            let row_index = (1 + row_delta) as usize;
            let progress = match identity {
                IdentityInSequence::Internal(identity_index) => {
                    self.process_identity(row_index, identity_index)?
                }
                IdentityInSequence::OuterQuery => {
                    // TODO: Fail if not?
                    if self.calldata.is_some() {
                        let (progress, new_outer_assignments) =
                            self.process_outer_query(row_index)?;
                        outer_assignments.extend(new_outer_assignments);
                        progress
                    } else {
                        false
                    }
                }
            };
            sequence_iterator.report_progress(progress);
        }
        Ok(outer_assignments)
    }

    /// Destroys itself, returns the data.
    pub fn finish(
        self,
    ) -> (
        Vec<Row<'a, T>>,
        Option<Vec<AffineExpression<&'a PolynomialReference, T>>>,
    ) {
        (self.data, self.calldata.map(|c| c.left_mut))
    }

    /// On a row pair of a given index, iterate over all identities until no more progress is made.
    /// For each identity, it tries to figure out unknown values and updates it.
    fn process_identity(
        &mut self,
        row_index: usize,
        identity_index: usize,
    ) -> Result<bool, EvalError<T>> {
        let identity = &self.identities[identity_index];

        // Create row pair
        let row_pair = RowPair::new(
            &self.data[row_index],
            &self.data[row_index + 1],
            self.row_offset + row_index as u64,
            self.fixed_data,
            UnknownStrategy::Unknown,
        );

        // Compute updates
        let updates = self
            .identity_processor
            .process_identity(identity, &row_pair)
            .map_err(|e| {
                log::warn!("Error in identity: {identity}");
                e
            })?;

        // Build RowUpdater
        // (a bit complicated, because we need two mutable
        // references to elements of the same vector)
        let (before, after) = self.data.split_at_mut(row_index + 1);
        let current = before.last_mut().unwrap();
        let next = after.first_mut().unwrap();
        let mut row_updater = RowUpdater::new(current, next, self.row_offset + row_index as u64);

        // Apply the updates, return progress
        Ok(row_updater.apply_updates(&updates, || identity.to_string()))
    }

    // TODO: Remove code duplication with process_identity
    fn process_outer_query(
        &mut self,
        row_index: usize,
    ) -> Result<(bool, Constraints<&'a PolynomialReference, T>), EvalError<T>> {
        let Calldata {
            left,
            right,
            left_mut,
        } = self.calldata.as_mut().unwrap();

        // Create row pair
        let row_pair = RowPair::new(
            &self.data[row_index],
            &self.data[row_index + 1],
            self.row_offset + row_index as u64,
            self.fixed_data,
            UnknownStrategy::Unknown,
        );

        let updates = self
            .identity_processor
            .process_link(left, right, &row_pair)?;

        if updates.constraints.is_empty() {
            return Ok((false, vec![]));
        }

        log::trace!("    Updates from: outer query");
        // Build RowUpdater
        // (a bit complicated, because we need two mutable
        // references to elements of the same vector)
        let (before, after) = self.data.split_at_mut(row_index + 1);
        let current = before.last_mut().unwrap();
        let next = after.first_mut().unwrap();
        let mut row_updater = RowUpdater::new(current, next, self.row_offset + row_index as u64);

        if updates.constraints.is_empty() {
            return Ok((false, vec![]));
        }

        for (poly, c) in &updates.constraints {
            if self.witness_cols.contains(&poly.poly_id()) {
                row_updater.apply_update(poly, c);
            } else if let Constraint::Assignment(v) = c {
                for l in left_mut.iter_mut() {
                    log::trace!("      => {} (outer) = {}", poly, v);
                    l.assign(poly, *v);
                }
            };
        }

        let outer_assignments = updates
            .constraints
            .into_iter()
            .filter(|(poly, _)| !self.witness_cols.contains(&poly.poly_id()))
            .collect::<Vec<_>>();

        Ok((true, outer_assignments))
    }
}
