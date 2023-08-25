use ast::analyzed::Identity;
use number::FieldElement;

use super::{
    identity_processor::IdentityProcessor,
    rows::{Row, RowFactory, RowPair, RowUpdater, UnknownStrategy},
    sequence_iterator::{IdentityInSequence, ProcessingSequenceIterator, SequenceStep},
    EvalError, FixedData,
};

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
    sequence_iterator: ProcessingSequenceIterator,
}

impl<'a, 'b, T: FieldElement> Processor<'a, 'b, T> {
    pub fn new(
        row_offset: u64,
        data: Vec<Row<'a, T>>,
        identity_processor: IdentityProcessor<'a, 'a, T>,
        identities: &'b [&'a Identity<T>],
        fixed_data: &'a FixedData<'a, T>,
        row_factory: RowFactory<'a, T>,
        sequence_iterator: ProcessingSequenceIterator,
    ) -> Self {
        Self {
            row_offset,
            data,
            identity_processor,
            identities,
            fixed_data,
            row_factory,
            sequence_iterator,
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
    /// The current strategy is to go over *non-wrapping* row pairs once,
    /// but this can be generalized in the future.
    pub fn solve(&mut self) -> Result<(), EvalError<T>> {
        while let Some(step) = self.sequence_iterator.next() {
            let SequenceStep {
                row_delta,
                identity,
            } = step;
            match identity {
                IdentityInSequence::Internal(identity_index) => {
                    let progress = self.iterate_on_row_pair(row_delta, identity_index)?;
                    self.sequence_iterator.report_progress(progress);
                }
                // TODO: Implement outer query
                IdentityInSequence::OuterQuery => {}
            }
        }
        Ok(())
    }

    /// Destroys itself, returns the data.
    pub fn finish(self) -> Vec<Row<'a, T>> {
        self.data
    }

    /// On a row pair of a given index, iterate over all identities until no more progress is made.
    /// For each identity, it tries to figure out unknown values and updates it.
    fn iterate_on_row_pair(
        &mut self,
        row: usize,
        identity_index: usize,
    ) -> Result<bool, EvalError<T>> {
        let identity = &self.identities[identity_index];

        // Create row pair
        let row_pair = RowPair::new(
            &self.data[row],
            &self.data[row + 1],
            self.row_offset + row as u64,
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
        let (before, after) = self.data.split_at_mut(row + 1);
        let current = before.last_mut().unwrap();
        let next = after.first_mut().unwrap();
        let mut row_updater = RowUpdater::new(current, next, self.row_offset + row as u64);

        // Apply the updates, return progress
        Ok(row_updater.apply_updates(&updates, || identity.to_string()))
    }
}
