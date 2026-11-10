use std::collections::{HashMap, HashSet};

use super::CompilerError;
use indexmap::IndexSet;
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::ScriptBuilder;

trait ScriptBuilderStackBindingExt {
    fn drop_from_depth(&mut self, depth: i64) -> Result<(), CompilerError>;
    fn pick_from_depth(&mut self, depth: i64) -> Result<(), CompilerError>;
    fn roll_from_depth(&mut self, depth: i64) -> Result<(), CompilerError>;
}

impl ScriptBuilderStackBindingExt for ScriptBuilder {
    fn drop_from_depth(&mut self, depth: i64) -> Result<(), CompilerError> {
        // read: [a, ..., c] = [bottom ... top]
        match depth {
            // [x] -> []
            0 => {
                self.add_op(OpDrop)?;
            }
            // [x, a] -> [a]
            1 => {
                self.add_op(OpNip)?;
            }
            // [x, a, b] -> [a, b]
            2 => {
                self.add_op(OpRot)?;
                self.add_op(OpDrop)?;
            }
            _ => {
                // [..., x, ..., top] -> [..., ..., top]
                self.add_i64(depth)?;
                self.add_op(OpRoll)?;
                self.add_op(OpDrop)?;
            }
        }

        Ok(())
    }

    fn pick_from_depth(&mut self, depth: i64) -> Result<(), CompilerError> {
        // read: [a, ..., c] = [bottom ... top]
        match depth {
            // [x] -> [x, x]
            0 => {
                self.add_op(OpDup)?;
            }
            // [x, a] -> [x, a, x]
            1 => {
                self.add_op(OpOver)?;
            }
            _ => {
                // [..., x, ..., top] -> [..., x, ..., top, x]
                self.add_i64(depth)?;
                self.add_op(OpPick)?;
            }
        }

        Ok(())
    }

    fn roll_from_depth(&mut self, depth: i64) -> Result<(), CompilerError> {
        // read: [a, ..., c] = [bottom ... top]
        match depth {
            // [x] -> [x]
            0 => {}
            // [x, a] -> [a, x]
            1 => {
                self.add_op(OpSwap)?;
            }
            // [x, a, b] -> [a, b, x]
            2 => {
                self.add_op(OpRot)?;
            }
            _ => {
                // [..., x, ..., top] -> [..., ..., top, x]
                self.add_i64(depth)?;
                self.add_op(OpRoll)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct StackBindings {
    // Logical equivalent of the runtime stack, stored top-to-bottom so index
    // equals depth (from top).
    stack: IndexSet<String>,
}

impl PartialEq for StackBindings {
    fn eq(&self, other: &Self) -> bool {
        // `IndexSet`'s default equality is set equality, which ignores order.
        // `StackBindings` equality should mean full stack-layout equality, so
        // we compare the ordered slices directly. Use `set_eq` for relaxed
        // same-bindings comparison.
        self.stack.as_slice() == other.stack.as_slice()
    }
}

impl Eq for StackBindings {}

impl StackBindings {
    pub(crate) fn from_depths(depths: HashMap<String, i64>) -> Self {
        let mut ordered = depths.into_iter().collect::<Vec<_>>();
        ordered.sort_by_key(|(_, depth)| *depth);
        assert!(
            ordered
                .iter()
                .enumerate()
                .all(|(expected_depth, (_, depth))| *depth == expected_depth as i64),
            "illegal stack binding depths"
        );
        Self {
            stack: ordered.into_iter().map(|(name, _)| name).collect(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.stack.len()
    }

    pub(crate) fn contains(&self, name: &str) -> bool {
        self.stack.contains(name)
    }

    pub(crate) fn depth(&self, name: &str) -> Option<i64> {
        self.stack.get_index_of(name).map(|index| index as i64)
    }

    #[allow(dead_code)]
    pub(crate) fn names(&self) -> impl Iterator<Item = &String> {
        self.stack.iter()
    }

    #[allow(dead_code)]
    pub(crate) fn clone_depths(&self) -> HashMap<String, i64> {
        self.stack
            .iter()
            .cloned()
            .enumerate()
            .map(|(depth, name)| (name, depth as i64))
            .collect()
    }

    pub(crate) fn binding_order(&self) -> Vec<String> {
        self.stack.iter().cloned().collect()
    }

    pub(crate) fn set_eq(&self, other: &Self) -> bool {
        // default `IndexSet` equality is set equality (i.e., order can differ)
        self.stack == other.stack
    }

    pub(crate) fn insert_binding(&mut self, name: &str, depth: i64) {
        assert!(
            (0..=self.stack.len() as i64).contains(&depth),
            "depth out of bounds: {depth}"
        );
        let target_index = depth as usize;
        assert!(
            self.stack.insert_before(target_index, name.to_string()).1,
            "binding already exists: {name}"
        );
    }

    pub(crate) fn push_binding(&mut self, name: &str) {
        self.insert_binding(name, 0);
    }

    fn remove_binding(&mut self, name: &str) {
        assert!(
            self.stack.shift_remove(name),
            "removed binding {name} should exist"
        );
    }

    fn move_binding_to_top(&mut self, name: &str) {
        let from = self
            .stack
            .get_index_of(name)
            .expect("binding should exist before moving to top");
        self.stack.move_index(from, 0);
    }

    /// Emits stack ops to remove the named bindings while preserving the
    /// relative order of all surviving bindings.
    ///
    /// The removal order is current top-to-bottom among the bindings being
    /// removed, which minimizes the total `ROLL` depth for this direct
    /// `ROLL+DROP` strategy.
    pub(crate) fn emit_drop_bindings(
        &mut self,
        names: &[String],
        builder: &mut ScriptBuilder,
    ) -> Result<(), CompilerError> {
        if names.is_empty() {
            return Ok(());
        }

        let names_to_remove = names.iter().cloned().collect::<HashSet<_>>();
        for name in self.binding_order() {
            if !names_to_remove.contains(&name) {
                continue;
            }

            let depth = self
                .depth(&name)
                .expect("binding should exist before dropping");
            builder.drop_from_depth(depth)?;

            self.remove_binding(&name);
        }

        Ok(())
    }

    /// Rewrites the physical stack after rebinding an existing binding and
    /// updates the binding model to reflect the new stack shape.
    ///
    /// Assumptions:
    /// - `name` is already bound in this `StackBindings`
    /// - the newly computed RHS value is currently on top of the stack
    /// - the compiler wants the rebound name to move to depth `0`
    ///
    /// Operationally, this rolls the old bound value to the top, drops it, and
    /// leaves the newly computed RHS value at the top. The binding model is
    /// then updated so:
    /// - `name` becomes depth `0`
    /// - bindings that were above the old slot shift by `+1`
    /// - deeper bindings keep their previous depths
    pub(crate) fn emit_update_stack_for_rebinding(
        &mut self,
        name: &str,
        builder: &mut ScriptBuilder,
    ) -> Result<(), CompilerError> {
        let depth = self
            .depth(name)
            .expect("binding should exist before stack rebinding");

        builder.drop_from_depth(depth + 1)?;

        self.move_binding_to_top(name);

        Ok(())
    }

    /// Moves an existing binding to the runtime stack top and updates the
    /// binding model to match. This is useful for in-place updates where the
    /// old bound value is about to be consumed to compute the new one.
    #[allow(dead_code)]
    pub(crate) fn emit_move_binding_to_top(
        &mut self,
        name: &str,
        builder: &mut ScriptBuilder,
    ) -> Result<(), CompilerError> {
        let depth = self
            .depth(name)
            .expect("binding should exist before moving to top");
        builder.roll_from_depth(depth)?;
        self.move_binding_to_top(name);
        Ok(())
    }

    /// Emits a copy of the named binding onto the runtime stack top.
    ///
    /// `stack_depth` accounts for transient values already pushed above the
    /// logical binding layout during expression compilation.
    pub(crate) fn emit_copy_binding_to_top(
        &self,
        name: &str,
        stack_depth: &mut i64,
        builder: &mut ScriptBuilder,
    ) -> Result<bool, CompilerError> {
        let Some(index) = self.depth(name) else {
            return Ok(false);
        };

        builder.pick_from_depth(index + *stack_depth)?;
        *stack_depth += 1;
        Ok(true)
    }

    /// Emits code to transform the current runtime stack layout into
    /// `target_bindings`.
    ///
    /// This first tries the bounded local-op fast path, then falls back to the
    /// suffix-rebuild strategy using altstack.
    pub(crate) fn emit_stack_reordering(
        &self,
        target_bindings: &Self,
        builder: &mut ScriptBuilder,
    ) -> Result<(), CompilerError> {
        if self == target_bindings {
            return Ok(());
        }

        let permutation = Permutation::from_orders(self, target_bindings);

        if let Some(opcodes) = permutation.local_stack_reordering_opcodes() {
            builder.add_ops(&opcodes)?;
            return Ok(());
        }

        let keep_start = permutation.longest_keepable_suffix_start();
        let move_prefix = &target_bindings.stack[..keep_start];
        let mut remaining_stack = self.stack.clone();

        for name in move_prefix {
            let index = remaining_stack
                .get_index_of(name)
                .expect("binding existence was asserted above");
            let depth = index as i64;

            builder.roll_from_depth(depth)?;
            builder.add_op(OpToAltStack)?;

            remaining_stack.shift_remove_index(index);
        }

        debug_assert!(
            remaining_stack
                .iter()
                .eq(target_bindings.stack[move_prefix.len()..].iter())
        );

        for _ in 0..move_prefix.len() {
            builder.add_op(OpFromAltStack)?;
        }
        Ok(())
    }
}

/// A permutation over stack positions, represented in target-indexed form.
///
/// Read as:
/// `target[i] = current[indices[i]]`
///
/// So `indices[i]` tells us which current slot should fill target slot `i`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Permutation {
    indices: Vec<usize>,
}

impl Permutation {
    fn identity(len: usize) -> Self {
        Self {
            indices: (0..len).collect(),
        }
    }

    /// Builds the permutation that transforms `current_order` into
    /// `target_order`.
    ///
    /// Example:
    /// - current: [a, b, c, d]
    /// - target:  [c, d, a, b]
    /// - indices: [2, 3, 0, 1]
    fn from_orders(current_order: &StackBindings, target_order: &StackBindings) -> Self {
        assert!(
            current_order.set_eq(target_order),
            "stack reconciliation requires both layouts to contain the same bindings"
        );
        Self {
            indices: target_order
                .stack
                .iter()
                .map(|name| current_order.stack.get_index_of(name).expect("set equal"))
                .collect(),
        }
    }

    fn len(&self) -> usize {
        self.indices.len()
    }

    /// Returns the start index of the longest keepable target suffix.
    ///
    /// Once the target layout is expressed as positions in the current layout,
    /// a keepable suffix is exactly a suffix whose positions stay strictly
    /// increasing left-to-right.
    ///
    /// Example:
    /// - `current = [a, b, c, d, e]`
    /// - `target  = [c, a, b, d, e]`
    /// - permutation indices are `[2, 0, 1, 3, 4]`
    /// - the longest increasing suffix is `[0, 1, 3, 4]`
    /// - so the function returns `1`, meaning only `[c]` must move
    fn longest_keepable_suffix_start(&self) -> usize {
        let mut j = self.indices.len();
        while j > 1 && self.indices[j - 2] < self.indices[j - 1] {
            j -= 1;
        }
        j.saturating_sub(1)
    }

    /// Searches the bounded local opcode space and returns the first 1- or 2-op
    /// sequence that exactly realizes this permutation.
    fn local_stack_reordering_opcodes(&self) -> Option<Vec<u8>> {
        let local_ops = [OpSwap, OpRot, Op2Swap, Op2Rot];
        let identity = Self::identity(self.len());

        for opcode in local_ops {
            if let Some(next) = identity.apply_local_opcode(opcode)
                && next == *self
            {
                return Some(vec![opcode]);
            }
        }

        for first in local_ops {
            let Some(mid) = identity.apply_local_opcode(first) else {
                continue;
            };
            for second in local_ops {
                if let Some(next) = mid.apply_local_opcode(second)
                    && next == *self
                {
                    return Some(vec![first, second]);
                }
            }
        }

        None
    }

    /// Applies one local stack opcode to this target-as-current-index
    /// permutation.
    ///
    /// This is the symbolic counterpart of the small bounded search used by
    /// `local_stack_reordering_opcodes`: it predicts what `SWAP`, `ROT`,
    /// `2SWAP`, or `2ROT` would do to the top portion of the current layout.
    ///
    /// Returns `None` when:
    /// - the opcode is not part of that local search space, or
    /// - the current stack is too short for the opcode to apply.
    #[allow(non_upper_case_globals)]
    fn apply_local_opcode(&self, opcode: u8) -> Option<Self> {
        let mut next = self.indices.clone();
        match opcode {
            OpSwap if next.len() >= 2 => {
                next.swap(0, 1);
            }
            OpRot if next.len() >= 3 => {
                next[..3].rotate_right(1);
            }
            Op2Swap if next.len() >= 4 => {
                next[..4].rotate_left(2);
            }
            Op2Rot if next.len() >= 6 => {
                next[..6].rotate_right(2);
            }
            _ => return None,
        }
        Some(Self { indices: next })
    }
}
