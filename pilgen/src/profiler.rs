use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Write;
use std::path::Path;

use rustc_demangle::demangle;

pub struct AsmProfiler {
    pc_name: String,
    instructions: HashMap<String, InstrKind>,
    file_nrs: HashMap<usize, (String, String)>,
    // TODO use a struct
    source_locations: BTreeMap<usize, (usize, usize, usize)>,
    function_starts: BTreeMap<usize, String>,
    output: Option<File>,
    instruction_counts: BTreeMap<Location, usize>,
    previous_pc: usize,
    call_stack: Vec<CallStackItem>,
    calls: BTreeMap<(Location, Location), (usize, usize)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InstrKind {
    Regular,
    /// Call or tail-call.
    Call,
    Return,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CallStackItem {
    source: Location,
    dest: Option<Location>,
    instructions: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Location {
    file_nr: usize,
    function: String, // TODO use index
    line: usize,
}

impl AsmProfiler {
    pub fn pc_name(&self) -> &str {
        self.pc_name.as_str()
    }
    pub fn instructions(&self) -> &HashMap<String, InstrKind> {
        &self.instructions
    }

    pub fn set_output_dir(&mut self, dir: &Path) {
        assert!(self.output.is_none());
        self.output = Some(File::create(dir.join("callgrind.out")).unwrap());
        write!(self.output.as_mut().unwrap(), "events: Instructions\n\n").unwrap();
    }

    pub fn called_pc(&mut self, pc: usize, instr_kind: InstrKind) {
        let Some(location) = self.location(pc) else { return; };

        // Did we return from a tail call?
        while !self.last_call_stack_is_here(&location) {
            self.pop_call_stack();
        }

        // First instruction after a call.
        if let Some(CallStackItem { dest: d @ None, .. }) = self.call_stack.last_mut() {
            *d = Some(location.clone());
        }

        *self.instruction_counts.entry(location.clone()).or_default() += 1;
        if let Some(CallStackItem { instructions, .. }) = self.call_stack.last_mut() {
            *instructions += 1;
        }

        match instr_kind {
            InstrKind::Call => self.call_stack.push(CallStackItem {
                source: location,
                dest: None,
                instructions: 0,
            }),
            InstrKind::Return => self.pop_call_stack(),
            InstrKind::Regular => {}
        }

        self.previous_pc = pc;
    }

    /// Returns true if the last call stack item is complete but not pointing to
    /// the same function as `location`.
    fn last_call_stack_is_here(&self, location: &Location) -> bool {
        match self.call_stack.last() {
            Some(CallStackItem {
                dest: Some(dest), ..
            }) => (dest.file_nr, &dest.function) == (location.file_nr, &location.function),
            _ => true,
        }
    }

    /// Removes the last item from the call stack and stores it in the call statistic.
    /// Also adds the instructions to the counter one level up in the call stack.
    fn pop_call_stack(&mut self) {
        let Some(item) = self.call_stack.pop() else { return; };
        assert!(item.dest.is_some());
        let (count, instr) = self
            .calls
            .entry((item.source, item.dest.unwrap()))
            .or_default();
        *count += 1;
        *instr += item.instructions;
        if let Some(prev_item) = self.call_stack.last_mut() {
            prev_item.instructions += item.instructions;
        }
    }

    pub fn execution_finished(&mut self) {
        let out = self.output.as_mut().unwrap();
        let mut data: BTreeMap<
            (usize, String),
            (Vec<(usize, usize)>, Vec<(Location, Location, usize, usize)>),
        > = BTreeMap::default();
        for (loc, cnt) in &self.instruction_counts {
            data.entry((loc.file_nr, loc.function.clone()))
                .or_default()
                .0
                .push((loc.line, *cnt));
        }
        for ((source, dest), (count, instructions)) in &self.calls {
            data.entry((source.file_nr, source.function.clone()))
                .or_default()
                .1
                .push((source.clone(), dest.clone(), *count, *instructions));
        }
        for ((file_nr, function), (lines, calls)) in data {
            writeln!(
                out,
                "fl={}/{}",
                self.file_nrs[&file_nr].0, self.file_nrs[&file_nr].1
            )
            .unwrap();
            writeln!(out, "fn={:#}", demangle(&function)).unwrap();
            for (line, count) in lines {
                writeln!(out, "{line} {count}").unwrap();
            }
            for (source, dest, count, instructions) in calls {
                if dest.file_nr != file_nr {
                    writeln!(
                        out,
                        "cfi={}/{}",
                        self.file_nrs[&dest.file_nr].0, self.file_nrs[&dest.file_nr].1
                    )
                    .unwrap();
                }
                writeln!(out, "cfn={:#}", demangle(&dest.function)).unwrap();
                writeln!(out, "calls={count} {}", dest.line).unwrap();
                // TODO this division is a bit weird, but OK...
                writeln!(out, "{} {}", source.line, instructions / count).unwrap();
            }
            writeln!(out).unwrap();
        }

        // for
        // # callgrind format
        // events: Instructions

        // fl=file1.c
        // fn=main
        // 16 20
        // cfn=func1
        // calls=1 50
        // 16 400
        // cfi=file2.c
        // cfn=func2
        // calls=3 20
        // 16 400
    }

    fn source_location(&self, pc: usize) -> Option<&(usize, usize, usize)> {
        self.source_locations
            .range(..=pc)
            .last()
            .map(|(_, loc)| loc)
    }

    fn function(&self, pc: usize) -> Option<&String> {
        self.function_starts.range(..=pc).last().map(|(_, fun)| fun)
    }

    fn location(&self, pc: usize) -> Option<Location> {
        let (file, line, _column) = self.source_location(pc)?;
        let function = self.function(pc)?;
        Some(Location {
            file_nr: *file,
            function: function.to_string(),
            line: *line,
        })
    }
}

#[derive(Default)]
pub struct ProfilerBuilder {
    file_nrs: HashMap<usize, (String, String)>,
    source_locations: BTreeMap<usize, (usize, usize, usize)>,
    function_starts: BTreeMap<usize, String>,
    pc_name: String,
    instructions: HashMap<String, InstrKind>,
}

impl ProfilerBuilder {
    pub fn set_pc_name(&mut self, name: &str) {
        self.pc_name = name.to_string();
    }
    pub fn add_instruction(&mut self, name: &str, kind: InstrKind) {
        self.instructions.insert(name.to_string(), kind);
    }
    pub fn add_file(&mut self, nr: usize, dir: String, file: String) {
        assert!(self.file_nrs.insert(nr, (dir, file)).is_none());
    }
    pub fn set_label(&mut self, pc: usize, label: &str) {
        // TODO this is a hack
        if !label.contains("___dot_L") {
            self.function_starts.insert(pc, label.to_string());
        }
    }
    pub fn set_source_location(&mut self, pc: usize, file: usize, line: usize, col: usize) {
        self.source_locations.insert(pc, (file, line, col));
    }
    pub fn to_profiler(self) -> AsmProfiler {
        AsmProfiler {
            pc_name: self.pc_name,
            instructions: self.instructions,
            file_nrs: self.file_nrs,
            source_locations: self.source_locations,
            function_starts: self.function_starts,
            output: None,
            instruction_counts: Default::default(),
            previous_pc: 0,
            call_stack: vec![],
            calls: Default::default(),
        }
    }
}
