use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub use copy::CopyPatch;
pub use pattern::PatternPatch;
pub use regex::RegexPatch;

pub mod copy;
pub mod pattern;
pub mod regex;
pub mod vars;

pub type Priority = i32;

#[derive(Serialize, Deserialize, Debug)]
pub struct Manifest {
    pub version: String,
    // Does nothing, kept for legacy compat
    #[serde(default)]
    pub dump_lua: bool,
    #[serde(default)]
    pub priority: Priority,
}

// Represents a single .toml file after deserialization.
#[derive(Serialize, Deserialize, Debug)]
pub struct PatchFile {
    pub manifest: Manifest,
    pub patches: Vec<Patch>,

    // A table of variable name = value bindings. These are interpolated
    // into injected source code as the *last* step in the patching process.
    #[serde(default)]
    pub vars: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum Patch {
    // A patch which applies some change to a series of line(s) after a line with a match
    // to the provided pattern has been found.
    Pattern(PatternPatch),
    Regex(RegexPatch),
    Copy(CopyPatch),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum InsertPosition {
    At,
    Before,
    After,
}
