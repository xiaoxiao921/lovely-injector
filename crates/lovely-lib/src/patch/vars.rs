use std::{collections::HashMap, sync::LazyLock};

use regex_lite::{Captures, Regex};
use tracing::error;

/// Apply valid var interpolations to the provided line.
/// Interpolation targets are of form {{lovely:VAR_NAME}}.
pub fn apply_var_interp(line: &mut String, vars: &HashMap<String, String>) -> bool {
    // Cache the compiled regex.
    let re: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{\{lovely:(\w+)\}\}").unwrap());

    let mut success = true;

    let line_replaced = re.replace_all(line, |captures: &Captures| {
        let (_, [var]) = captures.extract();
        match vars.get(var) {
            Some(val) => val.into(),
            None => {
                error!("Failed to interpolate an unregistered variable '{var}'");
                success = false;
                // fall back to leaving the original placeholder in place
                captures.get(0).unwrap().as_str().to_string()
            }
        }
    });

    *line = line_replaced.to_string();
    success
}
