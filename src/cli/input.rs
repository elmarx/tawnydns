//! Reading inputs of the command line from files or stdin.

use std::io::{self, Read};
use std::path::Path;

/// Reads the file at `path`, `-` is stdin.
pub fn read_to_string(path: &Path) -> io::Result<String> {
    if path == "-" {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        Ok(input)
    } else {
        std::fs::read_to_string(path)
    }
}
