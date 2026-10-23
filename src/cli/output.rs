//! Writing results of the command line to stdout or files.

use std::ffi::OsString;
use std::fs::{File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Where to write a result, `-` is stdout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    Stdout,
    File(PathBuf),
}

impl From<OsString> for Output {
    fn from(value: OsString) -> Self {
        if value == "-" {
            Self::Stdout
        } else {
            Self::File(value.into())
        }
    }
}

impl Output {
    /// Writes `contents`, a file is created with `mode` and only replaced if `force` is set.
    pub fn write(&self, contents: &str, mode: u32, force: bool) -> io::Result<()> {
        match self {
            Self::Stdout => io::stdout().write_all(contents.as_bytes()),
            Self::File(path) => create(path, mode, force)?.write_all(contents.as_bytes()),
        }
    }
}

/// Creates the file at `path` with `mode`, replaces an existing one only if `force` is set.
pub fn create(path: &Path, mode: u32, force: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).mode(mode);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let file = options.open(path).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => io::Error::new(
            e.kind(),
            format!("{} exists, use --force to replace it", path.display()),
        ),
        _ => e,
    })?;
    // the mode only applies to new files
    file.set_permissions(Permissions::from_mode(mode))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parses_dash_as_stdout() {
        for (sample, expected) in [
            ("-", Output::Stdout),
            ("token.jwt", Output::File("token.jwt".into())),
            ("./-", Output::File("./-".into())),
        ] {
            let actual = Output::from(OsString::from(sample));

            assert_eq!(actual, expected, "{sample:?}");
        }
    }

    #[test]
    fn refuses_to_replace_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out");
        let sample = Output::File(path.clone());
        sample.write("first", 0o600, false).unwrap();

        let actual = sample.write("second", 0o600, false);

        assert_eq!(actual.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&path).unwrap(), "first");
    }

    #[test]
    fn replaces_with_force_and_applies_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out");
        fs::write(&path, "a longer first content").unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        let sample = Output::File(path.clone());

        sample.write("second", 0o600, true).unwrap();

        let actual = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(actual, 0o600);
        assert_eq!(fs::read_to_string(&path).unwrap(), "second");
    }
}
