use crate::error::AppError;
use std::path::Path;
use std::time::SystemTime;

/// Return file modification time
pub fn file_mtime(filepath: &Path) -> Result<SystemTime, AppError> {
    match filepath.metadata() {
        Ok(meta) => match meta.modified() {
            Ok(mtime) => Ok(mtime),
            Err(err) => Err(AppError::GenWithMsgAndErr(
                format!("Error acquiring file metadata mtime: file={:?}", filepath),
                Box::new(err),
            )),
        },

        Err(err) => Err(AppError::GenWithMsgAndErr(
            format!("Error acquiring CRL file metadata: file={:?}", filepath),
            Box::new(err),
        )),
    }
}

/// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const VALID_FILE: [&str; 3] = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "client0.local.crt.pem",
    ];
    const MISSING_FILE: [&str; 3] = [env!("CARGO_MANIFEST_DIR"), "testdata", "NON-EXISTENT.txt"];

    #[test]
    fn file_mtime_when_invalid_filepath() {
        let file_pathbuf: PathBuf = MISSING_FILE.iter().collect();

        let result = file_mtime(file_pathbuf.as_path());

        if result.is_ok() {
            panic!(
                "Unexpected result: path={:?}, val={:?}",
                &file_pathbuf, &result
            );
        }
    }

    #[test]
    fn file_mtime_when_valid_filepath() {
        let file_pathbuf: PathBuf = VALID_FILE.iter().collect();

        let result = file_mtime(file_pathbuf.as_path());

        if result.is_err() {
            panic!(
                "Unexpected result: path={:?}, val={:?}",
                &file_pathbuf, &result
            );
        }
    }
}
