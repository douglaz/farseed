//! Length-framed harness reads. Read stdout is data, never a framing delimiter.
pub(crate) fn command(checks: &[String], start: usize) -> String {
    let mut script = String::from(
        "umask 077\ntwr_dir=$(mktemp -d) || exit 1\ntrap 'rm -rf -- \"$twr_dir\"' 0\ntrap 'exit 1' HUP INT TERM\n",
    );
    for (index, command) in checks.iter().enumerate().skip(start) {
        let quoted = command.replace('\'', "'\\''");
        script.push_str(&format!(
            "sh -c '{quoted}' > \"$twr_dir/stdout\"\ntwr_exit=$?\ntwr_size=$(LC_ALL=C wc -c < \"$twr_dir/stdout\") || exit 1\nprintf 'TWR {index} %s %d\\n' \"$twr_exit\" \"$twr_size\" || exit 1\ncat \"$twr_dir/stdout\" || exit 1\n",
        ));
    }
    script.push_str("exit 0\n");
    script
}

fn decimal(text: &str) -> Option<usize> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Keep only the complete, ordered prefix. Never search stdout for a later header.
/// Extra bytes after the final planned frame invalidate the batch as a whole.
pub(crate) fn parse(mut bytes: &[u8], start: usize, end: usize) -> Vec<(u32, &[u8])> {
    let mut reads = Vec::new();
    for index in start..end {
        let Some(newline) = bytes.iter().take(96).position(|byte| *byte == b'\n') else {
            return reads;
        };
        let Ok(header) = std::str::from_utf8(&bytes[..newline]) else {
            return reads;
        };
        let fields = header.split(' ').collect::<Vec<_>>();
        if fields.len() != 4 || fields[0] != "TWR" || decimal(fields[1]) != Some(index) {
            return reads;
        }
        let Some(exit) = decimal(fields[2]).filter(|exit| *exit <= 255) else {
            return reads;
        };
        let Some(length) = decimal(fields[3]) else {
            return reads;
        };
        bytes = &bytes[newline + 1..];
        let Some(stdout) = bytes.get(..length) else {
            return reads;
        };
        reads.push((exit as u32, stdout));
        bytes = &bytes[length..];
    }
    if !bytes.is_empty() {
        reads.clear();
    }
    reads
}

pub(crate) fn frame(output: &mut Vec<u8>, index: usize, exit: u32, stdout: &[u8]) {
    output.extend_from_slice(format!("TWR {index} {exit} {}\n", stdout.len()).as_bytes());
    output.extend_from_slice(stdout);
}
