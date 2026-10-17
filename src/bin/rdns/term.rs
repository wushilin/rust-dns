//! Prompts, confirmations, tables and small parsers.

use anyhow::{anyhow, bail, Result};
use std::io::{BufRead, IsTerminal, Write};

pub fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// A line from the terminal (the prompt goes to stderr).
pub fn ask(prompt: &str) -> Result<String> {
    if !interactive() {
        bail!(
            "{} needed, and stdin is not a terminal",
            prompt.trim_end_matches([':', ' '])
        );
    }
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

/// A secret from the terminal, not echoed.
pub fn ask_secret(prompt: &str) -> Result<String> {
    if !interactive() {
        bail!(
            "{} needed, and stdin is not a terminal",
            prompt.trim_end_matches([':', ' '])
        );
    }
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let _echo = NoEcho::new();
    let mut s = String::new();
    let r = std::io::stdin().lock().read_line(&mut s);
    eprintln!();
    r?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

/// A new password, typed twice.
pub fn ask_new_password(prompt: &str) -> Result<String> {
    let a = ask_secret(prompt)?;
    let b = ask_secret("Repeat it: ")?;
    if a != b {
        bail!("the passwords do not match");
    }
    Ok(a)
}

/// The first line of stdin (for `--password-stdin`).
pub fn stdin_line() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    let s = s.trim_end_matches(['\r', '\n']).to_string();
    if s.is_empty() {
        bail!("no password on stdin");
    }
    Ok(s)
}

/// Ask before something that cannot be undone; `yes` skips the question.
pub fn confirm(what: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !interactive() {
        bail!("{what}: refusing without --yes (not a terminal)");
    }
    let a = ask(&format!("{what}? [y/N] "))?;
    if matches!(a.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(anyhow!("cancelled"))
    }
}

/// Terminal echo off until dropped (Unix; elsewhere a no-op).
struct NoEcho {
    #[cfg(unix)]
    saved: Option<libc::termios>,
}

impl NoEcho {
    fn new() -> Self {
        #[cfg(unix)]
        // SAFETY: tcgetattr/tcsetattr on fd 0 with a properly sized termios.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut t) == 0 {
                let saved = t;
                t.c_lflag &= !libc::ECHO;
                t.c_lflag |= libc::ECHONL;
                if libc::tcsetattr(0, libc::TCSANOW, &t) == 0 {
                    return NoEcho { saved: Some(saved) };
                }
            }
            NoEcho { saved: None }
        }
        #[cfg(not(unix))]
        NoEcho {}
    }
}

impl Drop for NoEcho {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(t) = self.saved {
            // SAFETY: restores the attributes read in `new`.
            unsafe {
                libc::tcsetattr(0, libc::TCSANOW, &t);
            }
        }
    }
}

/// Left-aligned columns, two spaces apart; the last column is not padded.
pub fn table(header: &[&str], rows: &[Vec<String>]) {
    let n = header.len();
    let mut w: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate().take(n) {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let mut s = String::new();
        for (i, c) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                s.push_str(c);
            } else {
                s.push_str(c);
                s.push_str(&" ".repeat(w[i] - c.chars().count() + 2));
            }
        }
        println!("{}", s.trim_end());
    };
    line(header.to_vec());
    for r in rows {
        line(r.iter().map(String::as_str).collect());
    }
}

/// `90`, `90s`, `15m`, `12h`, `7d`, `2w` as seconds.
pub fn parse_duration(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = match s.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => {
            let m = match c.to_ascii_lowercase() {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86_400,
                'w' => 7 * 86_400,
                _ => bail!("'{s}': use a number of seconds or a suffix s, m, h, d, w"),
            };
            (&s[..i], m)
        }
        _ => (s, 1),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow!("'{s}' is not a duration (e.g. 90s, 15m, 12h, 7d)"))?;
    n.checked_mul(mult)
        .filter(|v| *v > 0)
        .ok_or_else(|| anyhow!("'{s}' is not a usable duration"))
}

/// An instant: RFC 3339 as given, or a duration from now.
pub fn parse_instant(s: &str) -> Result<String> {
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s.trim()) {
        return Ok(t
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    }
    let secs = parse_duration(s)
        .map_err(|_| anyhow!("'{s}': give an RFC 3339 time or a duration from now (e.g. 30d)"))?;
    let at = chrono::Utc::now() + chrono::Duration::seconds(secs as i64);
    Ok(at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90").unwrap(), 90);
        assert_eq!(parse_duration("15m").unwrap(), 900);
        assert_eq!(parse_duration("12H").unwrap(), 43_200);
        assert_eq!(parse_duration("7d").unwrap(), 604_800);
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("1y").is_err());
        assert!(parse_duration("abc").is_err());
    }
}
