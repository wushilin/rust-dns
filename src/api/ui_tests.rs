//! K1/K2: the console (src/ui/index.html) against the API it calls.
//!
//! The console disables every control the signed-in caller may not use
//! (default-deny, see the "access" section of index.html). These tests make
//! the declarations it relies on mandatory:
//! - every button in the console's templates declares itself: a permission
//!   (`data-perm`, a real [`ZonePerm`] / [`GlobalPerm`], with `data-zone`
//!   for zone permissions), `data-ro-ok` (safe on a read-only standby), or a
//!   close / copy control;
//! - every non-GET API call site is a real route and sits behind a declared
//!   control (or is a sign-in / sign-out step), and the standby flag of that
//!   control agrees with [`STANDBY_WRITABLE`] both ways;
//! - `api()` carries the client-side standby guard.

use super::{openapi_doc, path_matches, STANDBY_WRITABLE};
use crate::model::{GlobalPerm, ZonePerm};

const HTML: &str = crate::ui::INDEX_HTML;

fn script() -> &'static str {
    let start = HTML.find("<script>").expect("console script");
    &HTML[start..]
}

/// The tag text of a `<button` starting at `i`: up to the first `>` that is
/// not inside a `${...}` expression.
fn tag_at(s: &str, i: usize) -> &str {
    let b = s.as_bytes();
    let (mut depth, mut k) = (0usize, i);
    while k < b.len() {
        match b[k] {
            b'$' if b.get(k + 1) == Some(&b'{') => {
                depth += 1;
                k += 1;
            }
            b'{' if depth > 0 => depth += 1,
            b'}' if depth > 0 => depth -= 1,
            b'>' if depth == 0 => return &s[i..=k],
            _ => {}
        }
        k += 1;
    }
    &s[i..]
}

fn buttons() -> Vec<(usize, &'static str)> {
    let s = script();
    s.match_indices("<button")
        .map(|(i, _)| (line_of(s, i), tag_at(s, i)))
        .collect()
}

fn line_of(s: &str, i: usize) -> usize {
    s[..i].matches('\n').count()
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("{name}=\"");
    let i = tag.find(&key)? + key.len();
    let j = tag[i..].find('"')? + i;
    Some(&tag[i..j])
}

fn declared(tag: &str) -> bool {
    tag.contains("data-perm=\"")
        || tag.contains("data-ro-ok")
        || tag.contains("data-close")
        || tag.contains("data-dclose")
        || tag.contains("data-copy=")
        || tag.contains("${ctlAttrs(")
}

fn perm_names<T: serde::Serialize>(all: &[T]) -> Vec<String> {
    all.iter()
        .map(|p| {
            serde_json::to_value(p)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect()
}

#[test]
fn every_console_button_declares_its_access() {
    let zone = perm_names(&ZonePerm::ALL);
    let global = perm_names(&GlobalPerm::ALL);
    let all = buttons();
    assert!(all.len() > 60, "found {} buttons", all.len());
    for (line, tag) in all {
        assert!(
            declared(tag),
            "script line {line}: a console button must declare data-perm, data-ro-ok or be a close/copy control: {tag}"
        );
        if let Some(p) = attr(tag, "data-perm") {
            if zone.iter().any(|z| z == p) {
                assert!(
                    attr(tag, "data-zone").is_some(),
                    "script line {line}: zone permission {p} needs data-zone: {tag}"
                );
            } else {
                assert!(
                    global.iter().any(|g| g == p),
                    "script line {line}: unknown permission {p}: {tag}"
                );
            }
        }
    }
}

/// A call site: method, normalized path (`{x}` for every expression).
struct Call {
    line: usize,
    method: &'static str,
    path: String,
}

/// The first argument of a call starting at `s[i..]` (just after `(`),
/// normalized: literal text kept, every expression replaced by `{x}`.
fn path_arg(s: &str, i: usize) -> String {
    let b: Vec<char> = s[i..].chars().collect();
    let (mut out, mut k) = (String::new(), 0usize);
    while k < b.len() {
        match b[k] {
            ',' | ')' => break,
            ' ' | '+' => k += 1,
            '\'' => {
                k += 1;
                while k < b.len() && b[k] != '\'' {
                    out.push(b[k]);
                    k += 1;
                }
                k += 1;
            }
            '`' => {
                k += 1;
                while k < b.len() && b[k] != '`' {
                    if b[k] == '$' && b.get(k + 1) == Some(&'{') {
                        let mut depth = 0;
                        while k < b.len() {
                            if b[k] == '{' {
                                depth += 1;
                            } else if b[k] == '}' {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                            k += 1;
                        }
                        out.push_str("{x}");
                    } else {
                        out.push(b[k]);
                    }
                    k += 1;
                }
                k += 1;
            }
            _ => {
                // An expression: up to the next top-level `+`, `,` or `)`.
                let mut depth = 0;
                while k < b.len() {
                    match b[k] {
                        '(' | '[' | '{' => depth += 1,
                        ')' | ']' | '}' if depth > 0 => depth -= 1,
                        ')' | ',' | '+' if depth == 0 => break,
                        _ => {}
                    }
                    k += 1;
                }
                out.push_str("{x}");
            }
        }
    }
    out.split('?').next().unwrap().to_string()
}

fn write_calls() -> Vec<Call> {
    let s = script();
    let mut out = Vec::new();
    let helpers = [("POST(", "POST"), ("PUT(", "PUT"), ("DEL(", "DELETE")];
    for (needle, method) in helpers {
        for (i, _) in s.match_indices(needle) {
            let prev = s[..i].chars().last().unwrap_or(' ');
            if prev.is_alphanumeric() || prev == '_' || prev == '.' {
                continue;
            }
            let at = i + needle.len();
            if s[at..].starts_with("p,") || s[at..].starts_with("p)") {
                continue; // the helper definitions themselves
            }
            out.push(Call {
                line: line_of(s, i),
                method,
                path: path_arg(s, at),
            });
        }
    }
    for (i, _) in s.match_indices("api('") {
        let rest = &s[i + 5..];
        let m = &rest[..rest.find('\'').unwrap()];
        let method = match m {
            "GET" => continue,
            "POST" => "POST",
            "PUT" => "PUT",
            "DELETE" => "DELETE",
            "PATCH" => "PATCH",
            other => panic!("api('{other}' ...)"),
        };
        if rest[m.len() + 1..].starts_with(", p") {
            continue; // GET/POST/PUT/DEL helper definitions
        }
        let at = i + 5 + m.len() + 1 + rest[m.len() + 1..].find(',').unwrap() + 1;
        out.push(Call {
            line: line_of(s, i),
            method,
            path: path_arg(s, at).trim().to_string(),
        });
    }
    out
}

fn word(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-'
}

/// The identifier that starts at `s[i..]`.
fn ident_at(s: &str, i: usize) -> &str {
    let end = s[i..].find(|c: char| !word(c)).map_or(s.len(), |j| i + j);
    &s[i..end]
}

/// Selectors (`#id` or `[data-x]`) whose click / change handler is bound on
/// this line: `$('#id').onclick =`, `m.querySelector('#id').onclick =`,
/// `$$('[data-x]').forEach(b => b.onclick = ...)`.
fn bound_selectors(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, _) in line.match_indices("('#") {
        let id = ident_at(line, i + 3);
        let after = &line[i + 3 + id.len()..];
        if after.starts_with("').onclick") || after.starts_with("').onchange") {
            out.push(format!("#{id}"));
        }
    }
    for (i, _) in line.match_indices("('[data-") {
        let a = ident_at(line, i + 8);
        let rest = &line[i + 8 + a.len()..];
        let binds =
            rest.starts_with("]').forEach(") && rest.get(..40).unwrap_or(rest).contains(".onclick");
        if binds && (line[..i].ends_with("$$") || line[..i].ends_with("querySelectorAll")) {
            out.push(format!("[data-{a}]"));
        }
    }
    out
}

/// `ok` in `ok.onclick = ` (a variable, not a selector call).
fn bound_var(line: &str) -> Option<&str> {
    let i = line.find(".onclick = ")?;
    let start = line[..i].rfind(|c: char| !word(c)).map_or(0, |j| j + 1);
    let v = &line[start..i];
    (!v.is_empty()).then_some(v)
}

/// `#id` when the line defines `var = m.querySelector('#id')` / `var = $('#id')`.
fn var_def(line: &str, var: &str) -> Option<String> {
    for pat in [
        format!("{var} = m.querySelector('#"),
        format!("{var} = $('#"),
    ] {
        for (i, _) in line.match_indices(&pat) {
            if line[..i].chars().last().is_some_and(word) {
                continue;
            }
            return Some(format!("#{}", ident_at(line, i + pat.len())));
        }
    }
    None
}

/// `name` when the line defines `function name(` or `const name = async`.
fn fn_def(line: &str) -> Option<&str> {
    if let Some(i) = line.find("function ") {
        let n = ident_at(line, i + 9);
        if !n.is_empty() && line[i + 9 + n.len()..].starts_with('(') {
            return Some(n);
        }
    }
    let i = line.find("const ")?;
    let n = ident_at(line, i + 6);
    line[i + 6 + n.len()..].starts_with(" = async").then_some(n)
}

/// Whether the line binds a click handler that is, or calls, `name`.
fn binds_fn(line: &str, name: &str) -> bool {
    line.match_indices(".onclick = ").any(|(i, m)| {
        let rest = &line[i + m.len()..];
        (rest.starts_with(name) && !rest[name.len()..].starts_with(word))
            || rest.contains(&format!("=> {name}("))
    })
}

/// The controls whose handler contains script line `l`.
fn trigger(lines: &[&str], l: usize, seen: &mut Vec<String>) -> Vec<(usize, String)> {
    for k in (l.saturating_sub(40)..=l).rev() {
        let line = lines[k];
        let sels = bound_selectors(line);
        if !sels.is_empty() {
            return sels.into_iter().map(|x| (k, x)).collect();
        }
        if let Some(var) = bound_var(line) {
            for j in (k.saturating_sub(80)..=k).rev() {
                if let Some(id) = var_def(lines[j], var) {
                    return vec![(j, id)];
                }
            }
        }
        if let Some(name) = fn_def(line) {
            if seen.iter().any(|x| x == name) {
                return vec![];
            }
            seen.push(name.to_string());
            return lines
                .iter()
                .enumerate()
                .filter(|(_, x)| binds_fn(x, name))
                .flat_map(|(j, x)| bound_selectors(x).into_iter().map(move |s| (j, s)))
                .collect();
        }
    }
    vec![]
}

/// Button tags matching a selector; for an id, the one defined last before
/// script line `l` (ids such as `m-ok` are reused by every dialog).
fn controls_for(sel: &str, l: usize) -> Vec<(usize, &'static str)> {
    let all = buttons();
    if let Some(id) = sel.strip_prefix('#') {
        let key = format!("id=\"{id}\"");
        let hits: Vec<_> = all.into_iter().filter(|(_, t)| t.contains(&key)).collect();
        let before = hits.iter().rev().find(|(x, _)| *x <= l).copied();
        before.or(hits.first().copied()).into_iter().collect()
    } else {
        let a = &sel[1..sel.len() - 1];
        all.into_iter()
            .filter(|(_, t)| {
                t.contains(&format!("{a}="))
                    || t.contains(&format!(" {a} "))
                    || t.contains(&format!(" {a}>"))
            })
            .collect()
    }
}

#[test]
fn every_write_call_is_a_route_behind_a_declared_control() {
    let doc = serde_json::to_value(openapi_doc()).unwrap();
    let paths = doc["paths"].as_object().unwrap();
    let lines: Vec<&str> = script().lines().collect();
    let calls = write_calls();
    assert!(calls.len() >= 50, "found {} write call sites", calls.len());
    for c in &calls {
        let where_ = format!("script line {} ({} {})", c.line, c.method, c.path);
        let route = paths
            .iter()
            .find(|(t, item)| {
                item.get(c.method.to_lowercase()).is_some() && path_matches(t, &c.path)
            })
            .map(|(t, _)| t.clone())
            .unwrap_or_else(|| panic!("{where_}: no such API route"));
        if route.starts_with("/auth/") {
            continue; // sign-in and sign-out: the login page, before any rights
        }
        let standby_ok = STANDBY_WRITABLE
            .iter()
            .any(|(m, t)| *m == c.method && *t == route);
        let ctls: Vec<_> = trigger(&lines, c.line, &mut vec![])
            .into_iter()
            .flat_map(|(l, sel)| controls_for(&sel, l))
            .collect();
        assert!(
            !ctls.is_empty(),
            "{where_}: cannot tell which control triggers this call; bind the handler directly to a declared control ($('#id').onclick = ...)"
        );
        for (l, tag) in ctls {
            assert!(
                tag.contains("data-perm=\"") || tag.contains("data-ro-ok"),
                "{where_}: its control (script line {l}) must declare data-perm or data-ro-ok: {tag}"
            );
            let ro_ok = tag.contains("data-ro-ok");
            assert_eq!(
                ro_ok, standby_ok,
                "{where_}: control (script line {l}) has data-ro-ok={ro_ok} but the server {} {} {route} on a standby: {tag}",
                if standby_ok { "accepts" } else { "refuses" },
                c.method
            );
        }
    }
}

#[test]
fn api_wrapper_guards_writes_on_a_standby() {
    let s = script();
    let api = &s[s.find("async function api(").expect("api()")..];
    let api = &api[..api.find("\n}\n").unwrap()];
    let guard = api
        .find("requestAllowed(method, path, ro)")
        .expect("guard in api()");
    let fetch = api.find("fetch(").expect("fetch in api()");
    assert!(guard < fetch, "the guard runs before the request is sent");
    assert!(
        s.contains("standby_writable"),
        "the guard reads the published allowlist"
    );
    assert!(
        !s.contains("WRITE_SEL"),
        "no hand-kept list of write controls"
    );
}

/// A `${...}` inside a '...' string is printed literally (e.g. a
/// `data-zone="${esc(z.name)}"` that names no real zone): button markup with
/// expressions must be a template literal.
#[test]
fn button_markup_with_expressions_is_a_template_literal() {
    let s = script();
    for (i, _) in s.match_indices("'<") {
        let lit = &s[i + 1..];
        let lit = &lit[..lit.find('\'').unwrap_or(lit.len())];
        assert!(
            !lit.contains("${"),
            "script line {}: '${{...}}' in a quoted string is not interpolated: {lit}",
            line_of(s, i)
        );
    }
}

#[test]
fn path_args_are_normalized() {
    let n = |x: &str| path_arg(x, 0);
    assert_eq!(
        n("'/zones/' + encodeURIComponent(z.name), b)"),
        "/zones/{x}"
    );
    assert_eq!(
        n("`/zones/${encodeURIComponent(z.name)}/records/${r.id}`)"),
        "/zones/{x}/records/{x}"
    );
    assert_eq!(n("`/import?mode=${plan.mode}`, plan.body)"), "/import");
    assert_eq!(
        n("'/zones/' + encodeURIComponent($('#ho-zone').value) + '/import/hosts', x)"),
        "/zones/{x}/import/hosts"
    );
}
