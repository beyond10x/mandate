//! The gate's reader for declared documents.
//!
//! Before this step, `cargo xtask check` opened exactly three paths under `docs/`:
//! `docs/architecture/command-obligations.md`, `docs/sources/SHA256SUMS` and each file it names.
//! Every other document deliverable could be emptied, and the gate stayed green
//! (`story:gate-reads-document-deliverables`). This module is the reader that closes that.
//!
//! It makes three assertions about every declared document and deliberately no more — it does not
//! read prose and is not a linter:
//!
//! 1. the document exists and is not empty;
//! 2. every blocker the document *claims*, in the sense below, is reported by
//!    `aep plan artifact blocked` as `open`;
//! 3. every row set it says it read from the planning store still equals the store's own answer,
//!    and a blocker the document records as excluded from its rows is not also one of them.
//!
//! A **claim** is one of exactly three things, and nothing else in a document is read:
//!
//! * a row of a table whose header carries a `Blocker` column — the row claims *every* blocker its
//!   blocker cell names, and where the header also carries a store column (one ending `(store)`,
//!   or `Blocks`) the row states that blocker's row set;
//! * a bolded field whose label ends `(store).`, under a heading naming a blocker, which states
//!   that blocker's row set — as a sentence, across a line wrap, or as the list that follows it;
//! * a row of either shape under an exclusion heading (`Excluded`, `Exclusion`, `Exclusions` as
//!   the heading's first word after any numbering), which claims the blocker and records that it
//!   is deliberately *not* one of the document's rows.
//!
//! Prose is not a claim and a fenced sample is not a claim. That boundary is the story's own: "Do
//! not widen this into a prose linter." A document that mentions a blocker in a sentence — a
//! register recording that one was cleared, say — states no row set, so there is nothing to
//! compare and nothing to fail.
//!
//! A blocker is named by its full `decision-blocker:` id. A cell of a `Blocker` column may write
//! the bare name instead — `federated-login.md:124` does — but only as its single quoted token:
//! a cell holding several quoted words has not said which of them is a blocker, and inventing one
//! from a quoted word is how `` `none` `` becomes a blocker that no store can report.
//!
//! Nothing this reader declines to read is dropped in silence. A `Blocker` table with no delimiter
//! row, a row whose blocker cell states no blocker, a table that states none at all, and a
//! `(store).` field under a heading that names no blocker are each reported by their own line:
//! a row set that stops being compared is exactly the failure this step exists to prevent.
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
/// One group of `aep plan artifact blocked`: the blocker, its status, and the ids it blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocker {
    pub id: String,
    pub status: String,
    pub blocks: BTreeSet<String>,
}
/// A blocker a document claims, and — where the claim states one — the row set it states.
struct Claim {
    blocker: String,
    blocks: Option<BTreeSet<String>>,
    line: usize,
    excluded: bool,
}
/// Everything one document claims, and every place it states a claim this reader could not read.
/// A defect is a row set that stopped being compared, reported by the line it stopped on.
struct Reading {
    claims: Vec<Claim>,
    defects: Vec<(usize, String)>,
}
/// A `Blocker` table being read: its blocker column, its store column if it has one, the line its
/// header opened on, and how many of its rows have stated a blocker.
struct Table {
    blocker: usize,
    store: Option<usize>,
    line: usize,
    rows: usize,
}
pub fn parse_blocked(json: &[u8]) -> Result<Vec<Blocker>> {
    let report: Value = serde_json::from_slice(json)?;
    let groups = report.as_array().ok_or("blocked report is not a list")?;
    let mut blocked = Vec::new();
    for group in groups {
        let id = group["blocker"]
            .as_str()
            .ok_or("blocked group names no blocker")?;
        let status = group["status"]
            .as_str()
            .ok_or_else(|| format!("{id} reports no status"))?;
        let mut blocks = BTreeSet::new();
        for held in group["blocks"]
            .as_array()
            .ok_or_else(|| format!("{id} holds nothing"))?
        {
            blocks.insert(
                held["id"]
                    .as_str()
                    .ok_or_else(|| format!("{id} holds an unnamed artifact"))?
                    .to_owned(),
            );
        }
        blocked.push(Blocker {
            id: id.to_owned(),
            status: status.to_owned(),
            blocks,
        });
    }
    Ok(blocked)
}
/// The exact command the step reads the store with. The store is always this workspace's own
/// `.engineering/planning`, never a path derived from the documents being read: relocating the
/// documents must not relocate the answer they are compared against.
pub fn blocked_command(workspace: &Path) -> (String, Vec<String>) {
    let mut args: Vec<String> = ["plan", "artifact", "blocked", "--format", "json", "--store"]
        .iter()
        .map(|a| (*a).to_owned())
        .collect();
    args.push(
        workspace
            .join(".engineering/planning")
            .display()
            .to_string(),
    );
    ("aep".to_owned(), args)
}
/// The store's own answer, with the process call injected so a test can pin the command line
/// without a live store.
pub fn blocked_with(
    workspace: &Path,
    run: impl FnOnce(&str, &[String]) -> Result<Vec<u8>>,
) -> Result<Vec<Blocker>> {
    let (program, args) = blocked_command(workspace);
    parse_blocked(&run(&program, &args)?)
}
/// The store's own answer, read locally. `blocked` always exits 0, so a failure here is the tool
/// missing or the store unreadable, not a blocker existing.
pub fn store_blocked(workspace: &Path) -> Result<Vec<Blocker>> {
    blocked_with(workspace, |program, args| {
        let out = Command::new(program)
            .args(args)
            .output()
            .map_err(|e| format!("{program} {}: {e}", args.join(" ")))?;
        if !out.status.success() {
            return Err(format!(
                "{program} {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )
            .into());
        }
        Ok(out.stdout)
    })
}
/// Every document held to the assertions above: each `docs/architecture/*.md` present in the tree,
/// walked rather than listed so a document added there is covered the day it lands, plus the two
/// root documents `AGENTS.md:1` and the README.
pub fn declared(root: &Path) -> Result<Vec<PathBuf>> {
    let architecture = Path::new("docs/architecture");
    let directory = root.join(architecture);
    let mut declared = Vec::new();
    for entry in fs::read_dir(&directory).map_err(|e| format!("{}: {e}", directory.display()))? {
        let path = entry
            .map_err(|e| format!("{}: {e}", directory.display()))?
            .path();
        if path.extension().is_some_and(|e| e == "md") {
            declared.push(architecture.join(path.file_name().ok_or("document name")?));
        }
    }
    if declared.is_empty() {
        return Err(format!("{}: declares no document", directory.display()).into());
    }
    declared.sort();
    declared.push(PathBuf::from("README.md"));
    declared.push(PathBuf::from("AGENTS.md"));
    Ok(declared)
}
fn separator(line: &str) -> bool {
    line.contains('-') && line.chars().all(|c| matches!(c, '|' | '-' | ':' | ' '))
}
/// A table row's cells. GFM writes a literal pipe inside a cell as `\|`, so only an unescaped pipe
/// is a column boundary; an escaped one is content and is unescaped here.
fn cells(line: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut cell = String::new();
    let mut escaped = false;
    for c in line.chars() {
        if escaped {
            if c != '|' {
                cell.push('\\');
            }
            cell.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '|' {
            cells.push(cell.trim().to_owned());
            cell = String::new();
        } else {
            cell.push(c);
        }
    }
    if escaped {
        cell.push('\\');
    }
    cells.push(cell.trim().to_owned());
    if cells.first().is_some_and(String::is_empty) {
        cells.remove(0);
    }
    if cells.last().is_some_and(String::is_empty) {
        cells.pop();
    }
    cells
}
/// A header cell's name, with the emphasis and code markers that change nothing about which column
/// it is stripped off: `**Blocker**` and `Blocker` are the same header.
fn label(cell: &str) -> String {
    cell.trim_matches(|c| matches!(c, '*' | '_' | '`' | ' '))
        .to_ascii_lowercase()
}
/// The `Blocker` column of a table header, and its store column if it has one. A table may name a
/// blocker without stating its row set — the decisions table at `federated-login.md:124` does —
/// and that is still a claim about the blocker's status.
fn columns(header: &[String]) -> Option<(usize, Option<usize>)> {
    let blocker = header.iter().position(|c| label(c) == "blocker")?;
    let store = header
        .iter()
        .position(|c| label(c) == "blocks" || label(c).ends_with("(store)"));
    Some((blocker, store))
}
/// Whether a heading opens an exclusion section: its first word after any numbering, and the whole
/// word, not a prefix of it. `Exclusive access` is not an exclusions section, and reading it as one
/// fails a correct document — an over-match here is a false failure, not a missed one.
fn excludes(heading: &str) -> bool {
    heading
        .split_whitespace()
        .find(|word| {
            !word
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '.' | ')' | '(' | '-'))
        })
        .map(|word| {
            word.trim_matches(|c: char| !c.is_alphanumeric())
                .to_ascii_lowercase()
        })
        .is_some_and(|word| matches!(word.as_str(), "excluded" | "exclusion" | "exclusions"))
}
/// The tail of a bolded field whose label ends `(store).`, such as a row body's affected stories.
fn store_field(line: &str) -> Option<&str> {
    let (label, rest) = line.strip_prefix("**")?.split_once("**")?;
    label.trim_end().ends_with("(store).").then_some(rest)
}
/// The blocker a heading names, by its full artifact id. A heading is prose with a quoted word in
/// it as often as not, so the bare name a `Blocker` column may use is not admitted here: it would
/// turn `## The \`epoch\` field` into a claim about a blocker.
fn section_blocker(heading: &str) -> Option<String> {
    quoted(heading)
        .into_iter()
        .find(|t| t.starts_with("decision-blocker:"))
}
fn slug(token: &str) -> bool {
    !token.is_empty()
        && token
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}
/// Every blocker a `Blocker` cell names. A cell naming two claims two: reading the first and
/// dropping the rest is a row that stops being compared without saying so.
///
/// The dossier writes full artifact ids. The decisions table at `federated-login.md:124` writes
/// the bare name, and that spelling is admitted only when it is the cell's single quoted token —
/// a cell quoting several words has not said which is a blocker, and `` `none` `` at
/// `federated-login.md:127` is a word.
fn blocker_ids(cell: &str) -> Vec<String> {
    let tokens = quoted(cell);
    let mut ids: Vec<String> = Vec::new();
    for token in tokens.iter().filter(|t| t.starts_with("decision-blocker:")) {
        if !ids.contains(token) {
            ids.push(token.clone());
        }
    }
    if ids.is_empty()
        && let [only] = tokens.as_slice()
        && slug(only)
    {
        ids.push(format!("decision-blocker:{only}"));
    }
    ids
}
/// Every backtick-quoted token of a fragment.
fn quoted(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut rest = text;
    while let Some((_, tail)) = rest.split_once('`') {
        let Some((token, tail)) = tail.split_once('`') else {
            break;
        };
        tokens.push(token.to_owned());
        rest = tail;
    }
    tokens
}
fn artifact(token: &str) -> bool {
    token.starts_with("story:") || token.starts_with("task:")
}
/// The artifact ids of a table cell: the whole cell is the row set.
fn ids(cell: &str) -> BTreeSet<String> {
    quoted(cell).into_iter().filter(|t| artifact(t)).collect()
}
/// The artifact ids a bolded field opens with. Only the leading run counts: a row body may follow
/// its set with prose that names further ids as history — `runtime-decisions.md:175` names the
/// story a row moved from — and that prose is not part of the set the store is asked about.
fn leading_ids(field: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let mut rest = field;
    loop {
        rest = rest.trim_start();
        let Some(tail) = rest.strip_prefix('`') else {
            break;
        };
        let Some((token, tail)) = tail.split_once('`') else {
            break;
        };
        if !artifact(token) {
            break;
        }
        ids.insert(token.to_owned());
        rest = tail.strip_prefix(',').unwrap_or(tail);
        rest = rest.strip_prefix(" and").unwrap_or(rest);
    }
    ids
}
/// The content of a markdown list item, if the line is one.
fn list_item(line: &str) -> Option<&str> {
    for marker in ["- ", "* ", "+ "] {
        if let Some(rest) = line.strip_prefix(marker) {
            return Some(rest);
        }
    }
    let (number, rest) = line.split_once(". ").or_else(|| line.split_once(") "))?;
    (!number.is_empty() && number.chars().all(|c| c.is_ascii_digit())).then_some(rest)
}
/// The row set a bolded field states, and the line after it.
///
/// A field runs to the end of its paragraph: a markdown line wrap inside one is invisible to a
/// reader and must be invisible here too, or half a row set is compared against all of it. A field
/// may also state its set as the list that follows it — the ordinary way to write four of them —
/// and a list read as the empty set reports drift from a store the document agrees with.
fn field_row_set(lines: &[&str], start: usize) -> (BTreeSet<String>, usize) {
    let mut text = store_field(lines[start].trim())
        .unwrap_or_default()
        .to_owned();
    let mut next = start + 1;
    while let Some(line) = lines.get(next) {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("**")
            || line.starts_with('|')
            || list_item(line).is_some()
        {
            break;
        }
        text.push(' ');
        text.push_str(line);
        next += 1;
    }
    let mut ids = leading_ids(&text);
    // The list belonging to a field follows it directly, or across the one blank line markdown
    // needs to start a list. Anything else — a heading, another field — ends the field.
    let mut start_of_list = next;
    if lines
        .get(start_of_list)
        .is_some_and(|l| l.trim().is_empty())
    {
        start_of_list += 1;
    }
    if lines
        .get(start_of_list)
        .and_then(|l| list_item(l.trim()))
        .is_some()
    {
        next = start_of_list;
        while let Some(item) = lines.get(next).and_then(|l| list_item(l.trim())) {
            ids.extend(leading_ids(item));
            next += 1;
        }
    }
    (ids, next)
}
/// Close a table that has ended. The one place a `Blocker` table that stated no blocker is
/// reported: a table ends either at a non-row line or at the end of the document, and two copies
/// of this report would be two things to delete rather than one.
fn close(table: Option<Table>, defects: &mut Vec<(usize, String)>) {
    if let Some(closed) = table
        && closed.rows == 0
    {
        defects.push((
            closed.line,
            "this table names a `Blocker` column and states no blocker".to_owned(),
        ));
    }
}
/// Everything a document claims about the store, and everywhere it states a claim this reader
/// could not read.
fn read(text: &str) -> Reading {
    let lines: Vec<&str> = text.lines().collect();
    let mut reading = Reading {
        claims: Vec::new(),
        defects: Vec::new(),
    };
    let mut excluded = false;
    let mut section: Option<String> = None;
    let mut table: Option<Table> = None;
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index].trim();
        let at = index + 1;
        // A non-row line ends the table; a table that named a `Blocker` column and then stated
        // none is recorded as it closes, not silently dropped.
        if !line.starts_with('|') {
            close(table.take(), &mut reading.defects);
        }
        if let Some(rest) = line.strip_prefix('#') {
            let heading = rest.trim_start_matches('#').trim();
            excluded = excludes(heading);
            section = section_blocker(heading);
            index += 1;
            continue;
        }
        if line.starts_with('|') {
            if !separator(line) {
                let cells = cells(line);
                if let Some(open) = table.as_mut() {
                    let blocks = open.store.and_then(|i| cells.get(i)).map(|c| ids(c));
                    let blockers = blocker_ids(cells.get(open.blocker).map_or("", String::as_str));
                    if blockers.is_empty() {
                        reading.defects.push((
                            at,
                            "this row of a `Blocker` table states no blocker".to_owned(),
                        ));
                    } else {
                        open.rows += 1;
                        for blocker in blockers {
                            reading.claims.push(Claim {
                                blocker,
                                blocks: blocks.clone(),
                                line: at,
                                excluded,
                            });
                        }
                    }
                } else if let Some((blocker, store)) = columns(&cells) {
                    if lines.get(at).is_some_and(|next| separator(next.trim())) {
                        table = Some(Table {
                            blocker,
                            store,
                            line: at,
                            rows: 0,
                        });
                    } else {
                        reading.defects.push((
                            at,
                            "this table header names a `Blocker` column and no delimiter row \
                             follows it"
                                .to_owned(),
                        ));
                    }
                }
            }
            index += 1;
            continue;
        }
        if store_field(line).is_some() {
            let (blocks, next) = field_row_set(&lines, index);
            match section.clone() {
                Some(blocker) => reading.claims.push(Claim {
                    blocker,
                    blocks: Some(blocks),
                    line: at,
                    excluded,
                }),
                None => reading.defects.push((
                    at,
                    "this `(store).` field is under a heading naming no blocker".to_owned(),
                )),
            }
            index = next;
            continue;
        }
        index += 1;
    }
    close(table, &mut reading.defects);
    reading
}
fn list(ids: &BTreeSet<String>) -> String {
    if ids.is_empty() {
        return "nothing".to_owned();
    }
    ids.iter()
        .map(|i| format!("`{i}`"))
        .collect::<Vec<_>>()
        .join(", ")
}
/// A document is empty when nothing but whitespace is left. A byte order mark is not whitespace to
/// `str::trim` and is not content to a reader, so it is stripped too: truncating a file and saving
/// it again is exactly how one is left behind.
fn blank(text: &str) -> bool {
    text.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
        .is_empty()
}
/// Every declared document, against the store's own answer. Reports every failure it finds rather
/// than the first, so one run names the whole correction.
pub fn documents(root: &Path, blocked: &[Blocker]) -> Result<String> {
    let store: BTreeMap<&str, &Blocker> = blocked.iter().map(|b| (b.id.as_str(), b)).collect();
    let declared = declared(root)?;
    let mut problems: Vec<String> = Vec::new();
    let mut read_documents: Vec<(String, String)> = Vec::new();
    for document in &declared {
        let at = document.display().to_string();
        match fs::read_to_string(root.join(document)) {
            Err(e) => problems.push(format!("{at}: declared document cannot be read: {e}")),
            Ok(text) if blank(&text) => {
                problems.push(format!("{at}: declared document is empty"));
            }
            Ok(text) => read_documents.push((at, text)),
        }
    }
    let mut rows = 0;
    for (at, text) in &read_documents {
        let reading = read(text);
        for (line, defect) in &reading.defects {
            problems.push(format!("{at}:{line}: {defect}"));
        }
        let excluded: BTreeSet<&str> = reading
            .claims
            .iter()
            .filter(|c| c.excluded)
            .map(|c| c.blocker.as_str())
            .collect();
        let mut checked = BTreeSet::new();
        for claim in &reading.claims {
            let Claim {
                blocker,
                blocks,
                line,
                excluded: is_excluded,
            } = claim;
            if checked.insert(blocker.as_str()) {
                match store.get(blocker.as_str()) {
                    None => problems.push(format!(
                        "{at}: claims `{blocker}`, which `aep plan artifact blocked` does not report"
                    )),
                    // Defensive: a cleared blocker leaves the report entirely rather than changing
                    // status inside it, so this branch answers a store that reports one anyway.
                    Some(held) if held.status != "open" => problems.push(format!(
                        "{at}: claims `{blocker}`, which the store reports as `{}`, not `open`",
                        held.status
                    )),
                    Some(_) => {}
                }
            }
            if !is_excluded && excluded.contains(blocker.as_str()) {
                problems.push(format!(
                    "{at}:{line}: `{blocker}` is recorded as excluded from this document's rows and is one"
                ));
            }
            let (Some(blocks), Some(held)) = (blocks, store.get(blocker.as_str())) else {
                continue;
            };
            rows += 1;
            if &held.blocks != blocks {
                problems.push(format!(
                    "{at}:{line}: `{blocker}` blocks {} here, {} in the store",
                    list(blocks),
                    list(&held.blocks)
                ));
            }
        }
    }
    if !problems.is_empty() {
        return Err(problems.join("\n").into());
    }
    Ok(format!(
        "{} declared documents present; {rows} store-derived row sets match `aep plan artifact blocked`",
        declared.len()
    ))
}
