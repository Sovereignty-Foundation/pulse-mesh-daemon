// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! Render a clap command tree as a Markdown reference page, for
//! `mesh-hub --dump-cli-markdown` and `pms docs cli-markdown`;
//! `scripts/docs/check-generated.py` fails when a committed page differs from
//! what they print.

use clap::Command;
use std::fmt::Write as _;

/// Markdown for `cmd` and every subcommand, depth first.
pub fn markdown(cmd: &Command) -> String {
    let mut out = String::new();
    render(cmd, &[], &mut out);
    out
}

fn render(cmd: &Command, path: &[&str], out: &mut String) {
    let mut names: Vec<&str> = path.to_vec();
    names.push(cmd.get_name());
    let full = names.join(" ");
    let level = "#".repeat((path.len() + 2).min(6));
    let _ = writeln!(out, "{level} `{full}`\n");
    if let Some(about) = cmd.get_long_about().or(cmd.get_about()) {
        let _ = writeln!(out, "{about}\n");
    }
    let args: Vec<_> = cmd
        .get_arguments()
        .filter(|a| !a.is_hide_set() && a.get_id() != "help" && a.get_id() != "version")
        .collect();
    if !args.is_empty() {
        let _ = writeln!(out, "| Argument | Default | Meaning |\n|---|---|---|");
        for a in args {
            // One code span for the flag and its value names, so the angle
            // brackets are not HTML.
            let values = if a.get_action().takes_values() {
                a.get_value_names()
                    .map(|v| v.iter().map(|s| format!(" <{s}>")).collect::<String>())
                    .unwrap_or_else(|| format!(" <{}>", a.get_id().as_str().to_uppercase()))
            } else {
                String::new()
            };
            let name = match a.get_long() {
                Some(l) => format!("`--{l}{values}`"),
                None => format!("`{}`", values.trim_start()),
            };
            let default: Vec<String> = a
                .get_default_values()
                .iter()
                .map(|v| v.to_string_lossy().into_owned())
                .collect();
            let default = if default.is_empty() {
                if a.is_required_set() {
                    "required".to_string()
                } else {
                    String::new()
                }
            } else {
                format!("`{}`", default.join(" "))
            };
            let help = a
                .get_long_help()
                .or(a.get_help())
                .map(|h| h.to_string().replace('\n', " "))
                .unwrap_or_default();
            let _ = writeln!(out, "| {name} | {default} | {help} |");
        }
        let _ = writeln!(out);
    }
    // What `--help` prints after the flags: the daemon's exit statuses.
    if let Some(after) = cmd.get_after_long_help().or(cmd.get_after_help()) {
        let _ = writeln!(out, "{}\n", after.to_string().trim_end());
    }
    for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
        render(sub, &names, out);
    }
}
