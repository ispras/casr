extern crate anyhow;
extern crate casr;
extern crate clap;
extern crate cursive;
extern crate cursive_tree_view;
extern crate regex;
extern crate serde_json;

use clap::{App, Arg};
use cursive::event::EventTrigger;
use cursive::View;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

use anyhow::{Context, Result};
use cursive::align::Align;
use cursive::event::EventResult;
use cursive::theme::BaseColor;
use cursive::theme::Color;
use cursive::theme::Color::*;
use cursive::theme::Effect;
use cursive::theme::PaletteColor::*;
use cursive::theme::Style;
use cursive::utils::markup::StyledString;
use cursive::view::{Resizable, SizeConstraint};
use cursive::views::{
    LinearLayout, OnEventView, Panel, ResizedView, ScrollView, SelectView, TextContent, TextView,
};
use cursive::CursiveRunnable;
use cursive_tree_view::*;

use casr::report::CrashReport;

fn main() -> Result<()> {
    let matches = App::new("casr-cli")
        .author("Andrey Fedotov <fedotoff@ispras.ru>, Alexey Vishnyakov <vishnya@ispras.ru>, Georgy Savidov <avgor46@ispras.ru>")
        .version("2.3.0")
        .about("App provides text-based user interface to view CASR reports")
        .term_width(90)
        .arg(
            Arg::new("view")
                .long("view")
                .short('v')
                .takes_value(true)
                .value_name("MODE")
                .default_value("tree")
                .help("View mode")
                .possible_values(["tree", "slider", "stdout"]),
        )
        .arg(
            Arg::new("report")
                .takes_value(true)
                .required(true)
                .value_name("REPORT")
                .help("CASR report file to view"),
        )
        .get_matches();

    let report_path = PathBuf::from(matches.value_of("report").unwrap());
    let mut file = File::open(&report_path)
        .with_context(|| format!("Couldn't open report file: {}", &report_path.display()))?;

    let mut report_string = String::new();
    file.read_to_string(&mut report_string)
        .with_context(|| format!("Couldn't read report file: {}", &report_path.display()))?;

    let report: CrashReport = serde_json::from_str(&report_string)
        .with_context(|| format!("Couldn't deserialize report: {}", &report_path.display()))?;

    let mut header_string = StyledString::plain("Crash Report for ");
    header_string.append(StyledString::styled(
        &report.executable_path,
        Style::from(Color::Light(BaseColor::Blue)),
    ));

    if !report.package.is_empty() && !report.package_version.is_empty() {
        header_string.append(&format!(
            " from {} {}",
            report.package, report.package_version
        ));
    }
    let severity_type_string = format!(
        "{}: {}",
        report.execution_class.severity, report.execution_class.short_description
    );
    let styled_severity_string = match severity_type_string.as_str() {
        "CRITICAL" => StyledString::styled(
            severity_type_string,
            Style::from(Color::Light(BaseColor::Red)).combine(Effect::Bold),
        ),
        "POSSIBLE_CRITICAL" => StyledString::styled(
            severity_type_string,
            Style::from(Color::Light(BaseColor::Yellow)).combine(Effect::Bold),
        ),
        _ => StyledString::styled(
            severity_type_string,
            Style::from(Color::Light(BaseColor::Green)).combine(Effect::Bold),
        ),
    };
    // Initialize terminal.
    let mut theme = cursive::theme::load_default();
    theme.palette[Background] = TerminalDefault;
    theme.palette[View] = TerminalDefault;
    theme.palette[Primary] = TerminalDefault;
    let mut siv = cursive::default();
    siv.set_theme(theme);

    let header_content = TextContent::new(header_string);
    header_content.append("\nSeverity: ");
    header_content.append(styled_severity_string);

    let header = Panel::new(TextView::new_with_content(header_content.clone()));
    let footer = TextView::new("Press q to exit").align(Align::bot_right());

    let view = matches.value_of("view").unwrap();
    match view {
        "tree" => build_tree_report(&mut siv, header, footer, &report),
        "slider" => build_slider_report(&mut siv, header, footer, &report),
        _ => println!(
            "{}\n{}",
            &mut String::from(header_content.get_content().source()),
            report
        ),
    }

    Ok(())
}

/// Create tree view for casr report
///
/// # Arguments
///
/// * 'siv' - main view
///
/// * 'header' - header
///
/// * 'footer' - footer
///
/// * 'report' - casr report
fn build_tree_report(
    siv: &mut CursiveRunnable,
    mut header: Panel<TextView>,
    footer: TextView,
    report: &CrashReport,
) {
    let mut layout = LinearLayout::vertical();

    // Add report to tree.
    let mut tree = TreeView::new();
    let mut row: usize = 0;
    if !report.date.is_empty() {
        tree.insert_item("Date".to_string(), Placement::Parent, row)
            .unwrap();
        tree.insert_item(report.date.clone(), Placement::LastChild, row)
            .unwrap();
    }

    if !report.uname.is_empty() {
        row = tree
            .insert_item("Uname".to_string(), Placement::After, row)
            .unwrap();
        tree.insert_item(report.uname.clone(), Placement::LastChild, row)
            .unwrap();
    }

    if !report.os.is_empty() {
        row = tree
            .insert_item("OS".to_string(), Placement::After, row)
            .unwrap();
        tree.insert_item(report.os.clone(), Placement::LastChild, row)
            .unwrap();
    }

    if !report.os_release.is_empty() {
        row = tree
            .insert_item("OSRelease".to_string(), Placement::After, row)
            .unwrap();
        tree.insert_item(report.os_release.clone(), Placement::LastChild, row)
            .unwrap();
    }

    if !report.architecture.is_empty() {
        row = tree
            .insert_item("Architecture".to_string(), Placement::After, row)
            .unwrap();
        tree.insert_item(report.architecture.clone(), Placement::LastChild, row)
            .unwrap();
    }

    if !report.executable_path.is_empty() {
        row = tree
            .insert_item("ExecutablePath".to_string(), Placement::After, row)
            .unwrap();
        tree.insert_item(report.executable_path.clone(), Placement::LastChild, row)
            .unwrap();
        tree.collapse_item(row);
    }

    if !report.proc_cmdline.is_empty() {
        row = tree
            .insert_item("ProcCmdline".to_string(), Placement::After, row)
            .unwrap();
        tree.insert_item(report.proc_cmdline.clone(), Placement::LastChild, row)
            .unwrap();
    }

    if !report.stdin.is_empty() {
        row = tree
            .insert_item("Stdin".to_string(), Placement::After, row)
            .unwrap();
        tree.insert_item(report.stdin.clone(), Placement::LastChild, row)
            .unwrap();
    }

    if !report.proc_fd.is_empty() {
        row = tree
            .insert_item("ProcFiles".to_string(), Placement::After, row)
            .unwrap();
        report.proc_fd.iter().for_each(|file| {
            tree.insert_item(file.clone(), Placement::LastChild, row);
        });
    }

    if !report.network_connections.is_empty() {
        row = tree
            .insert_item("NetworkConnections".to_string(), Placement::After, row)
            .unwrap();
        report.network_connections.iter().for_each(|connection| {
            tree.insert_item(connection.clone(), Placement::LastChild, row);
        });
    }

    row = tree
        .insert_item("CrashSeverity".to_string(), Placement::After, row)
        .unwrap();
    tree.insert_item(
        report.execution_class.severity.to_string(),
        Placement::LastChild,
        row,
    );
    tree.insert_item(
        report.execution_class.short_description.to_string(),
        Placement::LastChild,
        row,
    );
    tree.insert_item(
        report.execution_class.description.to_string(),
        Placement::LastChild,
        row,
    );
    if !report.execution_class.explanation.is_empty() {
        tree.insert_item(
            report.execution_class.explanation.to_string(),
            Placement::LastChild,
            row,
        );
    }

    if !report.proc_maps.is_empty() {
        row = tree
            .insert_container_item("ProcMaps".to_string(), Placement::After, row)
            .unwrap();
        report.proc_maps.iter().for_each(|line| {
            tree.insert_item(line.clone(), Placement::LastChild, row);
        });
        tree.collapse_item(row);
    }

    if !report.proc_environ.is_empty() {
        row = tree
            .insert_container_item("ProcEnviron".to_string(), Placement::After, row)
            .unwrap();
        report
            .proc_environ
            .iter()
            .filter(|e| !e.contains("LS_COLORS"))
            .for_each(|line| {
                tree.insert_item(line.clone(), Placement::LastChild, row);
            });
        tree.collapse_item(row);
    }

    if !report.proc_status.is_empty() {
        row = tree
            .insert_container_item("ProcStatus".to_string(), Placement::After, row)
            .unwrap();
        report.proc_status.iter().for_each(|line| {
            tree.insert_item(line.clone(), Placement::LastChild, row);
        });
        tree.collapse_item(row);
    }

    if !report.registers.is_empty() || !report.disassembly.is_empty() {
        row = tree
            .insert_container_item("CrashState".to_string(), Placement::After, row)
            .unwrap();
        report.registers.iter().for_each(|(k, v)| {
            tree.insert_item(format!("{k}:    0x{v:x}"), Placement::LastChild, row);
        });

        if !report.disassembly.is_empty() && !report.registers.is_empty() {
            tree.insert_item("".to_string(), Placement::LastChild, row);
        }

        for line in report.disassembly.iter() {
            tree.insert_item(line.clone(), Placement::LastChild, row);
        }
    }

    if !report.stacktrace.is_empty() {
        row = tree
            .insert_container_item("Stacktrace".to_string(), Placement::After, row)
            .unwrap();
        report.stacktrace.iter().for_each(|e| {
            tree.insert_item(e.clone(), Placement::LastChild, row);
        });
        tree.expand_item(row);
    }

    if !report.asan_report.is_empty() {
        row = tree
            .insert_container_item("AsanReport".to_string(), Placement::After, row)
            .unwrap();
        report.asan_report.iter().for_each(|e| {
            tree.insert_item(e.clone(), Placement::LastChild, row);
        });
        tree.expand_item(row);
    }

    if !report.python_report.is_empty() {
        row = tree
            .insert_container_item("PythonReport".to_string(), Placement::After, row)
            .unwrap();
        report.python_report.iter().for_each(|e| {
            tree.insert_item(e.clone(), Placement::LastChild, row);
        });
        tree.expand_item(row);
    }

    if !report.source.is_empty() {
        row = tree
            .insert_container_item("Source".to_string(), Placement::After, row)
            .unwrap();
        report.source.iter().for_each(|e| {
            tree.insert_item(e.clone(), Placement::LastChild, row);
        });
        tree.expand_item(row);
    }

    if !report.package.is_empty() {
        row = tree
            .insert_container_item("Package".to_string(), Placement::After, row)
            .unwrap();
        tree.insert_item(report.package.clone(), Placement::LastChild, row);
    }

    if !report.package_version.is_empty() {
        row = tree
            .insert_container_item("PackageVersion".to_string(), Placement::After, row)
            .unwrap();
        tree.insert_item(report.package_version.clone(), Placement::LastChild, row);
    }

    if !report.package_description.is_empty() {
        row = tree
            .insert_item("PackageDescription".to_string(), Placement::After, row)
            .unwrap();
        tree.insert_item(
            report.package_description.clone(),
            Placement::LastChild,
            row,
        )
        .unwrap();
        tree.collapse_item(row);
    }

    if !report.crashline.is_empty() {
        let textcontent = header.get_inner_mut().get_shared_content();
        textcontent.append(format!("\nCrash line: {}", &report.crashline));
    }

    let scroll = ScrollView::new(tree).scroll_x(true);
    layout.add_child(header);
    layout.add_child(scroll);
    layout.add_child(footer);
    siv.add_fullscreen_layer(layout);

    siv.add_global_callback('q', |s| s.quit());

    siv.run();
}

/// Creates slider view for casr report
///
/// # Arguments
///
/// * 'siv' - main view
///
/// * 'header' - header
///
/// * 'footer' - footer
///
/// * 'report' - casr report
fn build_slider_report(
    siv: &mut CursiveRunnable,
    mut header: Panel<TextView>,
    footer: TextView,
    report: &CrashReport,
) {
    let mut select = SelectView::new();

    if !report.date.is_empty() {
        select.add_item("Date", report.date.clone());
    }

    if !report.uname.is_empty() {
        select.add_item("Uname", report.uname.clone());
    }

    if !report.os.is_empty() {
        select.add_item("OS", report.os.clone());
    }

    if !report.os_release.is_empty() {
        select.add_item("OSRelease", report.os_release.clone());
    }

    if !report.architecture.is_empty() {
        select.add_item("Architecture", report.architecture.clone());
    }

    if !report.executable_path.is_empty() {
        select.add_item("ExecutablePath", report.executable_path.clone());
    }

    if !report.proc_cmdline.is_empty() {
        select.add_item("ProcCmdline", report.proc_cmdline.clone());
    }

    if !report.stdin.is_empty() {
        select.add_item("Stdin", report.stdin.clone());
    }

    if !report.proc_fd.is_empty() {
        select.add_item("ProcFiles", report.proc_fd.join("\n"));
    }

    if !report.network_connections.is_empty() {
        select.add_item("NetworkConnections", report.network_connections.join("\n"));
    }
    let explanation = if !report.execution_class.explanation.is_empty() {
        format!("{}\n", report.execution_class.explanation)
    } else {
        "".to_string()
    };
    select.add_item(
        "CrashSeverity",
        format!(
            "{}\n{}\n{}\n{}",
            report.execution_class.severity,
            report.execution_class.short_description,
            report.execution_class.description,
            explanation
        ),
    );

    if !report.proc_maps.is_empty() {
        select.add_item("ProcMaps", report.proc_maps.join("\n"));
    }

    if !report.proc_environ.is_empty() {
        select.add_item("ProcEnviron", report.proc_environ.join("\n"));
    }

    if !report.proc_status.is_empty() {
        select.add_item("ProcStatus", report.proc_status.join("\n"));
    }

    let mut state = report
        .registers
        .iter()
        .map(|(k, v)| format!("{k}:    0x{v:x}\n"))
        .collect::<String>();

    if !report.disassembly.is_empty() {
        state.push_str(&format!("\n{}", &report.disassembly.join("\n")));
    }
    if !state.is_empty() {
        select.add_item("CrashState", state);
    }

    if !report.stacktrace.is_empty() {
        select.add_item("Stacktrace", report.stacktrace.join("\n"));
    }

    if !report.asan_report.is_empty() {
        select.add_item("AsanReport", report.asan_report.join("\n"));
    }

    if !report.python_report.is_empty() {
        select.add_item("PythonReport", report.python_report.join("\n"));
    }

    if !report.source.is_empty() {
        select.add_item("Source", report.source.join("\n"));
    }

    if !report.package.is_empty() {
        select.add_item("Package", report.package.clone());
    }

    if !report.package_version.is_empty() {
        select.add_item("PackageVersion", report.package_version.clone());
    }

    if !report.package_description.is_empty() {
        select.add_item("PackageDescription", report.package_description.clone());
    }

    if !report.crashline.is_empty() {
        let textcontent = header.get_inner_mut().get_shared_content();
        textcontent.append(format!("\nCrash line: {}", &report.crashline));
    }

    let scroll = ScrollView::new(select.fixed_width(20));

    let content = ResizedView::new(
        SizeConstraint::Full,
        SizeConstraint::Full,
        TextView::new("".to_string()),
    );
    let hl = LinearLayout::horizontal()
        .child(Panel::new(scroll))
        .child(Panel::new(ScrollView::new(content)));
    let layout = LinearLayout::vertical()
        .child(header)
        .child(hl)
        .child(footer);

    let layout = OnEventView::new(layout)
        .on_pre_event_inner(
            cursive::event::Key::Up,
            |layout1: &mut LinearLayout, _e: &cursive::event::Event| {
                change_text_view(layout1, Action::Arrow(1))
            },
        )
        .on_pre_event_inner(
            cursive::event::Key::Down,
            |layout1: &mut LinearLayout, _e: &cursive::event::Event| {
                change_text_view(layout1, Action::Arrow(0))
            },
        )
        .on_pre_event_inner(
            EventTrigger::mouse(),
            |layout1: &mut LinearLayout, e: &cursive::event::Event| {
                if let &cursive::event::Event::Mouse {
                    event: cursive::event::MouseEvent::Release(_),
                    ..
                } = e
                {
                    change_text_view(layout1, Action::Mouse(e.clone()))
                } else {
                    None
                }
            },
        );

    siv.add_global_callback('q', |s| s.quit());
    siv.add_fullscreen_layer(layout);
    siv.on_event(cursive::event::Event::Key(cursive::event::Key::Up));
    siv.run();
}

enum Action {
    Arrow(i32),
    Mouse(cursive::event::Event),
}

/// Function changes the Text view according to the selected item
///
/// # Arguments
///
/// * 'layout1' - main linear layout
///
/// * 'act' - change direction(up/down) or mouse click
///
fn change_text_view(layout1: &mut LinearLayout, act: Action) -> Option<EventResult> {
    let layout2 = (*layout1.get_child_mut(1).unwrap())
        .downcast_mut::<LinearLayout>()
        .unwrap();
    if layout2.get_focus_index() == 1 {
        return None;
    }
    let select = layout2
        .get_child_mut(0)
        .unwrap()
        .downcast_mut::<Panel<ScrollView<ResizedView<SelectView>>>>()
        .unwrap()
        .get_inner_mut()
        .get_inner_mut()
        .get_inner_mut();

    match act {
        Action::Arrow(arrow) => {
            if arrow == 1 {
                select.select_up(1);
            } else {
                select.select_down(1);
            }
        }
        Action::Mouse(ref e) => {
            select.on_event(e.clone());
        }
    };

    let totxt = String::from(select.get_item(select.selected_id().unwrap()).unwrap().1);
    let text = layout2
        .get_child_mut(1)
        .unwrap()
        .downcast_mut::<Panel<ScrollView<ResizedView<TextView>>>>()
        .unwrap()
        .get_inner_mut()
        .get_inner_mut()
        .get_inner_mut();
    *text = TextView::new(totxt);
    match act {
        Action::Arrow(_) => Some(EventResult::with_cb(|_s| {})),
        Action::Mouse(_) => None,
    }
}
