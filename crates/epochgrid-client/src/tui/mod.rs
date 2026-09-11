mod worker;
use anyhow::{Context, Result, ensure};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Style},
    text::Line,
    widgets::{Block, List, ListItem, Paragraph, Wrap},
};
use std::{io::IsTerminal, path::PathBuf, time::Duration};
use worker::Worker;

#[derive(Clone, Default)]
struct Snapshot {
    identity: String,
    channels: Vec<ChannelView>,
    selected: Option<String>,
    messages: Vec<MessageView>,
    members: Vec<String>,
    status: String,
    notice: String,
    security_warning: Option<String>,
    older: bool,
    fatal: Option<String>,
    send_count: u64,
    send_error: Option<String>,
}
#[derive(Clone)]
struct ChannelView {
    name: String,
    unread: u64,
}
#[derive(Clone)]
struct MessageView {
    id: i64,
    sequence: Option<u64>,
    sender: String,
    text: String,
}
#[derive(Debug, PartialEq)]
enum Action {
    Attach {
        name: String,
        path: String,
    },
    SaveAttachment {
        name: String,
        id: String,
        path: String,
    },
    Select(String),
    Create(String),
    Send {
        name: String,
        text: String,
    },
    Invite {
        name: String,
        user: String,
        device: String,
    },
    Join {
        user: String,
        device: String,
    },
    Older,
    Latest,
    Viewed(Vec<i64>),
}
fn safe_text(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control() && c != '\n' {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
fn submit(input: &str, selected: Option<&str>) -> Result<Action> {
    let name = || {
        selected
            .context("select or create a channel first")
            .map(str::to_owned)
    };
    if let Some(message) = input.strip_prefix("//") {
        return Ok(Action::Send {
            name: name()?,
            text: format!("/{message}"),
        });
    }
    if let Some(path) = input.strip_prefix("/attach ") {
        ensure!(!path.trim().is_empty(), "use /attach PATH");
        return Ok(Action::Attach {
            name: name()?,
            path: path.trim().into(),
        });
    }
    if let Some(arguments) = input.strip_prefix("/save ") {
        let (id, path) = arguments
            .trim()
            .split_once(' ')
            .context("use /save ATTACHMENT_ID OUTPUT_PATH")?;
        ensure!(!path.trim().is_empty(), "output path required");
        return Ok(Action::SaveAttachment {
            name: name()?,
            id: id.into(),
            path: path.trim().into(),
        });
    }
    if input.starts_with('/') {
        let fields: Vec<_> = input.split_whitespace().collect();
        return match fields.as_slice() {
            ["/create", channel] => Ok(Action::Create((*channel).into())),
            ["/invite", user] => Ok(Action::Invite {
                name: name()?,
                user: (*user).into(),
                device: "laptop".into(),
            }),
            ["/invite", user, device] => Ok(Action::Invite {
                name: name()?,
                user: (*user).into(),
                device: (*device).into(),
            }),
            ["/join", user] => Ok(Action::Join {
                user: (*user).into(),
                device: "laptop".into(),
            }),
            ["/join", user, device] => Ok(Action::Join {
                user: (*user).into(),
                device: (*device).into(),
            }),
            _ => anyhow::bail!(
                "Commands: /create NAME, /invite USER [DEVICE], /join INVITER [DEVICE], /members, /attach PATH, /save ID PATH, /help, /quit; // sends a literal slash"
            ),
        };
    }
    ensure!(
        !input.is_empty() && input.len() <= epochgrid_core::messaging::MAX_PLAINTEXT,
        "message must contain 1–16384 bytes"
    );
    Ok(Action::Send {
        name: name()?,
        text: input.into(),
    })
}
#[derive(Default)]
enum Notice {
    #[default]
    None,
    Text(String),
    Members,
    Devices,
}
impl From<String> for Notice {
    fn from(text: String) -> Self {
        Self::Text(text)
    }
}
impl From<&str> for Notice {
    fn from(text: &str) -> Self {
        Self::Text(text.into())
    }
}
impl Notice {
    fn clear(&mut self) {
        *self = Self::None;
    }
    fn text(&self, state: &Snapshot) -> String {
        if let Some(warning) = &state.security_warning {
            return warning.clone();
        }
        match self {
            Self::None => state.notice.clone(),
            Self::Text(text) => text.clone(),
            Self::Devices => format!("Device leaves: {}", state.members.join(", ")),
            Self::Members => format!(
                "Members: {}",
                state
                    .members
                    .iter()
                    .filter_map(|m| m.split_once('/').map(|(user, _)| user))
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}
#[derive(Default)]
struct Ui {
    input: String,
    notice: Notice,
    scroll: u16,
}
impl Ui {
    fn key(&mut self, key: KeyEvent, state: &Snapshot) -> Result<Option<Action>> {
        if key.kind == KeyEventKind::Release {
            return Ok(None);
        }
        match key.code {
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                if self.input.len() + c.len_utf8() <= epochgrid_core::messaging::MAX_PLAINTEXT {
                    self.input.push(c);
                }
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Esc => {
                self.input.clear();
            }
            KeyCode::Up => {
                self.scroll = self.scroll.saturating_add(1);
            }
            KeyCode::Down => {
                self.scroll = self.scroll.saturating_sub(1);
            }
            KeyCode::PageUp => {
                self.scroll = 0;
                return Ok(Some(Action::Older));
            }
            KeyCode::PageDown => {
                self.scroll = 0;
                return Ok(Some(Action::Latest));
            }
            KeyCode::Tab | KeyCode::BackTab if !state.channels.is_empty() => {
                let index = state
                    .channels
                    .iter()
                    .position(|c| Some(&c.name) == state.selected.as_ref())
                    .unwrap_or(0);
                let next = if key.code == KeyCode::Tab {
                    (index + 1) % state.channels.len()
                } else {
                    (index + state.channels.len() - 1) % state.channels.len()
                };
                self.scroll = 0;
                return Ok(Some(Action::Select(state.channels[next].name.clone())));
            }
            KeyCode::Enter if !self.input.is_empty() => {
                if self.input == "/members" {
                    self.notice = Notice::Members;
                    self.input.clear();
                } else if self.input == "/devices" {
                    self.notice = Notice::Devices;
                    self.input.clear();
                } else if self.input == "/help" {
                    self.notice = "Tab channels | Up/Down scroll | PgUp older / PgDn latest | /create NAME | /invite USER [DEVICE] | /join INVITER [DEVICE] | /members | /devices | /attach PATH | /save ID PATH | /quit | // literal slash".into();
                    self.input.clear();
                } else {
                    return submit(&self.input, state.selected.as_deref()).map(Some);
                }
            }
            _ => {}
        }
        Ok(None)
    }
    fn draw(&self, frame: &mut Frame, state: &Snapshot) {
        let [header, body, compose, footer] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(3),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .areas(frame.area());
        frame.render_widget(
            Paragraph::new(format!(
                "EpochGrid | {} | {}",
                safe_text(&state.identity),
                safe_text(&state.status)
            )),
            header,
        );
        let [channels, messages] =
            Layout::horizontal([Constraint::Length(25), Constraint::Min(5)]).areas(body);
        let items = state.channels.iter().map(|channel| {
            let selected = state.selected.as_ref() == Some(&channel.name);
            ListItem::new(format!(
                "{} #{} ({})",
                if selected { ">" } else { " " },
                channel.name,
                channel.unread
            ))
            .style(if selected {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default()
            })
        });
        frame.render_widget(
            List::new(items).block(Block::bordered().title("Channels / unread")),
            channels,
        );
        let lines: Vec<Line> = state
            .messages
            .iter()
            .flat_map(|message| {
                let sequence = message
                    .sequence
                    .map_or_else(|| "pending".into(), |s| s.to_string());
                let mut lines = vec![Line::from(format!(
                    "{} [{}]",
                    safe_text(&message.sender),
                    sequence
                ))];
                lines.extend(message.text.lines().map(|l| Line::from(l.to_owned())));
                lines.push(Line::default());
                lines
            })
            .collect();
        let title = format!(
            "{}{}",
            state
                .selected
                .as_deref()
                .unwrap_or("No channel — /create NAME or /join INVITER"),
            if state.older { " (older page)" } else { "" }
        );
        let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
        let height = paragraph.line_count(messages.width.saturating_sub(2));
        let scroll = height
            .saturating_sub(messages.height.saturating_sub(2) as usize)
            .saturating_sub(self.scroll as usize)
            .min(u16::MAX as usize) as u16;
        frame.render_widget(
            paragraph
                .scroll((scroll, 0))
                .block(Block::bordered().title(title)),
            messages,
        );
        let input = safe_text(&self.input);
        let width = Line::from(input.as_str()).width();
        let offset = width
            .saturating_sub(compose.width.saturating_sub(3) as usize)
            .min(u16::MAX as usize) as u16;
        frame.render_widget(
            Paragraph::new(input)
                .scroll((0, offset))
                .block(Block::bordered().title("Message / command — Enter sends; Esc clears")),
            compose,
        );
        if compose.width >= 3 && compose.height >= 3 {
            frame.set_cursor_position((
                compose.x
                    + 1
                    + (width.saturating_sub(offset as usize) as u16).min(compose.width - 3),
                compose.y + 1,
            ));
        }
        let notice = self.notice.text(state);
        frame.render_widget(Paragraph::new(format!("{}\nTab channels | Up/Down scroll | PgUp older | PgDn latest | /help | Ctrl-C quit", safe_text(&notice))).wrap(Wrap { trim: false }), footer);
    }
}
struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = crossterm::execute!(std::io::stdout(), event::DisableBracketedPaste);
        ratatui::restore();
    }
}
pub fn run(home: PathBuf, server: String) -> Result<()> {
    ensure!(
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
        "tui requires a terminal; use chat or message commands for scripting"
    );
    let worker = Worker::start(home, server);
    let _guard = TerminalGuard;
    let mut terminal = ratatui::try_init()?;
    crossterm::execute!(std::io::stdout(), event::EnableBracketedPaste)?;
    let mut ui = Ui::default();
    let mut viewed = Vec::new();
    let mut pending: Option<(u64, String)> = None;
    loop {
        let state = worker.updates.borrow().clone();
        if let Some(error) = &state.fatal {
            anyhow::bail!("{error}");
        }
        if let Some((count, draft)) = &pending
            && state.send_count > *count
        {
            if let Some(error) = &state.send_error {
                ui.notice = format!("Send failed; draft retained: {error}").into();
            } else if &ui.input == draft {
                ui.input.clear();
            }
            pending = None;
        }
        terminal.draw(|frame| ui.draw(frame, &state))?;
        let ids: Vec<_> = state.messages.iter().map(|m| m.id).collect();
        if viewed != ids
            && worker
                .commands
                .try_send(Action::Viewed(ids.clone()))
                .is_ok()
        {
            viewed = ids;
        }
        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    if (key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL))
                        || (key.code == KeyCode::Enter && ui.input == "/quit")
                    {
                        break;
                    }
                    if key.code == KeyCode::Enter && pending.is_some() {
                        continue;
                    }
                    match ui.key(key, &state) {
                        Ok(Some(action)) => {
                            let message = matches!(action, Action::Send { .. });
                            let send = matches!(
                                action,
                                Action::Send { .. }
                                    | Action::Create(_)
                                    | Action::Invite { .. }
                                    | Action::Join { .. }
                                    | Action::Attach { .. }
                                    | Action::SaveAttachment { .. }
                            );
                            match worker.commands.try_send(action) {
                                Ok(()) => {
                                    if message {
                                        pending = Some((state.send_count, ui.input.clone()));
                                    } else if send {
                                        ui.input.clear();
                                    }
                                    ui.notice.clear();
                                }
                                Err(_) => {
                                    ui.notice = "Worker busy; input retained, try again".into()
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(error) => ui.notice = error.to_string().into(),
                    }
                }
                Event::Paste(text) => {
                    for c in text.chars().filter(|c| !c.is_control()) {
                        if ui.input.len() + c.len_utf8() <= epochgrid_core::messaging::MAX_PLAINTEXT
                        {
                            ui.input.push(c);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commands_unicode_editing_and_channel_navigation() -> Result<()> {
        let mut ui = Ui::default();
        let state = Snapshot {
            selected: Some("engineering".into()),
            channels: vec![
                ChannelView {
                    name: "engineering".into(),
                    unread: 2,
                },
                ChannelView {
                    name: "other".into(),
                    unread: 0,
                },
            ],
            ..Default::default()
        };
        ui.key(
            KeyEvent::new(KeyCode::Char('é'), KeyModifiers::NONE),
            &state,
        )?;
        ui.key(
            KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
            &state,
        )?;
        assert!(ui.input.is_empty());
        assert_eq!(
            ui.key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE), &state)?,
            Some(Action::Select("other".into()))
        );
        assert!(submit("hello", None).is_err());
        assert!(submit("/unknown", state.selected.as_deref()).is_err());
        assert_eq!(
            submit("/join bob", None)?,
            Action::Join {
                user: "bob".into(),
                device: "laptop".into()
            }
        );
        assert_eq!(
            submit("//literal", Some("engineering"))?,
            Action::Send {
                name: "engineering".into(),
                text: "/literal".into()
            }
        );
        assert!(!safe_text("escape\u{1b}[2J").contains('\u{1b}'));
        Ok(())
    }
    #[test]
    fn attachment_commands_preserve_paths_with_spaces() -> Result<()> {
        assert_eq!(
            submit("/attach /tmp/private file.txt", Some("engineering"))?,
            Action::Attach {
                name: "engineering".into(),
                path: "/tmp/private file.txt".into()
            }
        );
        assert_eq!(
            submit("/save abc /tmp/saved file.txt", Some("engineering"))?,
            Action::SaveAttachment {
                name: "engineering".into(),
                id: "abc".into(),
                path: "/tmp/saved file.txt".into()
            }
        );
        assert!(submit("/attach ", Some("engineering")).is_err());
        assert!(submit("/save abc ", Some("engineering")).is_err());
        assert!(submit("/attach file", None).is_err());
        Ok(())
    }

    #[test]
    fn members_collapse_users_and_devices_remain_visible() -> Result<()> {
        let state = Snapshot {
            members: vec![
                "alice/laptop".into(),
                "alice/desktop".into(),
                "bob/laptop".into(),
            ],
            ..Default::default()
        };
        let mut ui = Ui {
            input: "/members".into(),
            ..Default::default()
        };
        ui.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), &state)?;
        assert_eq!(ui.notice.text(&state), "Members: alice, bob");
        ui.input = "/devices".into();
        ui.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), &state)?;
        assert_eq!(
            ui.notice.text(&state),
            "Device leaves: alice/laptop, alice/desktop, bob/laptop"
        );
        let mut updated = state.clone();
        updated.members.remove(1);
        assert_eq!(
            ui.notice.text(&updated),
            "Device leaves: alice/laptop, bob/laptop"
        );
        updated.security_warning = Some("REVOCATION FAILURE: test".into());
        assert_eq!(ui.notice.text(&updated), "REVOCATION FAILURE: test");
        Ok(())
    }
    #[test]
    fn renders_history_pending_unread_and_offline_status() -> Result<()> {
        let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 24))?;
        let state = Snapshot {
            identity: "alice/laptop".into(),
            status: "Offline".into(),
            selected: Some("engineering".into()),
            channels: vec![ChannelView {
                name: "engineering".into(),
                unread: 2,
            }],
            messages: vec![MessageView {
                id: 1,
                sequence: None,
                sender: "alice/laptop".into(),
                text: "saved message".into(),
            }],
            ..Default::default()
        };
        terminal.draw(|frame| Ui::default().draw(frame, &state))?;
        let buffer = terminal.backend().buffer();
        let text: String = buffer.content.iter().map(|c| c.symbol()).collect();
        for expected in [
            "EpochGrid",
            "alice/laptop",
            "Offline",
            "engineering (2)",
            "pending",
            "saved message",
        ] {
            assert!(text.contains(expected), "missing {expected}");
        }
        Ok(())
    }
}
