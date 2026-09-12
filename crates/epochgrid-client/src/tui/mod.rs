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
use std::{
    io::IsTerminal,
    path::PathBuf,
    time::{Duration, Instant},
};
use worker::Worker;

#[derive(Clone, Default)]
struct Snapshot {
    identity: String,
    channels: Vec<ChannelView>,
    selected: Option<String>,
    messages: Vec<MessageView>,
    typing: Vec<(String, Instant)>,
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
    message_id: Option<String>,
    status: Option<String>,
    id: i64,
    sequence: Option<u64>,
    sender: String,
    text: String,
}
fn message_lines(message: &MessageView) -> Vec<Line<'static>> {
    let sequence = message
        .sequence
        .map_or_else(|| "pending".into(), |s| s.to_string());
    let mut lines = vec![Line::from(format!(
        "{} [{}]{}",
        safe_text(&message.sender),
        sequence,
        message
            .message_id
            .as_ref()
            .map_or_else(String::new, |id| format!(" #{}", &id[..12]))
    ))];
    lines.extend(message.text.lines().map(|l| Line::from(l.to_owned())));
    if let Some(status) = &message.status {
        lines.push(Line::from(safe_text(status)));
    }
    lines.push(Line::default());
    lines
}
#[derive(Debug, PartialEq)]
enum RelationDraft {
    Reply(String),
    Edit(String),
    Reaction { target: String, add: bool },
}
#[derive(Debug, PartialEq)]
enum Action {
    Typing {
        name: String,
        active: bool,
        observed: Instant,
    },
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
        relation: Option<RelationDraft>,
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
            relation: None,
            name: name()?,
            text: format!("/{message}"),
        });
    }
    for prefix in ["/reply ", "/edit ", "/react ", "/unreact "] {
        if let Some(arguments) = input.strip_prefix(prefix) {
            let (target, text) = arguments
                .trim()
                .split_once(' ')
                .context("use COMMAND MESSAGE_ID TEXT_OR_REACTION")?;
            ensure!(!text.trim().is_empty(), "text or reaction is required");
            let relation = match prefix {
                "/reply " => RelationDraft::Reply(target.into()),
                "/edit " => RelationDraft::Edit(target.into()),
                _ => RelationDraft::Reaction {
                    target: target.into(),
                    add: prefix == "/react ",
                },
            };
            return Ok(Action::Send {
                name: name()?,
                text: text.into(),
                relation: Some(relation),
            });
        }
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
            ["/status"] => Ok(Action::Send {
                name: name()?,
                text: "/status".into(),
                relation: None,
            }),
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
                "Commands: /status, /create NAME, /invite USER [DEVICE], /join INVITER [DEVICE], /members, /reply ID TEXT, /edit ID TEXT, /react ID VALUE, /unreact ID VALUE, /attach PATH, /save ID PATH, /help, /quit; // sends a literal slash"
            ),
        };
    }
    ensure!(
        !input.is_empty() && input.len() <= epochgrid_core::messaging::MAX_PLAINTEXT,
        "message must contain 1–16384 bytes"
    );
    Ok(Action::Send {
        relation: None,
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
                    .map(|m| epochgrid_core::participants::member_label(m))
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
                    self.notice = "Tab channels | Up/Down scroll | PgUp older / PgDn latest | /create NAME | /invite USER [DEVICE] | /join INVITER [DEVICE] | /members | /devices | /status | /reply ID TEXT | /edit ID TEXT | /react ID VALUE | /unreact ID VALUE | /attach PATH | /save ID PATH | /quit | // literal slash".into();
                    self.input.clear();
                } else {
                    return submit(&self.input, state.selected.as_deref()).map(Some);
                }
            }
            _ => {}
        }
        Ok(None)
    }
    fn visible_ids(&self, area: ratatui::layout::Rect, state: &Snapshot) -> Vec<i64> {
        // Same layout and wrapping as draw(); only visible message text counts.
        let [_, body, _, _] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(3),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .areas(area);
        let [_, messages] =
            Layout::horizontal([Constraint::Length(25), Constraint::Min(5)]).areas(body);
        let width = messages.width.saturating_sub(2);
        let height = messages.height.saturating_sub(2) as usize;
        if width == 0 || height == 0 {
            return Vec::new();
        }
        let heights: Vec<_> = state
            .messages
            .iter()
            .map(|m| {
                Paragraph::new(message_lines(m))
                    .wrap(Wrap { trim: false })
                    .line_count(width)
            })
            .collect();
        let top = heights
            .iter()
            .sum::<usize>()
            .saturating_sub(height)
            .saturating_sub(self.scroll as usize)
            .min(u16::MAX as usize);
        let mut offset = 0;
        state
            .messages
            .iter()
            .zip(heights)
            .filter_map(|(m, h)| {
                let header = Paragraph::new(vec![message_lines(m).remove(0)])
                    .wrap(Wrap { trim: false })
                    .line_count(width);
                let text_height = Paragraph::new(
                    m.text
                        .lines()
                        .map(|l| Line::from(l.to_owned()))
                        .collect::<Vec<_>>(),
                )
                .wrap(Wrap { trim: false })
                .line_count(width);
                let visible = !m.text.is_empty()
                    && offset + header < top + height
                    && offset + header + text_height > top;
                offset += h;
                visible.then_some(m.id)
            })
            .collect()
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
        let lines: Vec<Line> = state.messages.iter().flat_map(message_lines).collect();
        let typing = state
            .typing
            .iter()
            .filter(|(_, expiry)| *expiry > Instant::now())
            .filter_map(|(s, _)| s.split_once('/').map(|(u, _)| u))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        let title = format!(
            "{}{}{}",
            state
                .selected
                .as_deref()
                .unwrap_or("No channel — /create NAME or /join INVITER"),
            if state.older { " (older page)" } else { "" },
            if typing.is_empty() {
                String::new()
            } else {
                format!(" — {typing} is typing")
            }
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
#[derive(Default)]
struct DraftActivity {
    draft: String,
    edited: Option<Instant>,
    announced: Option<(String, Instant)>,
}
impl DraftActivity {
    fn update(
        &mut self,
        draft: &str,
        selected: Option<&str>,
        pending: bool,
        now: Instant,
    ) -> Vec<Action> {
        if self.draft != draft {
            self.draft = draft.into();
            self.edited = Some(now);
        }
        let target = selected.filter(|_| {
            !pending
                && !draft.is_empty()
                && (!draft.starts_with('/') || draft.starts_with("//"))
                && self
                    .edited
                    .is_some_and(|t| now.duration_since(t) < Duration::from_secs(3))
        });
        let mut actions = Vec::new();
        if self
            .announced
            .as_ref()
            .is_some_and(|(name, _)| Some(name.as_str()) != target)
            && let Some((name, _)) = self.announced.take()
        {
            actions.push(Action::Typing {
                name,
                active: false,
                observed: now,
            });
        }
        if let Some(name) = target
            && self
                .announced
                .as_ref()
                .is_none_or(|(_, last)| now.duration_since(*last) >= Duration::from_secs(2))
        {
            actions.push(Action::Typing {
                name: name.into(),
                active: true,
                observed: now,
            });
            self.announced = Some((name.into(), now));
        }
        actions
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
    let mut activity = DraftActivity::default();
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
        for action in activity.update(
            &ui.input,
            state.selected.as_deref(),
            pending.is_some(),
            Instant::now(),
        ) {
            let _ = worker.commands.try_send(action);
        }
        let mut ids = Vec::new();
        terminal.draw(|frame| {
            ids = ui.visible_ids(frame.area(), &state);
            ui.draw(frame, &state);
        })?;
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
    fn service_command_and_visible_membership() -> Result<()> {
        assert_eq!(
            submit("/status", Some("engineering"))?,
            Action::Send {
                name: "engineering".into(),
                text: "/status".into(),
                relation: None,
            }
        );
        assert!(submit("/status", None).is_err());
        let state = Snapshot {
            members: vec![
                "alice/laptop".into(),
                "alice/desktop".into(),
                "status/service".into(),
            ],
            ..Snapshot::default()
        };
        assert_eq!(
            Notice::Members.text(&state),
            "Members: @status [service], alice"
        );
        assert!(Notice::Devices.text(&state).contains("status/service"));
        Ok(())
    }
    #[test]
    fn relationship_commands_preserve_text_and_target() -> Result<()> {
        assert_eq!(
            submit("/reply abcdef12 hello world", Some("engineering"))?,
            Action::Send {
                name: "engineering".into(),
                text: "hello world".into(),
                relation: Some(RelationDraft::Reply("abcdef12".into()))
            }
        );
        assert_eq!(
            submit("/edit abcdef12 revised text", Some("engineering"))?,
            Action::Send {
                name: "engineering".into(),
                text: "revised text".into(),
                relation: Some(RelationDraft::Edit("abcdef12".into()))
            }
        );
        for (command, add) in [("react", true), ("unreact", false)] {
            assert_eq!(
                submit(&format!("/{command} abcdef12 👍"), Some("engineering"))?,
                Action::Send {
                    name: "engineering".into(),
                    text: "👍".into(),
                    relation: Some(RelationDraft::Reaction {
                        target: "abcdef12".into(),
                        add
                    })
                }
            );
        }
        assert!(submit("/edit abcdef12", Some("engineering")).is_err());
        assert!(submit("/reply abcdef12 hello", None).is_err());
        Ok(())
    }
    #[test]
    fn only_visible_message_text_is_marked_read() {
        let state = Snapshot {
            messages: (0..20)
                .map(|id| MessageView {
                    message_id: None,
                    id,
                    status: None,
                    sequence: Some(id as u64),
                    sender: "bob/laptop".into(),
                    text: format!("message {id}"),
                })
                .collect(),
            ..Default::default()
        };
        let area = ratatui::layout::Rect::new(0, 0, 100, 24);
        let ui = Ui::default();
        let latest = ui.visible_ids(area, &state);
        assert!(latest.contains(&19));
        assert!(!latest.contains(&0));
        let older = Ui {
            scroll: 50,
            ..Default::default()
        }
        .visible_ids(area, &state);
        assert!(!older.contains(&19));
        assert!(!older.is_empty());
        assert!(
            ui.visible_ids(ratatui::layout::Rect::new(0, 0, 1, 1), &state)
                .is_empty()
        );
    }
    #[test]
    fn typing_drafts_refresh_stop_and_ignore_commands() {
        let mut activity = DraftActivity::default();
        let now = Instant::now();
        assert!(matches!(
            activity.update("hello", Some("g"), false, now).as_slice(),
            [Action::Typing { active: true, .. }]
        ));
        assert!(
            activity
                .update("hello", Some("g"), false, now + Duration::from_secs(1))
                .is_empty()
        );
        assert!(matches!(
            activity
                .update("hello!", Some("g"), false, now + Duration::from_secs(2))
                .as_slice(),
            [Action::Typing { active: true, .. }]
        ));
        assert!(matches!(
            activity
                .update("hello!", Some("g"), false, now + Duration::from_secs(5))
                .as_slice(),
            [Action::Typing { active: false, .. }]
        ));
        assert!(
            activity
                .update(
                    "/invite bob",
                    Some("g"),
                    false,
                    now + Duration::from_secs(6)
                )
                .is_empty()
        );
        assert!(
            activity
                .update("queued", Some("g"), true, now + Duration::from_secs(7))
                .is_empty()
        );
    }
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
                relation: None,
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
                message_id: None,
                status: None,
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
