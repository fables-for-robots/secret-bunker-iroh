//! Interactive terminal UI over the bunker protocol.
//!
//! One UI for every role — what you can do is what the server lets you do.
//! Users browse the groups they hold permissions on and view/edit/delete
//! secrets; group admins additionally manage ACLs and rotate DEKs; service
//! admins also create groups and register/remove identities. All
//! enforcement stays on the server: the TUI merely surfaces denials.
//!
//! Runs on a blocking thread; network calls go through a tokio runtime
//! handle. One request is in flight at a time, mirroring the CLI.

use std::time::Duration;

use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};
use tokio::runtime::Handle;

use crate::client::Client;
use crate::proto::{GroupInfo, IdentityInfo, Request, Response, parse_perms, perms_str};

const ACCENT: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;

/// Identities eligible for a new grant: all registered names minus those
/// already on the group's ACL.
fn grant_candidates(names: Vec<String>, acl: &[(String, u8)]) -> Vec<String> {
    names
        .into_iter()
        .filter(|name| !acl.iter().any(|(member, _)| member == name))
        .collect()
}

pub fn run(handle: Handle, client: Client, my_id: String) -> Result<()> {
    let mut terminal = ratatui::init();
    let result = App::new(handle, client, my_id).run(&mut terminal);
    ratatui::restore();
    result
}

#[derive(PartialEq, Clone, Copy)]
enum Focus {
    Groups,
    Secrets,
}

enum Mode {
    Normal,
    Help,
    ViewSecret {
        name: String,
        version: u64,
        value: String,
    },
    Form(Form),
    Confirm(ConfirmAction),
    Identities,
    Acl,
    /// Pick an identity to grant on `acl_group` from the names not yet on
    /// its ACL.
    GrantPicker,
}

enum ConfirmAction {
    DeleteSecret { name: String, version: u64 },
    RemoveIdentity { name: String },
    RotateDek { group: String },
    SetServiceAdmin { name: String, service_admin: bool },
}

enum FormKind {
    NewGroup,
    NewSecret,
    EditSecret { name: String, expected_version: u64 },
    AddIdentity,
    GrantEntry,
}

struct Form {
    kind: FormKind,
    title: String,
    fields: Vec<(&'static str, String)>,
    focus: usize,
}

impl Form {
    fn new(kind: FormKind, title: &str, fields: &[(&'static str, &str)]) -> Self {
        Form {
            kind,
            title: title.to_string(),
            fields: fields
                .iter()
                .map(|(label, value)| (*label, value.to_string()))
                .collect(),
            focus: 0,
        }
    }
}

struct App {
    handle: Handle,
    client: Client,
    my_id: String,
    service_admin: bool,
    groups: Vec<GroupInfo>,
    gsel: usize,
    secrets: Vec<(String, u64)>,
    ssel: usize,
    identities: Vec<IdentityInfo>,
    isel: usize,
    acl: Vec<(String, u8)>,
    asel: usize,
    acl_group: String,
    candidates: Vec<String>,
    csel: usize,
    focus: Focus,
    mode: Mode,
    status: String,
    quit: bool,
}

impl App {
    fn new(handle: Handle, client: Client, my_id: String) -> Self {
        App {
            handle,
            client,
            my_id,
            service_admin: false,
            groups: Vec::new(),
            gsel: 0,
            secrets: Vec::new(),
            ssel: 0,
            identities: Vec::new(),
            isel: 0,
            acl: Vec::new(),
            asel: 0,
            acl_group: String::new(),
            candidates: Vec::new(),
            csel: 0,
            focus: Focus::Groups,
            mode: Mode::Normal,
            status: String::from("connected — press ? for help"),
            quit: false,
        }
    }

    fn run(mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        self.refresh_groups();
        self.refresh_secrets();
        while !self.quit {
            terminal.draw(|frame| self.draw(frame))?;
            if event::poll(Duration::from_millis(200))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                self.on_key(key);
            }
        }
        Ok(())
    }

    // ---- networking ----

    fn req(&mut self, request: Request) -> Option<Response> {
        match self.handle.block_on(self.client.request(&request)) {
            Ok(response) => Some(response),
            Err(err) => {
                self.status = format!("transport error: {err:#}");
                None
            }
        }
    }

    fn refresh_groups(&mut self) {
        match self.req(Request::ListGroups) {
            Some(Response::Groups {
                service_admin,
                groups,
            }) => {
                self.service_admin = service_admin;
                self.groups = groups;
                self.gsel = self.gsel.min(self.groups.len().saturating_sub(1));
            }
            Some(Response::Denied) => {
                self.status = "denied: this identity is not registered on the bunker".into();
            }
            _ => {}
        }
    }

    fn selected_group(&self) -> Option<&GroupInfo> {
        self.groups.get(self.gsel)
    }

    fn refresh_secrets(&mut self) {
        let Some(group) = self.selected_group().map(|g| g.name.clone()) else {
            self.secrets.clear();
            return;
        };
        match self.req(Request::List { group }) {
            Some(Response::Names(names)) => {
                self.secrets = names;
                self.ssel = self.ssel.min(self.secrets.len().saturating_sub(1));
            }
            Some(Response::Denied) => {
                // No read permission on this group (e.g. write-only).
                self.secrets.clear();
            }
            _ => {}
        }
    }

    fn refresh_identities(&mut self) {
        if let Some(Response::Identities(ids)) = self.req(Request::ListIdentities) {
            self.identities = ids;
            self.isel = self.isel.min(self.identities.len().saturating_sub(1));
        }
    }

    fn refresh_acl(&mut self) {
        let group = self.acl_group.clone();
        match self.req(Request::GroupAcl { group }) {
            Some(Response::Acl(entries)) => {
                self.acl = entries;
                self.asel = self.asel.min(self.acl.len().saturating_sub(1));
            }
            Some(Response::Denied) => {
                self.status = "denied: group admin required for ACL".into();
                self.mode = Mode::Normal;
            }
            _ => {}
        }
    }

    // ---- key handling ----

    fn on_key(&mut self, key: KeyEvent) {
        match &self.mode {
            Mode::Normal => self.on_key_normal(key),
            Mode::Help | Mode::ViewSecret { .. } => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => self.mode = Mode::Normal,
                _ => {}
            },
            Mode::Confirm(_) => self.on_key_confirm(key),
            Mode::Form(_) => self.on_key_form(key),
            Mode::Identities => self.on_key_identities(key),
            Mode::Acl => self.on_key_acl(key),
            Mode::GrantPicker => self.on_key_grant_picker(key),
        }
    }

    fn on_key_normal(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => self.mode = Mode::Help,
            KeyCode::Tab | KeyCode::Left | KeyCode::Right | KeyCode::Char('h' | 'l') => {
                self.focus = match self.focus {
                    Focus::Groups => Focus::Secrets,
                    Focus::Secrets => Focus::Groups,
                };
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Char('r') => {
                self.refresh_groups();
                self.refresh_secrets();
                self.status = "refreshed".into();
            }
            KeyCode::Char('I') => {
                if self.service_admin {
                    self.refresh_identities();
                    self.mode = Mode::Identities;
                } else {
                    self.status = "identities: service admin only".into();
                }
            }
            KeyCode::Char('n') => match self.focus {
                Focus::Groups => {
                    if self.service_admin {
                        self.mode =
                            Mode::Form(Form::new(FormKind::NewGroup, "new group", &[("name", "")]));
                    } else {
                        self.status = "create group: service admin only".into();
                    }
                }
                Focus::Secrets => {
                    if self.selected_group().is_some() {
                        self.mode = Mode::Form(Form::new(
                            FormKind::NewSecret,
                            "new secret",
                            &[("name", ""), ("value", "")],
                        ));
                    }
                }
            },
            KeyCode::Char('a') => {
                if let Some(group) = self.selected_group().map(|g| g.name.clone()) {
                    self.acl_group = group;
                    self.mode = Mode::Acl;
                    self.refresh_acl();
                }
            }
            KeyCode::Char('R') => {
                if let Some(group) = self.selected_group().map(|g| g.name.clone()) {
                    self.mode = Mode::Confirm(ConfirmAction::RotateDek { group });
                }
            }
            KeyCode::Enter | KeyCode::Char('v') if self.focus == Focus::Secrets => {
                self.view_selected_secret();
            }
            KeyCode::Enter if self.focus == Focus::Groups => self.refresh_secrets(),
            KeyCode::Char('e') if self.focus == Focus::Secrets => self.edit_selected_secret(),
            KeyCode::Char('d') if self.focus == Focus::Secrets => {
                if let Some((name, version)) = self.secrets.get(self.ssel).cloned() {
                    self.mode = Mode::Confirm(ConfirmAction::DeleteSecret { name, version });
                }
            }
            _ => {}
        }
    }

    fn move_selection(&mut self, delta: i64) {
        let (sel, len) = match self.focus {
            Focus::Groups => (&mut self.gsel, self.groups.len()),
            Focus::Secrets => (&mut self.ssel, self.secrets.len()),
        };
        if len == 0 {
            return;
        }
        *sel = (*sel as i64 + delta).rem_euclid(len as i64) as usize;
        if self.focus == Focus::Groups {
            self.ssel = 0;
            self.refresh_secrets();
        }
    }

    fn view_selected_secret(&mut self) {
        let (Some(group), Some((name, _))) = (
            self.selected_group().map(|g| g.name.clone()),
            self.secrets.get(self.ssel).cloned(),
        ) else {
            return;
        };
        match self.req(Request::Get {
            group,
            name: name.clone(),
        }) {
            Some(Response::Secret { value, version }) => {
                self.mode = Mode::ViewSecret {
                    name,
                    version,
                    value: String::from_utf8_lossy(&value).into_owned(),
                };
            }
            Some(response) => self.show_response(&response),
            None => {}
        }
    }

    fn edit_selected_secret(&mut self) {
        let (Some(group), Some((name, _))) = (
            self.selected_group().map(|g| g.name.clone()),
            self.secrets.get(self.ssel).cloned(),
        ) else {
            return;
        };
        match self.req(Request::Get {
            group,
            name: name.clone(),
        }) {
            Some(Response::Secret { value, version }) => {
                let current = String::from_utf8_lossy(&value).into_owned();
                self.mode = Mode::Form(Form::new(
                    FormKind::EditSecret {
                        name: name.clone(),
                        expected_version: version,
                    },
                    &format!("edit secret '{name}' (v{version})"),
                    &[("value", current.as_str())],
                ));
            }
            Some(response) => self.show_response(&response),
            None => {}
        }
    }

    fn on_key_confirm(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Enter => {
                let Mode::Confirm(action) = std::mem::replace(&mut self.mode, Mode::Normal) else {
                    return;
                };
                match action {
                    ConfirmAction::DeleteSecret { name, version } => {
                        let Some(group) = self.selected_group().map(|g| g.name.clone()) else {
                            return;
                        };
                        if let Some(response) = self.req(Request::Delete {
                            group,
                            name,
                            expected_version: version,
                        }) {
                            self.show_response(&response);
                        }
                        self.refresh_secrets();
                    }
                    ConfirmAction::RemoveIdentity { name } => {
                        if let Some(response) = self.req(Request::RemoveIdentity { name }) {
                            self.show_response(&response);
                        }
                        self.refresh_identities();
                        self.mode = Mode::Identities;
                    }
                    ConfirmAction::RotateDek { group } => {
                        if let Some(response) = self.req(Request::RotateDek { group }) {
                            match response {
                                Response::Ok => self.status = "DEK rotated".into(),
                                other => self.show_response(&other),
                            }
                        }
                    }
                    ConfirmAction::SetServiceAdmin {
                        name,
                        service_admin,
                    } => {
                        if let Some(response) = self.req(Request::SetServiceAdmin {
                            name,
                            service_admin,
                        }) {
                            self.show_response(&response);
                        }
                        self.refresh_identities();
                        self.mode = Mode::Identities;
                    }
                }
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.mode = match self.mode {
                    Mode::Confirm(
                        ConfirmAction::RemoveIdentity { .. }
                        | ConfirmAction::SetServiceAdmin { .. },
                    ) => Mode::Identities,
                    _ => Mode::Normal,
                }
            }
            _ => {}
        }
    }

    fn on_key_form(&mut self, key: KeyEvent) {
        let Mode::Form(form) = &mut self.mode else {
            return;
        };
        match key.code {
            KeyCode::Esc => {
                self.mode = match form.kind {
                    FormKind::AddIdentity => Mode::Identities,
                    FormKind::GrantEntry => Mode::Acl,
                    _ => Mode::Normal,
                }
            }
            KeyCode::Tab | KeyCode::Down => form.focus = (form.focus + 1) % form.fields.len(),
            KeyCode::Up => {
                form.focus = (form.focus + form.fields.len() - 1) % form.fields.len();
            }
            KeyCode::Backspace => {
                form.fields[form.focus].1.pop();
            }
            KeyCode::Char(c) => form.fields[form.focus].1.push(c),
            KeyCode::Enter => {
                if form.focus + 1 < form.fields.len() {
                    form.focus += 1;
                } else {
                    let Mode::Form(form) = std::mem::replace(&mut self.mode, Mode::Normal) else {
                        return;
                    };
                    self.submit_form(form);
                }
            }
            _ => {}
        }
    }

    fn submit_form(&mut self, form: Form) {
        let value = |i: usize| form.fields[i].1.clone();
        match form.kind {
            FormKind::NewGroup => {
                let name = value(0);
                if name.is_empty() {
                    self.status = "group name must not be empty".into();
                    return;
                }
                if let Some(response) = self.req(Request::CreateGroup { name }) {
                    self.show_response(&response);
                }
                self.refresh_groups();
                self.refresh_secrets();
            }
            FormKind::NewSecret => {
                let (name, secret_value) = (value(0), value(1));
                if name.is_empty() {
                    self.status = "secret name must not be empty".into();
                    return;
                }
                let Some(group) = self.selected_group().map(|g| g.name.clone()) else {
                    return;
                };
                if let Some(response) = self.req(Request::Put {
                    group,
                    name,
                    value: secret_value.into_bytes(),
                    expected_version: 0,
                }) {
                    self.show_response(&response);
                }
                self.refresh_secrets();
            }
            FormKind::EditSecret {
                name,
                expected_version,
            } => {
                let Some(group) = self.selected_group().map(|g| g.name.clone()) else {
                    return;
                };
                if let Some(response) = self.req(Request::Put {
                    group,
                    name,
                    value: value(0).into_bytes(),
                    expected_version,
                }) {
                    self.show_response(&response);
                }
                self.refresh_secrets();
            }
            FormKind::AddIdentity => {
                let (name, id, admin_flag) = (value(0), value(1), value(2));
                if name.is_empty() || id.is_empty() {
                    self.status = "name and endpoint id are required".into();
                    self.mode = Mode::Identities;
                    return;
                }
                if let Some(response) = self.req(Request::AddIdentity {
                    name,
                    endpoint_id: id,
                    service_admin: admin_flag.trim().eq_ignore_ascii_case("y"),
                }) {
                    self.show_response(&response);
                }
                self.refresh_identities();
                self.mode = Mode::Identities;
            }
            FormKind::GrantEntry => {
                let (identity, perms_text) = (value(0), value(1));
                let perms = match parse_perms(&perms_text) {
                    Ok(perms) => perms,
                    Err(err) => {
                        self.status = err.to_string();
                        self.mode = Mode::Acl;
                        return;
                    }
                };
                if let Some(response) = self.req(Request::Grant {
                    group: self.acl_group.clone(),
                    identity,
                    perms,
                }) {
                    self.show_response(&response);
                }
                self.mode = Mode::Acl;
                self.refresh_acl();
                self.refresh_groups();
            }
        }
    }

    fn on_key_identities(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q' | 'I') => self.mode = Mode::Normal,
            KeyCode::Down | KeyCode::Char('j') if !self.identities.is_empty() => {
                self.isel = (self.isel + 1) % self.identities.len();
            }
            KeyCode::Up | KeyCode::Char('k') if !self.identities.is_empty() => {
                self.isel = (self.isel + self.identities.len() - 1) % self.identities.len();
            }
            KeyCode::Char('n') => {
                self.mode = Mode::Form(Form::new(
                    FormKind::AddIdentity,
                    "register identity",
                    &[
                        ("name", ""),
                        ("endpoint id", ""),
                        ("service admin (y/n)", "n"),
                    ],
                ));
            }
            KeyCode::Char('d') => {
                if let Some(identity) = self.identities.get(self.isel) {
                    self.mode = Mode::Confirm(ConfirmAction::RemoveIdentity {
                        name: identity.name.clone(),
                    });
                }
            }
            KeyCode::Char('s') => {
                if let Some(identity) = self.identities.get(self.isel) {
                    self.mode = Mode::Confirm(ConfirmAction::SetServiceAdmin {
                        name: identity.name.clone(),
                        service_admin: !identity.service_admin,
                    });
                }
            }
            _ => {}
        }
    }

    fn on_key_acl(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => self.mode = Mode::Normal,
            KeyCode::Down | KeyCode::Char('j') if !self.acl.is_empty() => {
                self.asel = (self.asel + 1) % self.acl.len();
            }
            KeyCode::Up | KeyCode::Char('k') if !self.acl.is_empty() => {
                self.asel = (self.asel + self.acl.len() - 1) % self.acl.len();
            }
            KeyCode::Char(c @ ('r' | 'w' | 'a' | 'x')) => {
                let Some((identity, perms)) = self.acl.get(self.asel).cloned() else {
                    return;
                };
                let perms = match c {
                    'r' => perms ^ 1,
                    'w' => perms ^ 2,
                    'a' => perms ^ 4,
                    _ => 0,
                };
                if let Some(response) = self.req(Request::Grant {
                    group: self.acl_group.clone(),
                    identity,
                    perms,
                }) {
                    self.show_response(&response);
                }
                self.refresh_acl();
                self.refresh_groups();
            }
            KeyCode::Char('n') => self.open_grant_picker(),
            _ => {}
        }
    }

    fn open_grant_picker(&mut self) {
        match self.req(Request::ListIdentityNames {
            group: self.acl_group.clone(),
        }) {
            Some(Response::IdentityNames(names)) => {
                self.candidates = grant_candidates(names, &self.acl);
                if self.candidates.is_empty() {
                    self.status =
                        format!("every identity already has a grant on '{}'", self.acl_group);
                } else {
                    self.csel = 0;
                    self.mode = Mode::GrantPicker;
                }
            }
            // Server predates ListIdentityNames (or denied it): fall back
            // to typing the name.
            Some(_) => self.open_grant_form(""),
            None => {}
        }
    }

    fn open_grant_form(&mut self, identity: &str) {
        let mut form = Form::new(
            FormKind::GrantEntry,
            &format!("grant on '{}'", self.acl_group),
            &[("identity", identity), ("perms (r/rw/rwa/none)", "r")],
        );
        if !identity.is_empty() {
            form.focus = 1; // identity picked; jump straight to perms
        }
        self.mode = Mode::Form(form);
    }

    fn on_key_grant_picker(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => self.mode = Mode::Acl,
            KeyCode::Down | KeyCode::Char('j') if !self.candidates.is_empty() => {
                self.csel = (self.csel + 1) % self.candidates.len();
            }
            KeyCode::Up | KeyCode::Char('k') if !self.candidates.is_empty() => {
                self.csel = (self.csel + self.candidates.len() - 1) % self.candidates.len();
            }
            KeyCode::Enter => {
                if let Some(identity) = self.candidates.get(self.csel).cloned() {
                    self.open_grant_form(&identity);
                }
            }
            _ => {}
        }
    }

    fn show_response(&mut self, response: &Response) {
        self.status = match response {
            Response::Ok => "ok".into(),
            Response::Version { version } => format!("saved as v{version}"),
            Response::VersionConflict { current } => {
                format!("version conflict: current is v{current} — refresh and retry")
            }
            Response::Denied => "denied".into(),
            Response::Failed { reason } => format!("failed: {reason}"),
            _ => return,
        };
    }

    // ---- drawing ----

    fn draw(&self, frame: &mut Frame) {
        let [header, body, footer] = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(3),
                Constraint::Length(2),
            ])
            .areas(frame.area());

        self.draw_header(frame, header);
        if matches!(self.mode, Mode::Identities)
            || matches!(&self.mode, Mode::Form(f) if matches!(f.kind, FormKind::AddIdentity))
            || matches!(
                self.mode,
                Mode::Confirm(
                    ConfirmAction::RemoveIdentity { .. } | ConfirmAction::SetServiceAdmin { .. }
                )
            )
        {
            self.draw_identities(frame, body);
        } else {
            self.draw_panes(frame, body);
        }
        self.draw_footer(frame, footer);

        match &self.mode {
            Mode::Help => self.draw_help(frame),
            Mode::ViewSecret {
                name,
                version,
                value,
            } => self.draw_view_secret(frame, name, *version, value),
            Mode::Form(form) => self.draw_form(frame, form),
            Mode::Confirm(action) => self.draw_confirm(frame, action),
            Mode::Acl => self.draw_acl(frame),
            Mode::GrantPicker => self.draw_grant_picker(frame),
            _ => {}
        }
    }

    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let role = if self.service_admin {
            Span::styled(" service admin ", Style::new().fg(Color::Black).bg(ACCENT))
        } else {
            Span::styled(" user ", Style::new().fg(Color::Black).bg(Color::Gray))
        };
        let id_short: String = self.my_id.chars().take(10).collect();
        let line = Line::from(vec![
            Span::styled(
                " secret-bunker ",
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            role,
            Span::styled(format!("  {id_short}…"), Style::new().fg(DIM)),
        ]);
        frame.render_widget(Paragraph::new(line), area);
    }

    fn draw_panes(&self, frame: &mut Frame, area: Rect) {
        let [left, right] = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(32), Constraint::Percentage(68)])
            .areas(area);

        let pane = |title: &str, focused: bool| {
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {title} "))
                .border_style(if focused {
                    Style::new().fg(ACCENT)
                } else {
                    Style::new().fg(DIM)
                })
        };

        let group_items: Vec<ListItem> = self
            .groups
            .iter()
            .map(|g| {
                ListItem::new(Line::from(vec![
                    Span::raw(format!("{:<20}", g.name)),
                    Span::styled(format!("[{}]", perms_str(g.perms)), Style::new().fg(DIM)),
                ]))
            })
            .collect();
        let mut gstate = ListState::default();
        gstate.select((!self.groups.is_empty()).then_some(self.gsel));
        frame.render_stateful_widget(
            List::new(group_items)
                .block(pane("groups", self.focus == Focus::Groups))
                .highlight_style(Style::new().bg(ACCENT).fg(Color::Black)),
            left,
            &mut gstate,
        );

        let secret_items: Vec<ListItem> = self
            .secrets
            .iter()
            .map(|(name, version)| {
                ListItem::new(Line::from(vec![
                    Span::raw(format!("{name:<32}")),
                    Span::styled(format!("v{version}"), Style::new().fg(DIM)),
                ]))
            })
            .collect();
        let title = match self.selected_group() {
            Some(group) => format!("secrets in {}", group.name),
            None => "secrets".to_string(),
        };
        let mut sstate = ListState::default();
        sstate.select((!self.secrets.is_empty()).then_some(self.ssel));
        frame.render_stateful_widget(
            List::new(secret_items)
                .block(pane(&title, self.focus == Focus::Secrets))
                .highlight_style(Style::new().bg(ACCENT).fg(Color::Black)),
            right,
            &mut sstate,
        );
    }

    fn draw_identities(&self, frame: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .identities
            .iter()
            .map(|identity| {
                let id_short: String = identity.endpoint_id.chars().take(16).collect();
                let mut spans = vec![
                    Span::raw(format!("{:<20}", identity.name)),
                    Span::styled(format!("{id_short}…  "), Style::new().fg(DIM)),
                ];
                if identity.service_admin {
                    spans.push(Span::styled("service-admin", Style::new().fg(ACCENT)));
                }
                ListItem::new(Line::from(spans))
            })
            .collect();
        let mut state = ListState::default();
        state.select((!self.identities.is_empty()).then_some(self.isel));
        frame.render_stateful_widget(
            List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" identities ")
                        .border_style(Style::new().fg(ACCENT)),
                )
                .highlight_style(Style::new().bg(ACCENT).fg(Color::Black)),
            area,
            &mut state,
        );
    }

    fn draw_footer(&self, frame: &mut Frame, area: Rect) {
        let hints = match &self.mode {
            Mode::Normal => match self.focus {
                Focus::Groups => {
                    "tab panes  j/k move  n new-group  a acl  R rotate-dek  I identities  r refresh  ? help  q quit"
                }
                Focus::Secrets => {
                    "tab panes  j/k move  enter view  n new  e edit  d delete  r refresh  ? help  q quit"
                }
            },
            Mode::Identities => "j/k move  n register  s toggle service-admin  d remove  esc back",
            Mode::Acl => "j/k move  r/w/a toggle perm  x revoke  n add grant  esc back",
            Mode::GrantPicker => "j/k move  enter pick identity  esc back",
            Mode::Form(_) => "enter next/submit  tab field  esc cancel",
            Mode::Confirm(_) => "y confirm  n cancel",
            Mode::Help | Mode::ViewSecret { .. } => "esc close",
        };
        let lines = vec![
            Line::from(Span::styled(&*self.status, Style::new().fg(Color::Yellow))),
            Line::from(Span::styled(hints, Style::new().fg(DIM))),
        ];
        frame.render_widget(Paragraph::new(lines), area);
    }

    fn popup(&self, frame: &mut Frame, width: u16, height: u16, title: &str) -> Rect {
        let area = frame.area();
        let rect = Rect {
            x: area.width.saturating_sub(width) / 2,
            y: area.height.saturating_sub(height) / 2,
            width: width.min(area.width),
            height: height.min(area.height),
        };
        frame.render_widget(Clear, rect);
        frame.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {title} "))
                .border_style(Style::new().fg(ACCENT)),
            rect,
        );
        rect.inner(ratatui::layout::Margin {
            horizontal: 2,
            vertical: 1,
        })
    }

    fn draw_help(&self, frame: &mut Frame) {
        let inner = self.popup(frame, 64, 16, "help");
        let text = vec![
            Line::from("groups pane:  n new group   a manage acl   R rotate dek"),
            Line::from("secrets pane: enter view    n new secret   e edit   d delete"),
            Line::from("I identities (service admin): n register, d remove,"),
            Line::from("  s grant/revoke service admin (all-secrets access)"),
            Line::from(""),
            Line::from("acl view: r/w/a toggle permission bits, x revoke,"),
            Line::from("          n grant — pick an identity from the list"),
            Line::from(""),
            Line::from("Permissions: r read, w write (add/update/delete), a admin."),
            Line::from("The server enforces everything; 'denied' means the bunker"),
            Line::from("said no, not the UI."),
            Line::from(""),
            Line::from("q quit, r refresh, tab switch panes"),
        ];
        frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), inner);
    }

    fn draw_view_secret(&self, frame: &mut Frame, name: &str, version: u64, value: &str) {
        let inner = self.popup(frame, 72, 14, &format!("secret {name} (v{version})"));
        frame.render_widget(Paragraph::new(value).wrap(Wrap { trim: false }), inner);
    }

    fn draw_form(&self, frame: &mut Frame, form: &Form) {
        let inner = self.popup(frame, 64, form.fields.len() as u16 + 2, &form.title);
        let lines: Vec<Line> = form
            .fields
            .iter()
            .enumerate()
            .map(|(i, (label, value))| {
                let style = if i == form.focus {
                    Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)
                } else {
                    Style::new()
                };
                let cursor = if i == form.focus { "▏" } else { "" };
                Line::from(vec![
                    Span::styled(format!("{label:>22}: "), style),
                    Span::raw(format!("{value}{cursor}")),
                ])
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), inner);
    }

    fn draw_confirm(&self, frame: &mut Frame, action: &ConfirmAction) {
        let message = match action {
            ConfirmAction::DeleteSecret { name, version } => {
                format!("Delete secret '{name}' (v{version})?")
            }
            ConfirmAction::RemoveIdentity { name } => {
                format!("Remove identity '{name}' and all its grants?")
            }
            ConfirmAction::RotateDek { group } => {
                format!("Rotate the DEK of group '{group}'?")
            }
            ConfirmAction::SetServiceAdmin {
                name,
                service_admin: true,
            } => format!("Make '{name}' a service admin (full access to all secrets)?"),
            ConfirmAction::SetServiceAdmin {
                name,
                service_admin: false,
            } => format!("Revoke service admin from '{name}' (drops access to all secrets)?"),
        };
        let inner = self.popup(frame, message.len() as u16 + 6, 4, "confirm");
        frame.render_widget(
            Paragraph::new(vec![Line::from(message), Line::from("y / n")]),
            inner,
        );
    }

    fn draw_acl(&self, frame: &mut Frame) {
        let inner = self.popup(
            frame,
            48,
            (self.acl.len() as u16 + 3).max(5),
            &format!("acl: {}", self.acl_group),
        );
        let items: Vec<ListItem> = self
            .acl
            .iter()
            .map(|(name, perms)| {
                ListItem::new(Line::from(vec![
                    Span::raw(format!("{name:<24}")),
                    Span::styled(format!("[{}]", perms_str(*perms)), Style::new().fg(DIM)),
                ]))
            })
            .collect();
        let mut state = ListState::default();
        state.select((!self.acl.is_empty()).then_some(self.asel));
        frame.render_stateful_widget(
            List::new(items).highlight_style(Style::new().bg(ACCENT).fg(Color::Black)),
            inner,
            &mut state,
        );
    }

    fn draw_grant_picker(&self, frame: &mut Frame) {
        let inner = self.popup(
            frame,
            48,
            (self.candidates.len() as u16 + 3).max(5),
            &format!("grant on '{}': pick identity", self.acl_group),
        );
        let items: Vec<ListItem> = self
            .candidates
            .iter()
            .map(|name| ListItem::new(Line::from(name.as_str())))
            .collect();
        let mut state = ListState::default();
        state.select((!self.candidates.is_empty()).then_some(self.csel));
        frame.render_stateful_widget(
            List::new(items).highlight_style(Style::new().bg(ACCENT).fg(Color::Black)),
            inner,
            &mut state,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::grant_candidates;

    #[test]
    fn grant_candidates_excludes_existing_acl_members() {
        let names = vec!["admin".to_string(), "bob".to_string(), "carol".to_string()];
        let acl = vec![("admin".to_string(), 7u8), ("carol".to_string(), 1)];
        assert_eq!(grant_candidates(names, &acl), vec!["bob".to_string()]);
    }
}
