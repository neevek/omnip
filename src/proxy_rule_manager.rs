/// some simple rules are supported:
/// example.com
/// .example.com
/// ||example.com
/// @@||example.com
/// @@|example.com
/// %%||example.com
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::{Arc, RwLock};

use log::{debug, info, warn};
use regex::Regex;
use std::net::IpAddr;
use std::str::FromStr;

type FnMatch = Box<dyn Send + Sync + Fn(&str, u16) -> bool>;
const SORT_MATCH_RULES_COUNT_THRESHOLD: usize = 10;
const SORT_MATCH_RULES_INDEX_THRESHOLD: usize = 10;

pub struct ProxyRule {
    str_rule: String,
    fn_matches: FnMatch,
    match_count: RwLock<usize>,
}

pub enum MatchResult {
    Direct,
    Proxy,
    Reject,
}

impl ProxyRule {
    pub fn new(str_rule: &str, fn_matches: FnMatch) -> Self {
        ProxyRule {
            str_rule: str_rule.to_string(),
            fn_matches,
            match_count: RwLock::new(0),
        }
    }

    pub fn is_same_rule(&self, str_rule: &str) -> bool {
        self.str_rule == str_rule
    }

    pub fn matches(&self, host: &str, port: u16) -> bool {
        if self.fn_matches.as_ref()(host, port) {
            *self.match_count.write().unwrap() += 1;
            return true;
        }
        false
    }
}

#[derive(Clone)]
pub struct ProxyRuleManager {
    inner: Arc<RwLock<ProxyRuleManagerInner>>,
}
unsafe impl Send for ProxyRuleManager {}
unsafe impl Sync for ProxyRuleManager {}

pub struct ProxyRuleManagerInner {
    match_rules: Vec<ProxyRule>,
    exception_rules: Vec<ProxyRule>,
    reject_rules: Vec<ProxyRule>,
}

impl ProxyRuleManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(ProxyRuleManagerInner {
                match_rules: Vec::new(),
                exception_rules: Vec::new(),
                reject_rules: Vec::new(),
            })),
        }
    }

    pub fn add_rules_by_file(&mut self, file_path: &str) -> usize {
        let mut count = 0;
        if let Ok(file) = File::open(file_path) {
            BufReader::new(file).lines().for_each(|line| {
                if let Ok(line) = line {
                    if self.add_rule(line.as_str()) {
                        count += 1;
                    }
                }
            });
        }

        info!("added {} rules", count);
        count
    }

    pub fn add_rule(&mut self, rule: &str) -> bool {
        let mut prm = self.inner.write().unwrap();
        if Self::has_rule(&prm.match_rules, rule) {
            warn!("duplicated rule: {}", rule);
            return true;
        }
        if let Some(fn_matches) = Self::parse_proxy_rule(rule) {
            prm.match_rules.push(ProxyRule::new(rule, fn_matches));
            return true;
        }
        if Self::has_rule(&prm.exception_rules, rule) {
            warn!("duplicated exception rule: {}", rule);
            return true;
        }
        if let Some(fn_matches) = Self::parse_exception_rule(rule) {
            prm.exception_rules.push(ProxyRule::new(rule, fn_matches));
            return true;
        }
        if Self::has_rule(&prm.reject_rules, rule) {
            warn!("duplicated reject rule: {}", rule);
            return true;
        }
        if let Some(fn_matches) = Self::parse_reject_rule(rule) {
            prm.reject_rules.push(ProxyRule::new(rule, fn_matches));
            return true;
        }
        false
    }

    pub fn clear_all(&mut self) {
        let mut prm = self.inner.write().unwrap();
        prm.match_rules.clear();
        prm.exception_rules.clear();
    }

    pub fn matches(&mut self, host: &str, port: u16) -> MatchResult {
        let prm = self.inner.read().unwrap();
        let should_rejct = self.do_match(&prm.reject_rules, host, port);
        if should_rejct {
            debug!("rejected! {host}:{port}");
            return MatchResult::Reject;
        }

        let should_proxy = self.do_match(&prm.match_rules, host, port);
        if !should_proxy {
            return MatchResult::Direct;
        }

        let matched_except_rule = self.do_match(&prm.exception_rules, host, port);
        if matched_except_rule {
            MatchResult::Direct
        } else {
            debug!("matched! {host}:{port}");
            MatchResult::Proxy
        }
    }

    pub fn parse_proxy_rule(rule: &str) -> Option<FnMatch> {
        if rule.is_empty() {
            return None;
        }

        // IPv6 may start with "::", but we will simply ignore it here
        if rule.chars().nth(0).unwrap().is_numeric() {
            // Handle CIDR notation first
            if let Some((ip_str, prefix_len)) = rule.split_once('/') {
                if let (Ok(ip), Ok(prefix_len)) =
                    (IpAddr::from_str(ip_str), prefix_len.parse::<u8>())
                {
                    let cidr = IpCidr::new(ip, prefix_len);
                    return Some(Box::new(move |host, _port| {
                        if host.is_empty() || !host.chars().nth(0).unwrap().is_numeric() {
                            return false;
                        }
                        if let Ok(host_ip) = IpAddr::from_str(host) {
                            return cidr.contains(&host_ip);
                        }
                        false
                    }));
                }
            }

            // Handle direct IP addresses
            if let Ok(ip) = IpAddr::from_str(rule) {
                return Some(Box::new(move |host, _port| {
                    if host.is_empty() || !host.chars().nth(0).unwrap().is_numeric() {
                        return false;
                    }
                    if let Ok(host_ip) = IpAddr::from_str(host) {
                        return host_ip == ip;
                    }
                    false
                }));
            }
        }

        let rule_len = rule.len();
        let bytes = rule.as_bytes();

        if rule_len > 2 && bytes[0] == b'/' && bytes[rule.len() - 1] == b'/' {
            let re = Regex::new(&rule[1..rule_len - 1]).ok()?;
            return Some(Box::new(move |host, _port| re.is_match(host)));
        }

        let ch = bytes[0].to_ascii_lowercase() as char;
        if ch != '|' && ch != '.' && !('0'..='9').contains(&ch) && !('a'..='z').contains(&ch) {
            return None;
        }

        let mut rule = rule;
        let mut requires_443_port = false;
        let mut fuzzy_match = false;

        // matches against domain
        if rule.starts_with("||") {
            rule = &rule[2..];
            fuzzy_match = true;
        } else if rule.starts_with('.') {
            rule = &rule[1..];
            fuzzy_match = true;
        } else if rule.starts_with("|https://") {
            rule = &rule[9..];
            requires_443_port = true;
        } else if rule.starts_with("|http://") {
            rule = &rule[8..];
        }

        Some(Self::build_rule(rule, requires_443_port, fuzzy_match))
    }

    pub fn parse_exception_rule(rule: &str) -> Option<FnMatch> {
        if rule.is_empty() || rule.as_bytes()[0] != b'@' {
            return None;
        }

        let mut rule = rule;
        let mut requires_443_port = false;
        let mut fuzzy_match = false;

        // matches against domain
        if rule.starts_with("@@|https://") {
            rule = &rule[11..];
            requires_443_port = true;
        } else if rule.starts_with("@@|http://") {
            rule = &rule[10..];
        } else if rule.starts_with("@@||") {
            rule = &rule[4..];
            fuzzy_match = true;
        }

        Some(Self::build_rule(rule, requires_443_port, fuzzy_match))
    }

    pub fn parse_reject_rule(rule: &str) -> Option<FnMatch> {
        if rule.is_empty() || rule.as_bytes()[0] != b'%' {
            return None;
        }

        let mut rule = rule;
        let mut requires_443_port = false;
        let mut fuzzy_match = false;

        // matches against domain
        if rule.starts_with("%%|https://") {
            rule = &rule[11..];
            requires_443_port = true;
        } else if rule.starts_with("%%|http://") {
            rule = &rule[10..];
        } else if rule.starts_with("%%||") {
            rule = &rule[4..];
            fuzzy_match = true;
        }

        Some(Self::build_rule(rule, requires_443_port, fuzzy_match))
    }

    fn build_rule(rule: &str, requires_443_port: bool, fuzzy_match: bool) -> FnMatch {
        let rule_copy = rule.to_string();
        Box::new(move |host, port| {
            if requires_443_port && port != 443 {
                return false;
            }
            if let Some(pos) = host.find(rule_copy.as_str()) {
                return pos == 0 || (fuzzy_match && host.as_bytes()[pos - 1] == b'.');
            }
            false
        })
    }

    fn has_rule(rules: &[ProxyRule], rule: &str) -> bool {
        rules.iter().any(|r| r.is_same_rule(rule))
    }

    fn do_match(&self, rules: &[ProxyRule], host: &str, port: u16) -> bool {
        rules
            .iter()
            .enumerate()
            .find(|(_, rule)| rule.matches(host, port))
            .map_or(false, |(index, rule)| {
                // sort the rules if it runs with tokio runtime (of course it does)
                if tokio::runtime::Handle::try_current().is_ok() {
                    if index >= SORT_MATCH_RULES_INDEX_THRESHOLD
                        && *rule.match_count.read().unwrap() >= SORT_MATCH_RULES_COUNT_THRESHOLD
                    {
                        let prm = self.clone();
                        tokio::spawn(async move {
                            prm.sort_rules();
                        });
                        info!("sort the rule for: {host}:{port}, current index:{index}");
                    }
                }
                true
            })
    }

    fn sort_rules(&self) {
        let mut prm = self.inner.write().unwrap();
        prm.match_rules.sort_by(|a, b| {
            (*b.match_count.read().unwrap()).cmp(&(*a.match_count.read().unwrap()))
        });
        prm.exception_rules.sort_by(|a, b| {
            (*b.match_count.read().unwrap()).cmp(&(*a.match_count.read().unwrap()))
        });
    }
}

impl Default for ProxyRuleManager {
    fn default() -> Self {
        Self::new()
    }
}

struct IpCidr {
    ip: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    fn new(ip: IpAddr, prefix_len: u8) -> Self {
        Self { ip, prefix_len }
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        match (self.ip, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = !((1u32 << (32 - self.prefix_len)) - 1);
                (u32::from(network) & mask) == (u32::from(*ip) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = !((1u128 << (128 - self.prefix_len)) - 1);
                (u128::from(network) & mask) == (u128::from(*ip) & mask)
            }
            _ => false,
        }
    }
}
