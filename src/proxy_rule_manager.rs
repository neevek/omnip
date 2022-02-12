use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::sync::RwLock;

use log::{debug, info, warn};
use regex::Regex;

type FnMatch = Box<dyn Send + Sync + Fn(&str, u16) -> bool>;
const SORT_MATCH_RULES_COUNT_THRESHOLD: usize = 10;
const SORT_MATCH_RULES_INDEX_THRESHOLD: usize = 10;

pub struct ProxyRule {
    str_rule: String,
    fn_matches: FnMatch,
    match_count: RwLock<usize>,
}

pub struct MatchResult {
    pub matched: bool,
    pub needs_sort_rules: bool,
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

pub struct ProxyRuleManager {
    match_rules: Vec<ProxyRule>,
    exception_rules: Vec<ProxyRule>,
}

impl ProxyRuleManager {
    pub fn new() -> Self {
        ProxyRuleManager {
            match_rules: Vec::new(),
            exception_rules: Vec::new(),
        }
    }

    pub fn add_rules_by_file(&mut self, file_path: &str) -> usize {
        let mut count = 0;
        if let Ok(file) = File::open(file_path) {
            for line in BufReader::new(file).lines() {
                if let Ok(line) = line {
                    if self.add_rule(line.as_str()) {
                        count += 1;
                    }
                }
            }
        }

        info!("added {} rules", count);
        count
    }

    pub fn add_rule(&mut self, rule: &str) -> bool {
        if Self::has_rule(&self.match_rules, rule) {
            warn!("duplicated rule: {}", rule);
            return true;
        }
        if let Some(fn_matches) = Self::parse(rule) {
            self.match_rules.push(ProxyRule::new(rule, fn_matches));
            return true;
        }
        if Self::has_rule(&self.exception_rules, rule) {
            warn!("duplicated exception rule: {}", rule);
            return true;
        }
        if let Some(fn_matches) = Self::parse_exception_rule(rule) {
            self.exception_rules.push(ProxyRule::new(rule, fn_matches));
            return true;
        }
        false
    }

    pub fn clear_all(&mut self) {
        self.match_rules.clear();
        self.exception_rules.clear();
    }

    pub fn matches(&self, host: &str, port: u16) -> MatchResult {
        let result1 = Self::do_match(&self.match_rules, host, port);
        let result2 = Self::do_match(&self.exception_rules, host, port);

        if result1.matched {
            debug!(
                "matched! {}:{}, match_rule:{}, exception_rule:{}",
                host, port, result1.matched, result2.matched
            );
        }

        MatchResult {
            matched: result1.matched && !result2.matched,
            needs_sort_rules: result1.needs_sort_rules || result2.needs_sort_rules,
        }
    }

    pub fn sort_rules(&mut self) {
        self.match_rules.sort_by(|a, b| {
            (*b.match_count.read().unwrap()).cmp(&(*a.match_count.read().unwrap()))
        });
        self.exception_rules.sort_by(|a, b| {
            (*b.match_count.read().unwrap()).cmp(&(*a.match_count.read().unwrap()))
        });
    }

    pub fn parse(rule: &str) -> Option<FnMatch> {
        if rule.is_empty() {
            return None;
        }

        let rule_len = rule.len();
        let bytes = rule.as_bytes();

        if rule_len > 2 && bytes[0] == '/' as u8 && bytes[rule.len() - 1] == '/' as u8 {
            let re = Regex::new(&rule[1..rule_len - 1]).ok()?;
            return Some(Box::new(move |host, _port| re.is_match(host)));
        }

        let ch = bytes[0].to_ascii_lowercase() as char;
        if ch != '|' && ch != '.' && (ch < '0' || ch > '9') && (ch < 'a' || ch > 'z') {
            return None;
        }

        let mut rule = rule;
        let mut requires_443_port = false;
        let mut fuzzy_match = false;

        // matches against domain
        if rule.starts_with("||") {
            rule = &rule[2..];
            fuzzy_match = true;
        } else if rule.starts_with(".") {
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
        if rule.is_empty() || rule.as_bytes()[0] != '@' as u8 {
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

    fn build_rule(rule: &str, requires_443_port: bool, fuzzy_match: bool) -> FnMatch {
        let rule_copy = rule.to_string();
        Box::new(move |host, port| {
            if requires_443_port && port != 443 {
                return false;
            }
            if let Some(pos) = host.find(rule_copy.as_str()) {
                return pos == 0 || (fuzzy_match && host.as_bytes()[pos - 1] == '.' as u8);
            }
            false
        })
    }

    fn has_rule(rules: &Vec<ProxyRule>, rule: &str) -> bool {
        for r in rules {
            if r.is_same_rule(rule) {
                return true;
            }
        }
        false
    }

    fn do_match(rules: &Vec<ProxyRule>, host: &str, port: u16) -> MatchResult {
        let mut needs_sort_rules = false;
        let mut matched = false;
        for (index, rule) in rules.into_iter().enumerate() {
            if rule.matches(host, port) {
                matched = true;
                if index >= SORT_MATCH_RULES_INDEX_THRESHOLD
                    && *rule.match_count.read().unwrap() >= SORT_MATCH_RULES_COUNT_THRESHOLD
                {
                    needs_sort_rules = true;
                }

                break;
            }
        }

        MatchResult {
            matched,
            needs_sort_rules,
        }
    }
}
