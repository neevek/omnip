use std::ascii::AsciiExt;

use log::info;
use regex::Regex;

type FnMatch = Box<dyn Fn(&str) -> bool>; // arg is net address in host[:port] format

pub struct ProxyRule {
    str_rule: String,
    fn_matches: FnMatch,
    match_count: usize,
}

impl ProxyRule {
    pub fn new(str_rule: &str, fn_matches: FnMatch) -> Self {
        ProxyRule {
            str_rule: str_rule.to_string(),
            fn_matches,
            match_count: 0,
        }
    }

    pub fn is_same_rule(&self, str_rule: &str) -> bool {
        self.str_rule == str_rule
    }

    pub fn matches(&self, host: &str, port: u16) -> bool {
        true
    }
}

pub struct ProxyRuleManager {}

impl ProxyRuleManager {
    pub fn add_rule(rule: &str) -> bool {
        true
    }

    pub fn parse(rule: &str) -> Option<FnMatch> {
        if rule.is_empty() {
            return None;
        }

        let rule_len = rule.len();
        let bytes = rule.as_bytes();

        if rule_len > 2 && bytes[0] == '/' as u8 || bytes[rule.len() - 1] == '/' as u8 {
            let re = Regex::new(&rule[1..rule_len - 1]).ok()?;
            return Some(Box::new(move |addr| re.is_match(addr)));
        }

        let ch = bytes[0].to_ascii_lowercase() as char;
        if ch != '|' && ch != '.' && (ch < '0' || ch > '9') && (ch < 'a' || ch > 'z') {
            return None;
        }

        let mut rule = rule;

        // matches against domain
        if rule.starts_with("||") {
            rule = &rule[2..];
        } else if rule.starts_with("|https://") {
            rule = &rule[9..];
        } else if rule.starts_with("|http://") {
            rule = &rule[8..];
        }

        if rule.starts_with(".") {
            rule = &rule[1..];
        }
        let rule_copy = rule.to_string();
        Some(Box::new(move |addr| addr.starts_with(rule_copy.as_str())))
    }
}
