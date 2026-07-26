use std::collections::BTreeMap;
use std::ops::Range;

use crate::binary::Address;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    CabiArgument {
        definition: String,
        index: u64,
    },
    Field {
        definition: String,
        index: u64,
    },
    Function(Address),
    Instruction {
        function: Address,
        basic_block: Address,
        address: Address,
    },
    LocalVariable {
        function: Address,
        index: u64,
    },
    Macro(String),
    Primitive(String),
    ReturnValue(String),
    Segment(Address),
    TypeDefinition(String),
    Unknown(String),
}

impl Location {
    fn parse(path: &str) -> Self {
        let mut parts = path.trim_start_matches('/').split('/');
        let recognised = match parts.next() {
            Some("instruction") => {
                match (
                    address(parts.next()),
                    address(parts.next()),
                    address(parts.next()),
                ) {
                    (Some(function), Some(basic_block), Some(address)) => Some(Self::Instruction {
                        function,
                        basic_block,
                        address,
                    }),
                    _ => None,
                }
            }
            Some("function") => address(parts.next()).map(Self::Function),
            Some("local-variable") => match (address(parts.next()), index(parts.next())) {
                (Some(function), Some(index)) => Some(Self::LocalVariable { function, index }),
                _ => None,
            },
            Some("cabi-argument") => match (parts.next(), index(parts.next())) {
                (Some(definition), Some(index)) => Some(Self::CabiArgument {
                    definition: definition.to_owned(),
                    index,
                }),
                _ => None,
            },
            Some("field") => match (parts.next(), index(parts.next())) {
                (Some(definition), Some(index)) => Some(Self::Field {
                    definition: definition.to_owned(),
                    index,
                }),
                _ => None,
            },
            Some("return-value") => parts
                .next()
                .map(|value| Self::ReturnValue(value.to_owned())),
            Some("primitive") => parts.next().map(|name| Self::Primitive(name.to_owned())),
            Some("type-definition") => parts
                .next()
                .map(|name| Self::TypeDefinition(name.to_owned())),
            Some("segment") => address(parts.next()).map(Self::Segment),
            Some("macro") => parts.next().map(|name| Self::Macro(name.to_owned())),
            _ => None,
        };
        recognised.unwrap_or_else(|| Self::Unknown(path.to_owned()))
    }

    pub fn instruction_address(&self) -> Option<Address> {
        match self {
            Self::Instruction { address, .. } => Some(*address),
            _ => None,
        }
    }
}

fn address(part: Option<&str>) -> Option<Address> {
    let head = part?.split(':').next()?;
    let value = u64::from_str_radix(head.strip_prefix("0x")?, 16).ok()?;
    Some(Address::new(value))
}

fn index(part: Option<&str>) -> Option<u64> {
    part?.parse().ok()
}

#[derive(Debug, Clone)]
pub struct Token {
    range: Range<usize>,
    token: Option<String>,
    defines: Option<Location>,
    references: Option<Location>,
    context: Option<Location>,
    instruction: Option<Address>,
}

impl Token {
    pub fn range(&self) -> &Range<usize> {
        &self.range
    }

    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    pub fn defines(&self) -> Option<&Location> {
        self.defines.as_ref()
    }

    pub fn references(&self) -> Option<&Location> {
        self.references.as_ref()
    }

    pub fn context(&self) -> Option<&Location> {
        self.context.as_ref()
    }

    pub fn instruction_address(&self) -> Option<Address> {
        self.instruction
    }
}

pub struct Document {
    text: String,
    tokens: Vec<Token>,
}

impl Document {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn tokens(&self) -> &[Token] {
        &self.tokens
    }

    pub fn address_map(&self) -> BTreeMap<Address, Vec<Range<usize>>> {
        let mut map = BTreeMap::<Address, Vec<Range<usize>>>::new();
        for token in &self.tokens {
            if let Some(address) = token.instruction_address() {
                map.entry(address).or_default().push(token.range.clone());
            }
        }
        map
    }

    pub fn address_at(&self, offset: usize) -> Option<Address> {
        self.tokens
            .iter()
            .filter(|token| token.range.contains(&offset))
            .find_map(Token::instruction_address)
    }

    pub fn referenced_functions(&self) -> impl Iterator<Item = Address> + '_ {
        self.tokens
            .iter()
            .filter_map(|token| match token.references {
                Some(Location::Function(address)) => Some(address),
                _ => None,
            })
    }
}

#[derive(Default, Clone)]
struct Element {
    token: Option<String>,
    defines: Option<String>,
    references: Option<String>,
    context: Option<String>,
}

pub(crate) fn strip(ptml: &str) -> String {
    let bytes = ptml.as_bytes();
    let mut text = String::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'<' {
            cursor = ptml[cursor..]
                .find('>')
                .map_or(bytes.len(), |at| cursor + at + 1);
            continue;
        }
        let run_start = cursor;
        while cursor < bytes.len() && bytes[cursor] != b'<' {
            cursor += 1;
        }
        decode_into(&ptml[run_start..cursor], &mut text);
    }
    text
}

pub(crate) fn parse(ptml: &str) -> Document {
    let bytes = ptml.as_bytes();
    let mut text = String::new();
    let mut tokens = Vec::new();
    let mut stack: Vec<Element> = Vec::new();

    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'<' {
            let end = ptml[cursor..]
                .find('>')
                .map_or(bytes.len(), |at| cursor + at + 1);
            let inner = &ptml[cursor + 1..end - 1];
            if inner.starts_with('/') {
                stack.pop();
            } else {
                stack.push(Element {
                    token: attribute(inner, "data-token"),
                    defines: attribute(inner, "data-location-definition"),
                    references: attribute(inner, "data-location-references"),
                    context: attribute(inner, "data-action-context-location"),
                });
            }
            cursor = end;
            continue;
        }

        let run_start = cursor;
        while cursor < bytes.len() && bytes[cursor] != b'<' {
            cursor += 1;
        }
        let start = text.len();
        decode_into(&ptml[run_start..cursor], &mut text);
        let end = text.len();
        if end == start {
            continue;
        }
        if let Some(token) = build_token(&stack, start..end) {
            tokens.push(token);
        }
    }

    Document { text, tokens }
}

fn build_token(stack: &[Element], range: Range<usize>) -> Option<Token> {
    let mut token = None;
    let mut defines = None;
    let mut references = None;
    let mut context = None;
    let mut instruction = None;
    for element in stack.iter().rev() {
        token = token.or_else(|| element.token.clone());
        defines = defines.or_else(|| element.defines.clone());
        references = references.or_else(|| element.references.clone());
        if let Some(raw) = &element.context {
            let location = Location::parse(raw);
            if instruction.is_none() {
                instruction = location.instruction_address();
            }
            context = context.or(Some(location));
        }
    }
    if token.is_none() && defines.is_none() && references.is_none() && context.is_none() {
        return None;
    }
    Some(Token {
        range,
        token,
        defines: defines.as_deref().map(Location::parse),
        references: references.as_deref().map(Location::parse),
        context,
        instruction,
    })
}

fn attribute(tag: &str, key: &str) -> Option<String> {
    let mut search = 0;
    while let Some(offset) = tag[search..].find(key) {
        let at = search + offset;
        let after = at + key.len();
        let preceded = at == 0 || tag.as_bytes()[at - 1] == b' ';
        let rest = &tag[after..];
        if preceded
            && let Some(rest) = rest.strip_prefix('=')
            && let Some(quote) = rest.chars().next()
            && (quote == '"' || quote == '\'')
            && let Some(close) = rest[1..].find(quote)
        {
            return Some(rest[1..1 + close].to_owned());
        }
        search = after;
    }
    None
}

fn decode_into(run: &str, text: &mut String) {
    const ENTITIES: [(&str, char); 5] = [
        ("&amp;", '&'),
        ("&lt;", '<'),
        ("&gt;", '>'),
        ("&quot;", '"'),
        ("&apos;", '\''),
    ];
    let mut remaining = run;
    while let Some(offset) = remaining.find('&') {
        text.push_str(&remaining[..offset]);
        let tail = &remaining[offset..];
        match ENTITIES
            .iter()
            .find(|(encoded, _)| tail.starts_with(encoded))
        {
            Some((encoded, decoded)) => {
                text.push(*decoded);
                remaining = &tail[encoded.len()..];
            }
            None => {
                text.push('&');
                remaining = &tail[1..];
            }
        }
    }
    text.push_str(remaining);
}
