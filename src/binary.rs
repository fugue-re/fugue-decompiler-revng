use std::fmt;
use std::path::Path;

use fallible_iterator::FallibleIterator;
use fugue_core::ir::SegmentProperties;
use fugue_core::lifter::{Language, Lifter};
use fugue_core::loader::{Loadable, Loader, Shellcode};
use fugue_core::storage::segments::{DefaultTransientSegmentStorage, SegmentStorage};
use fugue_core::types::AttributeMap;

use crate::error::Error;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Address(u64);

impl Address {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:#x}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Architecture {
    AArch64,
    X86_64,
}

impl Architecture {
    pub(crate) fn revng_name(self) -> &'static str {
        match self {
            Self::AArch64 => "aarch64",
            Self::X86_64 => "x86_64",
        }
    }

    pub(crate) fn tag_id(self) -> u8 {
        match self {
            Self::AArch64 => 1,
            Self::X86_64 => 0,
        }
    }

    pub(crate) fn pc_csv(self) -> &'static str {
        match self {
            Self::AArch64 => "_pc",
            Self::X86_64 => "_rip",
        }
    }

    pub(crate) fn stack_pointer_csv(self) -> &'static str {
        match self {
            Self::AArch64 => "_sp",
            Self::X86_64 => "_rsp",
        }
    }

    pub(crate) fn link_register_csv(self) -> Option<&'static str> {
        match self {
            Self::AArch64 => Some("_lr"),
            Self::X86_64 => None,
        }
    }

    pub(crate) fn minimum_instruction_size(self) -> u8 {
        match self {
            Self::AArch64 => 4,
            Self::X86_64 => 1,
        }
    }

    pub(crate) fn pointer_size(self) -> u64 {
        match self {
            Self::AArch64 | Self::X86_64 => 8,
        }
    }

    pub(crate) fn default_abi(self) -> &'static str {
        match self {
            Self::AArch64 => "AAPCS64",
            Self::X86_64 => "SystemV_x86_64",
        }
    }

    fn language_id(self) -> &'static str {
        match self {
            Self::AArch64 => "AARCH64:LE:64:v8A",
            Self::X86_64 => "x86:LE:64",
        }
    }

    fn from_language(processor: &str, bits: u32) -> Option<Self> {
        match (processor, bits) {
            ("AARCH64", 64) => Some(Self::AArch64),
            ("x86", 64) => Some(Self::X86_64),
            _ => None,
        }
    }
}

pub struct Segment {
    address: Address,
    name: String,
    properties: SegmentProperties,
    size: u64,
}

impl Segment {
    pub fn address(&self) -> Address {
        self.address
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn is_executable(&self) -> bool {
        self.properties.is_executable()
    }

    pub fn is_initialised(&self) -> bool {
        self.properties.is_initialised()
    }

    pub fn is_readable(&self) -> bool {
        self.properties.is_readable()
    }

    pub fn is_writable(&self) -> bool {
        self.properties.is_writable()
    }
}

pub struct FunctionSymbol {
    address: Address,
    name: String,
}

impl FunctionSymbol {
    pub fn address(&self) -> Address {
        self.address
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

pub struct Binary {
    language: &'static Language,
    entry: Option<Address>,
    segments: Vec<Segment>,
    storage: SegmentStorage,
    symbols: Vec<FunctionSymbol>,
}

impl Binary {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::from_loadable(&Loader::from_file(path)?)
    }

    pub fn from_raw(
        bytes: Vec<u8>,
        base: Address,
        architecture: Architecture,
    ) -> Result<Self, Error> {
        Self::from_loadable(&Shellcode::new(
            architecture.language_id(),
            base.value(),
            bytes,
        )?)
    }

    fn from_loadable(loadable: &impl Loadable) -> Result<Self, Error> {
        let language = loadable.architecture().language();
        Architecture::from_language(language.processor(), language.address_bits())
            .ok_or_else(|| Error::unsupported_architecture(language.id().to_owned()))?;
        let entry = loadable
            .entry_point()
            .map(|address| Address::new(address.offset().offset()));

        let mut segments = Vec::new();
        let mut image_segments = loadable.image_segments();
        while let Some(segment) = image_segments.next()? {
            segments.push(Segment {
                address: Address::new(segment.address().offset().offset()),
                name: segment.name().to_owned(),
                properties: segment.properties(),
                size: segment.size(),
            });
        }

        let symbols = loadable
            .image_symbols()
            .map(|table| {
                table
                    .iter()
                    .filter(|(_, entry)| entry.is_function())
                    .map(|(_, entry)| FunctionSymbol {
                        address: Address::new(entry.address().offset().offset()),
                        name: entry.symbol().as_str().to_owned(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut attributes = AttributeMap::new();
        let (storage, _) = SegmentStorage::from_loadable::<DefaultTransientSegmentStorage>(
            loadable,
            &mut attributes,
        )?
        .into_parts();

        Ok(Self {
            language,
            entry,
            segments,
            storage,
            symbols,
        })
    }

    pub fn architecture(&self) -> Architecture {
        Architecture::from_language(self.language.processor(), self.language.address_bits())
            .expect("the architecture was validated when the binary was loaded")
    }

    pub fn entry(&self) -> Option<Address> {
        self.entry
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    pub fn symbols(&self) -> &[FunctionSymbol] {
        &self.symbols
    }

    pub(crate) fn read(&self, address: u64, bytes: &mut [u8]) -> Result<usize, Error> {
        Ok(self.storage.read_bytes(address, bytes)?)
    }

    pub(crate) fn language(&self) -> &'static Language {
        self.language
    }

    pub(crate) fn lifter(&self) -> Lifter {
        Lifter::new(self.language)
    }
}
