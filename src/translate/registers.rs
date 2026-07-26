use fugue_core::il::pcode::Varnode;
use fugue_core::lifter::Language;

use crate::binary::Architecture;

pub(crate) struct RegisterAccess {
    pub csv: String,
    pub register_size: u16,
    pub byte_offset: u64,
    pub size: u16,
}

struct CanonicalRegister {
    offset: u64,
    size: u16,
    csv: String,
}

pub(crate) struct RegisterFile<'a> {
    space: u8,
    language: &'a Language,
    registers: Vec<CanonicalRegister>,
}

impl<'a> RegisterFile<'a> {
    pub(crate) fn build(language: &'a Language, architecture: Architecture) -> Self {
        let mut registers: Vec<CanonicalRegister> = canonical_names(architecture)
            .into_iter()
            .filter_map(|name| {
                let varnode = language.register_by_name(&name)?;
                Some(CanonicalRegister {
                    offset: varnode.offset(),
                    size: varnode.size() as u16,
                    csv: csv_name(architecture, &name),
                })
            })
            .collect();
        registers.sort_by_key(|register| register.offset);
        Self {
            space: language.register_space(),
            language,
            registers,
        }
    }

    pub(crate) fn space(&self) -> u8 {
        self.space
    }

    pub(crate) fn user_operation(&self, id: u16) -> Option<&'static str> {
        self.language.user_op_by_id(id)
    }

    pub(crate) fn resolve(&self, varnode: &Varnode) -> Option<RegisterAccess> {
        let start = varnode.offset();
        let end = start + varnode.size() as u64;
        if let Some(register) = self.registers.iter().find(|register| {
            register.offset <= start && end <= register.offset + register.size as u64
        }) {
            return Some(RegisterAccess {
                csv: register.csv.clone(),
                register_size: register.size,
                byte_offset: start - register.offset,
                size: varnode.size() as u16,
            });
        }
        let name = self.language.register_name(varnode)?;
        Some(RegisterAccess {
            csv: format!("_{}", name.to_lowercase()),
            register_size: varnode.size() as u16,
            byte_offset: 0,
            size: varnode.size() as u16,
        })
    }
}

fn csv_name(architecture: Architecture, name: &str) -> String {
    if architecture == Architecture::AArch64 && name == "x30" {
        return "_lr".to_owned();
    }
    format!("_{}", name.to_lowercase())
}

fn canonical_names(architecture: Architecture) -> Vec<String> {
    let fixed: &[&str] = match architecture {
        Architecture::AArch64 => &["pc", "sp", "NG", "ZR", "CY", "OV"],
        Architecture::X86_64 => &[
            "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "RIP", "CF", "PF", "AF", "ZF",
            "SF", "DF", "OF",
        ],
    };
    let mut names: Vec<String> = fixed.iter().map(|name| (*name).to_owned()).collect();
    match architecture {
        Architecture::AArch64 => names.extend((0..=30).map(|index| format!("x{index}"))),
        Architecture::X86_64 => names.extend((8..=15).map(|index| format!("R{index}"))),
    }
    names
}

#[cfg(test)]
mod test {
    use fugue_core::lifter::resolve_language;

    use super::*;

    fn access(file: &RegisterFile, offset: u64, size: usize) -> (String, u64, u16) {
        let varnode = Varnode {
            space: file.space(),
            offset,
            size: size as u16,
        };
        let access = file.resolve(&varnode).expect("register resolves");
        (access.csv, access.byte_offset, access.size)
    }

    #[test]
    fn x86_64_sub_registers_alias_the_full_register() {
        let language = resolve_language("x86:LE:64").expect("x86-64 language");
        let file = RegisterFile::build(language, Architecture::X86_64);
        let rax = language.register_by_name("RAX").expect("RAX");
        let eax = language.register_by_name("EAX").expect("EAX");
        let ah = language.register_by_name("AH").expect("AH");

        assert_eq!(access(&file, rax.offset(), 8), ("_rax".to_owned(), 0, 8));
        assert_eq!(access(&file, eax.offset(), 4), ("_rax".to_owned(), 0, 4));
        assert_eq!(access(&file, ah.offset(), 1), ("_rax".to_owned(), 1, 1));
    }

    #[test]
    fn aarch64_scratch_registers_fall_back_to_their_own_csv() {
        let language = resolve_language("AARCH64:LE:64:v8A").expect("aarch64 language");
        let file = RegisterFile::build(language, Architecture::AArch64);
        let scratch = Varnode {
            space: file.space(),
            offset: 0x105,
            size: 1,
        };
        let access = file.resolve(&scratch).expect("scratch register resolves");
        assert_eq!(access.csv, "_tmpcy");
        assert_eq!(access.byte_offset, 0);
        assert_eq!(access.register_size, 1);
    }

    #[test]
    fn aarch64_link_register_maps_to_lr() {
        let language = resolve_language("AARCH64:LE:64:v8A").expect("aarch64 language");
        let file = RegisterFile::build(language, Architecture::AArch64);
        let x30 = language.register_by_name("x30").expect("x30");
        let sp = language.register_by_name("sp").expect("sp");
        let pc = language.register_by_name("pc").expect("pc");

        assert_eq!(access(&file, x30.offset(), 8).0, "_lr");
        assert_eq!(access(&file, sp.offset(), 8).0, "_sp");
        assert_eq!(access(&file, pc.offset(), 8).0, "_pc");
    }
}
