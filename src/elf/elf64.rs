use super::elfxx::*;
use super::parser::*;
use crate::field_getter;
use std::convert::TryInto;

type Elf64Addr = u64;
type Elf64Off = u64;
type Elf64Half = u16;
type Elf64Word = u32;
type Elf64Xword = u64;

pub struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: Elf64Half,
    e_machine: Elf64Half,
    e_version: Elf64Word,
    e_entry: Elf64Addr,
    e_phoff: Elf64Off,
    e_shoff: Elf64Off,
    e_flags: Elf64Word,
    e_ehsize: Elf64Half,
    e_phentsize: Elf64Half,
    e_phnum: Elf64Half,
    e_shentsize: Elf64Half,
    e_shnum: Elf64Half,
    e_shstrndx: Elf64Half,
}

pub struct Elf64Phdr {
    p_type: Elf64Word,
    p_flags: Elf64Word,
    p_offset: Elf64Off,
    p_vaddr: Elf64Addr,
    p_paddr: Elf64Addr,
    p_filesz: Elf64Xword,
    p_memsz: Elf64Xword,
    p_align: Elf64Xword,
}

pub struct Elf64Shdr {
    sh_name: Elf64Word,
    sh_type: Elf64Word,
    sh_flags: Elf64Xword,
    sh_addr: Elf64Addr,
    sh_offset: Elf64Off,
    sh_size: Elf64Xword,
    sh_link: Elf64Word,
    sh_info: Elf64Word,
    sh_addralign: Elf64Xword,
    sh_entsize: Elf64Xword,
}

pub struct Elf64;

// All this just to avoid unsafe. This should be improved.
#[rustfmt::skip]
impl ElfHeader for Elf64Ehdr {
    fn describe() -> &'static str {
        "file header"
    }

    fn from_le_bytes(buf: &[u8]) -> Result<Elf64Ehdr, ReadErr> {
        Ok(Elf64Ehdr {
            e_ident:     buf[0..16].try_into()?,
            e_type:      Elf64Half::from_le_bytes(buf[16..18].try_into()?),
            e_machine:   Elf64Half::from_le_bytes(buf[18..20].try_into()?),
            e_version:   Elf64Word::from_le_bytes(buf[20..24].try_into()?),
            e_entry:     Elf64Addr::from_le_bytes(buf[24..32].try_into()?),
            e_phoff:     Elf64Off:: from_le_bytes(buf[32..40].try_into()?),
            e_shoff:     Elf64Off:: from_le_bytes(buf[40..48].try_into()?),
            e_flags:     Elf64Word::from_le_bytes(buf[48..52].try_into()?),
            e_ehsize:    Elf64Half::from_le_bytes(buf[52..54].try_into()?),
            e_phentsize: Elf64Half::from_le_bytes(buf[54..56].try_into()?),
            e_phnum:     Elf64Half::from_le_bytes(buf[56..58].try_into()?),
            e_shentsize: Elf64Half::from_le_bytes(buf[58..60].try_into()?),
            e_shnum:     Elf64Half::from_le_bytes(buf[60..62].try_into()?),
            e_shstrndx:  Elf64Half::from_le_bytes(buf[62..64].try_into()?),
        })
    }

    fn from_be_bytes(buf: &[u8]) -> Result<Elf64Ehdr, ReadErr> {
        Ok(Elf64Ehdr {
            e_ident:     buf[0..16].try_into()?,
            e_type:      Elf64Half::from_be_bytes(buf[16..18].try_into()?),
            e_machine:   Elf64Half::from_be_bytes(buf[18..20].try_into()?),
            e_version:   Elf64Word::from_be_bytes(buf[20..24].try_into()?),
            e_entry:     Elf64Addr::from_be_bytes(buf[24..32].try_into()?),
            e_phoff:     Elf64Off:: from_be_bytes(buf[32..40].try_into()?),
            e_shoff:     Elf64Off:: from_be_bytes(buf[40..48].try_into()?),
            e_flags:     Elf64Word::from_be_bytes(buf[48..52].try_into()?),
            e_ehsize:    Elf64Half::from_be_bytes(buf[52..54].try_into()?),
            e_phentsize: Elf64Half::from_be_bytes(buf[54..56].try_into()?),
            e_phnum:     Elf64Half::from_be_bytes(buf[56..58].try_into()?),
            e_shentsize: Elf64Half::from_be_bytes(buf[58..60].try_into()?),
            e_shnum:     Elf64Half::from_be_bytes(buf[60..62].try_into()?),
            e_shstrndx:  Elf64Half::from_be_bytes(buf[62..64].try_into()?),
        })
    }
}

#[rustfmt::skip]
impl ElfHeader for Elf64Phdr {
    fn describe() -> &'static str {
        "program header"
    }

    fn from_le_bytes(buf: &[u8]) -> Result<Elf64Phdr, ReadErr> {
        Ok(Elf64Phdr {
            p_type:   Elf64Word:: from_le_bytes(buf[ 0.. 4].try_into()?),
            p_flags:  Elf64Word:: from_le_bytes(buf[ 4.. 8].try_into()?),
            p_offset: Elf64Off::  from_le_bytes(buf[ 8..16].try_into()?),
            p_vaddr:  Elf64Addr:: from_le_bytes(buf[16..24].try_into()?),
            p_paddr:  Elf64Addr:: from_le_bytes(buf[24..32].try_into()?),
            p_filesz: Elf64Xword::from_le_bytes(buf[32..40].try_into()?),
            p_memsz:  Elf64Xword::from_le_bytes(buf[40..48].try_into()?),
            p_align:  Elf64Xword::from_le_bytes(buf[48..56].try_into()?),
        })
    }

    fn from_be_bytes(buf: &[u8]) -> Result<Elf64Phdr, ReadErr> {
        Ok(Elf64Phdr {
            p_type:   Elf64Word:: from_be_bytes(buf[ 0.. 4].try_into()?),
            p_flags:  Elf64Word:: from_be_bytes(buf[ 4.. 8].try_into()?),
            p_offset: Elf64Off::  from_be_bytes(buf[ 8..16].try_into()?),
            p_vaddr:  Elf64Addr:: from_be_bytes(buf[16..24].try_into()?),
            p_paddr:  Elf64Addr:: from_be_bytes(buf[24..32].try_into()?),
            p_filesz: Elf64Xword::from_be_bytes(buf[32..40].try_into()?),
            p_memsz:  Elf64Xword::from_be_bytes(buf[40..48].try_into()?),
            p_align:  Elf64Xword::from_be_bytes(buf[48..56].try_into()?),
        })
    }
}

#[rustfmt::skip]
impl ElfHeader for Elf64Shdr {
    fn describe() -> &'static str {
        "section header"
    }

    fn from_le_bytes(buf: &[u8]) -> Result<Elf64Shdr, ReadErr> {
        Ok(Elf64Shdr {
            sh_name:      Elf64Word:: from_le_bytes(buf[ 0.. 4].try_into()?),
            sh_type:      Elf64Word:: from_le_bytes(buf[ 4.. 8].try_into()?),
            sh_flags:     Elf64Xword::from_le_bytes(buf[ 8..16].try_into()?),
            sh_addr:      Elf64Addr:: from_le_bytes(buf[16..24].try_into()?),
            sh_offset:    Elf64Off::  from_le_bytes(buf[24..32].try_into()?),
            sh_size:      Elf64Xword::from_le_bytes(buf[32..40].try_into()?),
            sh_link:      Elf64Word:: from_le_bytes(buf[40..44].try_into()?),
            sh_info:      Elf64Word:: from_le_bytes(buf[44..48].try_into()?),
            sh_addralign: Elf64Xword::from_le_bytes(buf[48..56].try_into()?),
            sh_entsize:   Elf64Xword::from_le_bytes(buf[56..64].try_into()?),
        })
    }

    fn from_be_bytes(buf: &[u8]) -> Result<Elf64Shdr, ReadErr> {
        Ok(Elf64Shdr {
            sh_name:      Elf64Word:: from_be_bytes(buf[ 0.. 4].try_into()?),
            sh_type:      Elf64Word:: from_be_bytes(buf[ 4.. 8].try_into()?),
            sh_flags:     Elf64Xword::from_be_bytes(buf[ 8..16].try_into()?),
            sh_addr:      Elf64Addr:: from_be_bytes(buf[16..24].try_into()?),
            sh_offset:    Elf64Off::  from_be_bytes(buf[24..32].try_into()?),
            sh_size:      Elf64Xword::from_be_bytes(buf[32..40].try_into()?),
            sh_link:      Elf64Word:: from_be_bytes(buf[40..44].try_into()?),
            sh_info:      Elf64Word:: from_be_bytes(buf[44..48].try_into()?),
            sh_addralign: Elf64Xword::from_be_bytes(buf[48..56].try_into()?),
            sh_entsize:   Elf64Xword::from_be_bytes(buf[56..64].try_into()?),
        })
    }
}

impl ElfXXEhdr for Elf64Ehdr {
    fn e_ident(&self) -> [u8; 16] {
        self.e_ident
    }
    field_getter!(e_type);
    field_getter!(e_machine);
    field_getter!(e_version);
    field_getter!(e_entry);
    field_getter!(e_phoff);
    field_getter!(e_shoff);
    field_getter!(e_flags);
    field_getter!(e_ehsize);
    field_getter!(e_phentsize);
    field_getter!(e_phnum);
    field_getter!(e_shentsize);
    field_getter!(e_shnum);
    field_getter!(e_shstrndx);
}

impl ElfXXPhdr for Elf64Phdr {
    field_getter!(p_type);
    field_getter!(p_flags);
    field_getter!(p_offset);
    field_getter!(p_vaddr);
    field_getter!(p_paddr);
    field_getter!(p_filesz);
    field_getter!(p_memsz);
    field_getter!(p_align);
}

impl ElfXXShdr for Elf64Shdr {
    field_getter!(sh_name);
    field_getter!(sh_type);
    field_getter!(sh_flags);
    field_getter!(sh_addr);
    field_getter!(sh_offset);
    field_getter!(sh_size);
    field_getter!(sh_link);
    field_getter!(sh_info);
    field_getter!(sh_addralign);
    field_getter!(sh_entsize);
}

#[rustfmt::skip]
impl ElfXX<Elf64Ehdr, Elf64Phdr, Elf64Shdr> for Elf64 {
    fn add_ehdr_ranges(ehdr: &Elf64Ehdr, ranges: &mut Ranges) {
        ranges.add_range(0,  ehdr.e_ehsize as usize, RangeType::FileHeader);
        ranges.add_range(16, 2, RangeType::HeaderField("e_type"));
        ranges.add_range(18, 2, RangeType::HeaderField("e_machine"));
        ranges.add_range(20, 4, RangeType::HeaderField("e_version"));
        ranges.add_range(24, 8, RangeType::HeaderField("e_entry"));
        ranges.add_range(32, 8, RangeType::HeaderField("e_phoff"));
        ranges.add_range(40, 8, RangeType::HeaderField("e_shoff"));
        ranges.add_range(48, 4, RangeType::HeaderField("e_flags"));
        ranges.add_range(52, 2, RangeType::HeaderField("e_ehsize"));
        ranges.add_range(54, 2, RangeType::HeaderField("e_phentsize"));
        ranges.add_range(56, 2, RangeType::HeaderField("e_phnum"));
        ranges.add_range(58, 2, RangeType::HeaderField("e_shentsize"));
        ranges.add_range(60, 2, RangeType::HeaderField("e_shnum"));
        ranges.add_range(62, 2, RangeType::HeaderField("e_shstrndx"));
    }

    fn add_phdr_ranges(start: usize, ranges: &mut Ranges) {
        ranges.add_range(start,      4, RangeType::PhdrField("p_type"));
        ranges.add_range(start +  4, 4, RangeType::PhdrField("p_flags"));
        ranges.add_range(start +  8, 8, RangeType::PhdrField("p_offset"));
        ranges.add_range(start + 16, 8, RangeType::PhdrField("p_vaddr"));
        ranges.add_range(start + 24, 8, RangeType::PhdrField("p_paddr"));
        ranges.add_range(start + 32, 8, RangeType::PhdrField("p_filesz"));
        ranges.add_range(start + 40, 8, RangeType::PhdrField("p_memsz"));
        ranges.add_range(start + 48, 8, RangeType::PhdrField("p_align"));
    }

    fn add_shdr_ranges(start: usize, ranges: &mut Ranges) {
        ranges.add_range(start,      4, RangeType::ShdrField("sh_name"));
        ranges.add_range(start +  4, 4, RangeType::ShdrField("sh_type"));
        ranges.add_range(start +  8, 8, RangeType::ShdrField("sh_flags"));
        ranges.add_range(start + 16, 8, RangeType::ShdrField("sh_addr"));
        ranges.add_range(start + 24, 8, RangeType::ShdrField("sh_offset"));
        ranges.add_range(start + 32, 8, RangeType::ShdrField("sh_size"));
        ranges.add_range(start + 40, 4, RangeType::ShdrField("sh_link"));
        ranges.add_range(start + 44, 4, RangeType::ShdrField("sh_info"));
        ranges.add_range(start + 48, 8, RangeType::ShdrField("sh_addralign"));
        ranges.add_range(start + 56, 8, RangeType::ShdrField("sh_entsize"));
    }
}
