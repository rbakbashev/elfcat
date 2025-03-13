use super::elfxx::*;
use super::parser::*;
use std::convert::TryInto;

type Elf32Addr = u32;
type Elf32Half = u16;
type Elf32Off = u32;
type Elf32Word = u32;

pub struct Elf32Ehdr {
    e_ident: [u8; 16],
    e_type: Elf32Half,
    e_machine: Elf32Half,
    e_version: Elf32Word,
    e_entry: Elf32Addr,
    e_phoff: Elf32Off,
    e_shoff: Elf32Off,
    e_flags: Elf32Word,
    e_ehsize: Elf32Half,
    e_phentsize: Elf32Half,
    e_phnum: Elf32Half,
    e_shentsize: Elf32Half,
    e_shnum: Elf32Half,
    e_shstrndx: Elf32Half,
}

pub struct Elf32Phdr {
    p_type: Elf32Word,
    p_offset: Elf32Off,
    p_vaddr: Elf32Addr,
    p_paddr: Elf32Addr,
    p_filesz: Elf32Word,
    p_memsz: Elf32Word,
    p_flags: Elf32Word,
    p_align: Elf32Word,
}

pub struct Elf32Shdr {
    sh_name: Elf32Word,
    sh_type: Elf32Word,
    sh_flags: Elf32Word,
    sh_addr: Elf32Addr,
    sh_offset: Elf32Off,
    sh_size: Elf32Word,
    sh_link: Elf32Word,
    sh_info: Elf32Word,
    sh_addralign: Elf32Word,
    sh_entsize: Elf32Word,
}

pub struct Elf32;

#[rustfmt::skip]
impl ElfHeader for Elf32Ehdr {
    fn describe() -> &'static str {
        "file header"
    }

    fn from_le_bytes(buf: &[u8]) -> Result<Elf32Ehdr, ReadErr> {
        Ok(Elf32Ehdr {
            e_ident:     buf[0..16].try_into()?,
            e_type:      Elf32Half::from_le_bytes(buf[16..18].try_into()?),
            e_machine:   Elf32Half::from_le_bytes(buf[18..20].try_into()?),
            e_version:   Elf32Word::from_le_bytes(buf[20..24].try_into()?),
            e_entry:     Elf32Addr::from_le_bytes(buf[24..28].try_into()?),
            e_phoff:     Elf32Off:: from_le_bytes(buf[28..32].try_into()?),
            e_shoff:     Elf32Off:: from_le_bytes(buf[32..36].try_into()?),
            e_flags:     Elf32Word::from_le_bytes(buf[36..40].try_into()?),
            e_ehsize:    Elf32Half::from_le_bytes(buf[40..42].try_into()?),
            e_phentsize: Elf32Half::from_le_bytes(buf[42..44].try_into()?),
            e_phnum:     Elf32Half::from_le_bytes(buf[44..46].try_into()?),
            e_shentsize: Elf32Half::from_le_bytes(buf[46..48].try_into()?),
            e_shnum:     Elf32Half::from_le_bytes(buf[48..50].try_into()?),
            e_shstrndx:  Elf32Half::from_le_bytes(buf[50..52].try_into()?),
        })
    }

    fn from_be_bytes(buf: &[u8]) -> Result<Elf32Ehdr, ReadErr> {
        Ok(Elf32Ehdr {
            e_ident:     buf[0..16].try_into()?,
            e_type:      Elf32Half::from_be_bytes(buf[16..18].try_into()?),
            e_machine:   Elf32Half::from_be_bytes(buf[18..20].try_into()?),
            e_version:   Elf32Word::from_be_bytes(buf[20..24].try_into()?),
            e_entry:     Elf32Addr::from_be_bytes(buf[24..28].try_into()?),
            e_phoff:     Elf32Off:: from_be_bytes(buf[28..32].try_into()?),
            e_shoff:     Elf32Off:: from_be_bytes(buf[32..36].try_into()?),
            e_flags:     Elf32Word::from_be_bytes(buf[36..40].try_into()?),
            e_ehsize:    Elf32Half::from_be_bytes(buf[40..42].try_into()?),
            e_phentsize: Elf32Half::from_be_bytes(buf[42..44].try_into()?),
            e_phnum:     Elf32Half::from_be_bytes(buf[44..46].try_into()?),
            e_shentsize: Elf32Half::from_be_bytes(buf[46..48].try_into()?),
            e_shnum:     Elf32Half::from_be_bytes(buf[48..50].try_into()?),
            e_shstrndx:  Elf32Half::from_be_bytes(buf[50..52].try_into()?),
        })
    }
}

#[rustfmt::skip]
impl ElfHeader for Elf32Phdr {
    fn describe() -> &'static str {
        "program header"
    }

    fn from_le_bytes(buf: &[u8]) -> Result<Elf32Phdr, ReadErr> {
        Ok(Elf32Phdr {
            p_type:   Elf32Word::from_le_bytes(buf[ 0.. 4].try_into()?),
            p_offset: Elf32Off:: from_le_bytes(buf[ 4.. 8].try_into()?),
            p_vaddr:  Elf32Addr::from_le_bytes(buf[ 8..12].try_into()?),
            p_paddr:  Elf32Addr::from_le_bytes(buf[12..16].try_into()?),
            p_filesz: Elf32Word::from_le_bytes(buf[16..20].try_into()?),
            p_memsz:  Elf32Word::from_le_bytes(buf[20..24].try_into()?),
            p_flags:  Elf32Word::from_le_bytes(buf[24..28].try_into()?),
            p_align:  Elf32Word::from_le_bytes(buf[28..32].try_into()?),
        })
    }

    fn from_be_bytes(buf: &[u8]) -> Result<Elf32Phdr, ReadErr> {
        Ok(Elf32Phdr {
            p_type:   Elf32Word::from_be_bytes(buf[ 0.. 4].try_into()?),
            p_offset: Elf32Off:: from_be_bytes(buf[ 4.. 8].try_into()?),
            p_vaddr:  Elf32Addr::from_be_bytes(buf[ 8..12].try_into()?),
            p_paddr:  Elf32Addr::from_be_bytes(buf[12..16].try_into()?),
            p_filesz: Elf32Word::from_be_bytes(buf[16..20].try_into()?),
            p_memsz:  Elf32Word::from_be_bytes(buf[20..24].try_into()?),
            p_flags:  Elf32Word::from_be_bytes(buf[24..28].try_into()?),
            p_align:  Elf32Word::from_be_bytes(buf[28..32].try_into()?),
        })
    }
}

#[rustfmt::skip]
impl ElfHeader for Elf32Shdr {
    fn describe() -> &'static str {
        "section header"
    }

    fn from_le_bytes(buf: &[u8]) -> Result<Elf32Shdr, ReadErr> {
        Ok(Elf32Shdr {
            sh_name:      Elf32Word::from_le_bytes(buf[ 0.. 4].try_into()?),
            sh_type:      Elf32Word::from_le_bytes(buf[ 4.. 8].try_into()?),
            sh_flags:     Elf32Word::from_le_bytes(buf[ 8..12].try_into()?),
            sh_addr:      Elf32Addr::from_le_bytes(buf[12..16].try_into()?),
            sh_offset:    Elf32Off:: from_le_bytes(buf[16..20].try_into()?),
            sh_size:      Elf32Word::from_le_bytes(buf[20..24].try_into()?),
            sh_link:      Elf32Word::from_le_bytes(buf[24..28].try_into()?),
            sh_info:      Elf32Word::from_le_bytes(buf[28..32].try_into()?),
            sh_addralign: Elf32Word::from_le_bytes(buf[32..36].try_into()?),
            sh_entsize:   Elf32Word::from_le_bytes(buf[36..40].try_into()?),
        })
    }

    fn from_be_bytes(buf: &[u8]) -> Result<Elf32Shdr, ReadErr> {
        Ok(Elf32Shdr {
            sh_name:      Elf32Word::from_be_bytes(buf[ 0.. 4].try_into()?),
            sh_type:      Elf32Word::from_be_bytes(buf[ 4.. 8].try_into()?),
            sh_flags:     Elf32Word::from_be_bytes(buf[ 8..12].try_into()?),
            sh_addr:      Elf32Addr::from_be_bytes(buf[12..16].try_into()?),
            sh_offset:    Elf32Off:: from_be_bytes(buf[16..20].try_into()?),
            sh_size:      Elf32Word::from_be_bytes(buf[20..24].try_into()?),
            sh_link:      Elf32Word::from_be_bytes(buf[24..28].try_into()?),
            sh_info:      Elf32Word::from_be_bytes(buf[28..32].try_into()?),
            sh_addralign: Elf32Word::from_be_bytes(buf[32..36].try_into()?),
            sh_entsize:   Elf32Word::from_be_bytes(buf[36..40].try_into()?),
        })
    }
}

#[rustfmt::skip]
impl ElfXXEhdr for Elf32Ehdr {
    fn e_ident(&self)     -> [u8; 16] { self.e_ident            }
    fn e_type(&self)      -> u64      { self.e_type.into()      }
    fn e_machine(&self)   -> u64      { self.e_machine.into()   }
    fn e_version(&self)   -> u64      { self.e_version.into()   }
    fn e_entry(&self)     -> u64      { self.e_entry.into()     }
    fn e_phoff(&self)     -> u64      { self.e_phoff.into()     }
    fn e_shoff(&self)     -> u64      { self.e_shoff.into()     }
    fn e_flags(&self)     -> u64      { self.e_flags.into()     }
    fn e_ehsize(&self)    -> u64      { self.e_ehsize.into()    }
    fn e_phentsize(&self) -> u64      { self.e_phentsize.into() }
    fn e_phnum(&self)     -> u64      { self.e_phnum.into()     }
    fn e_shentsize(&self) -> u64      { self.e_shentsize.into() }
    fn e_shnum(&self)     -> u64      { self.e_shnum.into()     }
    fn e_shstrndx(&self)  -> u64      { self.e_shstrndx.into()  }
}

#[rustfmt::skip]
impl ElfXXPhdr for Elf32Phdr {
    fn p_type(&self)   -> u64 { self.p_type.into()   }
    fn p_flags(&self)  -> u64 { self.p_flags.into()  }
    fn p_offset(&self) -> u64 { self.p_offset.into() }
    fn p_vaddr(&self)  -> u64 { self.p_vaddr.into()  }
    fn p_paddr(&self)  -> u64 { self.p_paddr.into()  }
    fn p_filesz(&self) -> u64 { self.p_filesz.into() }
    fn p_memsz(&self)  -> u64 { self.p_memsz.into()  }
    fn p_align(&self)  -> u64 { self.p_align.into()  }
}

#[rustfmt::skip]
impl ElfXXShdr for Elf32Shdr {
    fn sh_name(&self)      -> u64 { self.sh_name.into()      }
    fn sh_type(&self)      -> u64 { self.sh_type.into()      }
    fn sh_flags(&self)     -> u64 { self.sh_flags.into()     }
    fn sh_addr(&self)      -> u64 { self.sh_addr.into()      }
    fn sh_offset(&self)    -> u64 { self.sh_offset.into()    }
    fn sh_size(&self)      -> u64 { self.sh_size.into()      }
    fn sh_link(&self)      -> u64 { self.sh_link.into()      }
    fn sh_info(&self)      -> u64 { self.sh_info.into()      }
    fn sh_addralign(&self) -> u64 { self.sh_addralign.into() }
    fn sh_entsize(&self)   -> u64 { self.sh_entsize.into()   }
}

#[rustfmt::skip]
impl ElfXX<Elf32Ehdr, Elf32Phdr, Elf32Shdr> for Elf32 {
    fn add_ehdr_ranges(ehdr: &Elf32Ehdr, ranges: &mut Ranges) {
        ranges.add_range(0,  ehdr.e_ehsize as usize, RangeType::FileHeader);
        ranges.add_range(16, 2, RangeType::HeaderField("e_type"));
        ranges.add_range(18, 2, RangeType::HeaderField("e_machine"));
        ranges.add_range(20, 4, RangeType::HeaderField("e_version"));
        ranges.add_range(24, 4, RangeType::HeaderField("e_entry"));
        ranges.add_range(28, 4, RangeType::HeaderField("e_phoff"));
        ranges.add_range(32, 4, RangeType::HeaderField("e_shoff"));
        ranges.add_range(36, 4, RangeType::HeaderField("e_flags"));
        ranges.add_range(40, 2, RangeType::HeaderField("e_ehsize"));
        ranges.add_range(42, 2, RangeType::HeaderField("e_phentsize"));
        ranges.add_range(44, 2, RangeType::HeaderField("e_phnum"));
        ranges.add_range(46, 2, RangeType::HeaderField("e_shentsize"));
        ranges.add_range(48, 2, RangeType::HeaderField("e_shnum"));
        ranges.add_range(50, 2, RangeType::HeaderField("e_shstrndx"));
    }

    fn add_phdr_ranges(start: usize, ranges: &mut Ranges) {
        ranges.add_range(start,      4, RangeType::PhdrField("p_type"));
        ranges.add_range(start +  4, 4, RangeType::PhdrField("p_offset"));
        ranges.add_range(start +  8, 4, RangeType::PhdrField("p_vaddr"));
        ranges.add_range(start + 12, 4, RangeType::PhdrField("p_paddr"));
        ranges.add_range(start + 16, 4, RangeType::PhdrField("p_filesz"));
        ranges.add_range(start + 20, 4, RangeType::PhdrField("p_memsz"));
        ranges.add_range(start + 24, 4, RangeType::PhdrField("p_flags"));
        ranges.add_range(start + 28, 4, RangeType::PhdrField("p_align"));
    }

    fn add_shdr_ranges(start: usize, ranges: &mut Ranges) {
        ranges.add_range(start,      4, RangeType::ShdrField("sh_name"));
        ranges.add_range(start +  4, 4, RangeType::ShdrField("sh_type"));
        ranges.add_range(start +  8, 4, RangeType::ShdrField("sh_flags"));
        ranges.add_range(start + 12, 4, RangeType::ShdrField("sh_addr"));
        ranges.add_range(start + 16, 4, RangeType::ShdrField("sh_offset"));
        ranges.add_range(start + 20, 4, RangeType::ShdrField("sh_size"));
        ranges.add_range(start + 24, 4, RangeType::ShdrField("sh_link"));
        ranges.add_range(start + 28, 4, RangeType::ShdrField("sh_info"));
        ranges.add_range(start + 32, 4, RangeType::ShdrField("sh_addralign"));
        ranges.add_range(start + 36, 4, RangeType::ShdrField("sh_entsize"));
    }
}
