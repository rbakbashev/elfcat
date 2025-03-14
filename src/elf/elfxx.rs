use super::defs::*;
use super::parser::*;
use std::mem::size_of;

pub trait ElfHeader: Sized {
    fn from_le_bytes(buf: &[u8]) -> Result<Self, ReadErr>;
    fn from_be_bytes(buf: &[u8]) -> Result<Self, ReadErr>;
    fn describe() -> &'static str;

    fn from_bytes(buf: &[u8], endianness: u8) -> Result<Self, String> {
        if endianness == ELF_DATA2LSB {
            Self::from_le_bytes(buf)
        } else {
            Self::from_be_bytes(buf)
        }
        .map_err(|a| format!("failed to read {}: {}", Self::describe(), a))
    }
}

// We do this because we can't access struct fields of a generic type
#[allow(unused)]
pub trait ElfXXEhdr: ElfHeader {
    fn e_ident(&self) -> [u8; 16];
    fn e_type(&self) -> u64;
    fn e_machine(&self) -> u64;
    fn e_version(&self) -> u64;
    fn e_entry(&self) -> u64;
    fn e_phoff(&self) -> u64;
    fn e_shoff(&self) -> u64;
    fn e_flags(&self) -> u64;
    fn e_ehsize(&self) -> u64;
    fn e_phentsize(&self) -> u64;
    fn e_phnum(&self) -> u64;
    fn e_shentsize(&self) -> u64;
    fn e_shnum(&self) -> u64;
    fn e_shstrndx(&self) -> u64;
}

#[allow(unused)]
pub trait ElfXXPhdr: ElfHeader {
    fn p_type(&self) -> u64;
    fn p_flags(&self) -> u64;
    fn p_offset(&self) -> u64;
    fn p_vaddr(&self) -> u64;
    fn p_paddr(&self) -> u64;
    fn p_filesz(&self) -> u64;
    fn p_memsz(&self) -> u64;
    fn p_align(&self) -> u64;
}

pub trait ElfXXShdr: ElfHeader {
    fn sh_name(&self) -> u64;
    fn sh_type(&self) -> u64;
    fn sh_flags(&self) -> u64;
    fn sh_addr(&self) -> u64;
    fn sh_offset(&self) -> u64;
    fn sh_size(&self) -> u64;
    fn sh_link(&self) -> u64;
    fn sh_info(&self) -> u64;
    fn sh_addralign(&self) -> u64;
    fn sh_entsize(&self) -> u64;
}

macro_rules! read_field {
    ($name:ident, $field:ident) => {
        $name
            .$field()
            .try_into()
            .map_err(|_| format!("failed to read {}", stringify!($field)))
    };
}

pub trait ElfXX<EhdrT, PhdrT, ShdrT>
where
    EhdrT: ElfXXEhdr,
    PhdrT: ElfXXPhdr,
    ShdrT: ElfXXShdr,
{
    fn parse(buf: &[u8], ident: &ParsedIdent, elf: &mut ParsedElf) -> Result<(), String> {
        let ehdr_size = size_of::<EhdrT>();

        if buf.len() < ehdr_size {
            return Err(String::from("file is smaller than ELF file header"));
        }

        let ehdr = EhdrT::from_bytes(&buf[0..ehdr_size], ident.endianness)?;

        elf.shstrndx = read_field!(ehdr, e_shstrndx)?;

        Self::parse_ehdr(&ehdr, elf)?;

        Self::parse_phdrs(buf, ident.endianness, &ehdr, elf)?;

        Self::parse_shdrs(buf, ident.endianness, &ehdr, elf)?;

        Ok(())
    }

    fn parse_ehdr(ehdr: &EhdrT, elf: &mut ParsedElf) -> Result<(), String> {
        Self::push_ehdr_info(ehdr, &mut elf.information)?;

        Self::add_ehdr_ranges(ehdr, &mut elf.ranges);

        Ok(())
    }

    fn push_ehdr_info(ehdr: &EhdrT, information: &mut Vec<InfoTuple>) -> Result<(), String> {
        information.push(("e_type", "Type", type_to_string(read_field!(ehdr, e_type)?)));

        information.push((
            "e_machine",
            "Architecture",
            machine_to_string(read_field!(ehdr, e_machine)?),
        ));

        information.push((
            "e_entry",
            "Entrypoint",
            format!("<span class='number' title='{}'>{:#x}</span>", ehdr.e_entry(), ehdr.e_entry()),
        ));

        information.push((
            "ph",
            "Program headers",
            format!(
                "<span title='{:#x}' class='number fileinfo_e_phnum'>{}</span> * \
                 <span title='{:#x}' class='number fileinfo_e_phentsize'>{}</span> @ \
                 <span title='{:#x}' class='number fileinfo_e_phoff'>{}</span>",
                ehdr.e_phnum(),
                ehdr.e_phnum(),
                ehdr.e_phentsize(),
                ehdr.e_phentsize(),
                ehdr.e_phoff(),
                ehdr.e_phoff()
            ),
        ));

        information.push((
            "sh",
            "Section headers",
            format!(
                "<span title='{:#x}' class='number fileinfo_e_shnum'>{}</span> * \
                 <span title='{:#x}' class='number fileinfo_e_shentsize'>{}</span> @ \
                 <span title='{:#x}' class='number fileinfo_e_shoff'>{}</span>",
                ehdr.e_shnum(),
                ehdr.e_shnum(),
                ehdr.e_shentsize(),
                ehdr.e_shentsize(),
                ehdr.e_shoff(),
                ehdr.e_shoff()
            ),
        ));

        if ehdr.e_flags() != 0 {
            information.push(("e_flags", "Flags", format!("{:#x}", ehdr.e_flags())));
        }

        Ok(())
    }

    fn add_ehdr_ranges(ehdr: &EhdrT, ranges: &mut Ranges);

    fn parse_phdrs(
        buf: &[u8],
        endianness: u8,
        ehdr: &EhdrT,
        elf: &mut ParsedElf,
    ) -> Result<(), String> {
        let mut start = read_field!(ehdr, e_phoff)?;
        let phnum = read_field!(ehdr, e_phnum)?;
        let phsize = size_of::<PhdrT>();

        for i in 0..phnum {
            let phdr = PhdrT::from_bytes(&buf[start..start + phsize], endianness)?;
            let parsed = Self::parse_phdr(&phdr)?;
            let ranges = &mut elf.ranges;

            if parsed.file_offset != 0 && parsed.file_size != 0 {
                ranges.add_range(parsed.file_offset, parsed.file_size, RangeType::Segment(i));
            }

            ranges.add_range(start, phsize, RangeType::ProgramHeader(i.into()));

            Self::add_phdr_ranges(start, ranges);

            elf.phdrs.push(parsed);

            start += phsize;
        }

        Ok(())
    }

    fn parse_phdr(phdr: &PhdrT) -> Result<ParsedPhdr, String> {
        let ptype = read_field!(phdr, p_type)?;
        let flags = pflags_to_string(read_field!(phdr, p_flags)?);
        let file_offset = read_field!(phdr, p_offset)?;
        let file_size = read_field!(phdr, p_filesz)?;
        let vaddr = read_field!(phdr, p_vaddr)?;
        let memsz = read_field!(phdr, p_memsz)?;
        let alignment = read_field!(phdr, p_align)?;

        Ok(ParsedPhdr {
            ptype,
            flags,
            file_offset,
            file_size,
            vaddr,
            memsz,
            alignment,
        })
    }

    fn add_phdr_ranges(start: usize, ranges: &mut Ranges);

    fn parse_shdrs(
        buf: &[u8],
        endianness: u8,
        ehdr: &EhdrT,
        elf: &mut ParsedElf,
    ) -> Result<(), String> {
        let mut start = read_field!(ehdr, e_shoff)?;
        let shnum = read_field!(ehdr, e_shnum)?;
        let shsize = size_of::<ShdrT>();

        for i in 0..shnum {
            let shdr = ShdrT::from_bytes(&buf[start..start + shsize], endianness)?;
            let parsed = Self::parse_shdr(buf, endianness, &shdr)?;
            let ranges = &mut elf.ranges;

            if parsed.file_offset != 0 && parsed.size != 0 && parsed.shtype != SHT_NOBITS {
                ranges.add_range(parsed.file_offset, parsed.size, RangeType::Section(i));
            }

            ranges.add_range(start, shsize, RangeType::SectionHeader(i.into()));

            Self::add_shdr_ranges(start, ranges);

            elf.shdrs.push(parsed);

            start += shsize;
        }

        Ok(())
    }

    fn parse_shdr(_buf: &[u8], _endianness: u8, shdr: &ShdrT) -> Result<ParsedShdr, String> {
        let name = read_field!(shdr, sh_name)?;
        let shtype = read_field!(shdr, sh_type)?;
        let flags = read_field!(shdr, sh_flags)?;
        let addr = read_field!(shdr, sh_addr)?;
        let file_offset = read_field!(shdr, sh_offset)?;
        let size = read_field!(shdr, sh_size)?;
        let link = read_field!(shdr, sh_link)?;
        let info = read_field!(shdr, sh_info)?;
        let addralign = read_field!(shdr, sh_addralign)?;
        let entsize = read_field!(shdr, sh_entsize)?;

        Ok(ParsedShdr {
            name,
            shtype,
            flags,
            addr,
            file_offset,
            size,
            link,
            info,
            addralign,
            entsize,
        })
    }

    fn add_shdr_ranges(start: usize, ranges: &mut Ranges);
}
