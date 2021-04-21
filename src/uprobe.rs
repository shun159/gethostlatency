use std::fs::read;
use std::path::Path;

use anyhow::{Context as _, Result};
use goblin::elf::{Elf, Sym};

pub struct SymbolResolver<'a> {
    elf: Elf<'a>,
}

impl<'a> SymbolResolver<'a> {
    pub fn find_in_file(pathname: &Path, symbol: &str) -> Result<Option<usize>> {
        let bytes = read(pathname).context("Failed to read ELF")?;
        let resolver = Self::parse(&bytes).context("Failed to parse ELF")?;
        let offset = resolver.find_offset(symbol);
        Ok(offset)
    }

    pub fn parse(bytes: &[u8]) -> Result<SymbolResolver> {
        let elf = Elf::parse(bytes)?;
        Ok(SymbolResolver { elf })
    }

    pub fn find_offset(&self, symbol: &str) -> Option<usize> {
        self.resolve_sym(symbol)
            .and_then(|sym| Some(sym.st_value as usize))
    }

    fn resolve_sym(&self, symbol: &str) -> Option<Sym> {
        self.elf.dynsyms.iter().find(|sym| {
            self.elf
                .dynstrtab
                .get(sym.st_name)
                .and_then(|sym| sym.ok())
                .map(|sym| sym == symbol)
                .unwrap_or(false)
        })
    }
}
