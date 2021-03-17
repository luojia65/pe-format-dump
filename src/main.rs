use std::{fs::OpenOptions, io::{self, Seek, SeekFrom}, path::Path, u32};
use byteorder::{LittleEndian, ReadBytesExt};

#[macro_use]
extern crate clap;

#[derive(Debug)]
pub struct DosHead {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

fn read_dos_head<R: io::Read>(read: &mut R) -> io::Result<DosHead> {
    Ok(DosHead {
        e_magic: read.read_u16::<LittleEndian>()?,
        e_cblp: read.read_u16::<LittleEndian>()?,
        e_cp: read.read_u16::<LittleEndian>()?,
        e_crlc: read.read_u16::<LittleEndian>()?,
        e_cparhdr: read.read_u16::<LittleEndian>()?,
        e_minalloc: read.read_u16::<LittleEndian>()?,
        e_maxalloc: read.read_u16::<LittleEndian>()?,
        e_ss: read.read_u16::<LittleEndian>()?,
        e_sp: read.read_u16::<LittleEndian>()?,
        e_csum: read.read_u16::<LittleEndian>()?,
        e_ip: read.read_u16::<LittleEndian>()?,
        e_cs: read.read_u16::<LittleEndian>()?,
        e_lfarlc: read.read_u16::<LittleEndian>()?,
        e_ovno: read.read_u16::<LittleEndian>()?,
        e_res: {
            [read.read_u16::<LittleEndian>()?, read.read_u16::<LittleEndian>()?,
            read.read_u16::<LittleEndian>()?, read.read_u16::<LittleEndian>()?]
        },
        e_oemid: read.read_u16::<LittleEndian>()?,
        e_oeminfo: read.read_u16::<LittleEndian>()?,
        e_res2: {
            [read.read_u16::<LittleEndian>()?, read.read_u16::<LittleEndian>()?,
            read.read_u16::<LittleEndian>()?, read.read_u16::<LittleEndian>()?,
            read.read_u16::<LittleEndian>()?, read.read_u16::<LittleEndian>()?,
            read.read_u16::<LittleEndian>()?, read.read_u16::<LittleEndian>()?,
            read.read_u16::<LittleEndian>()?, read.read_u16::<LittleEndian>()?]
        },
        e_lfanew: read.read_i32::<LittleEndian>()?,
    })
}

#[derive(Debug)]
pub struct NtHead {
    signature: u32,
    file_header: FileHeader,
    optional_header: OptionalHeader
}

pub fn read_nt_head<R: io::Read>(read: &mut R) -> io::Result<NtHead> {
    Ok(NtHead {
        signature: read.read_u32::<LittleEndian>()?,
        file_header: read_file_header(read)?,
        optional_header: read_optional_header(read)?,
    })
}

#[derive(Debug)]
pub struct FileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

pub fn read_file_header<R: io::Read>(read: &mut R) -> io::Result<FileHeader> {
    Ok(FileHeader {
        machine: read.read_u16::<LittleEndian>()?,
        number_of_sections: read.read_u16::<LittleEndian>()?,
        time_date_stamp: read.read_u32::<LittleEndian>()?,
        pointer_to_symbol_table: read.read_u32::<LittleEndian>()?,
        number_of_symbols: read.read_u32::<LittleEndian>()?,
        size_of_optional_header: read.read_u16::<LittleEndian>()?,
        characteristics: read.read_u16::<LittleEndian>()?,
    })
}

#[derive(Debug)]
pub struct OptionalHeader {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [DataDirectory; 16],
}

pub fn read_optional_header<R: io::Read>(read: &mut R) -> io::Result<OptionalHeader> {
    Ok(OptionalHeader {
        magic: read.read_u16::<LittleEndian>()?,
        major_linker_version: read.read_u8()?,
        minor_linker_version: read.read_u8()?,
        size_of_code: read.read_u32::<LittleEndian>()?,
        size_of_initialized_data: read.read_u32::<LittleEndian>()?,
        size_of_uninitialized_data: read.read_u32::<LittleEndian>()?,
        address_of_entry_point: read.read_u32::<LittleEndian>()?,
        base_of_code: read.read_u32::<LittleEndian>()?,
        base_of_data: read.read_u32::<LittleEndian>()?,
        image_base: read.read_u32::<LittleEndian>()?,
        section_alignment: read.read_u32::<LittleEndian>()?,
        file_alignment: read.read_u32::<LittleEndian>()?,
        major_operating_system_version: read.read_u16::<LittleEndian>()?,
        minor_operating_system_version: read.read_u16::<LittleEndian>()?,
        major_image_version: read.read_u16::<LittleEndian>()?,
        minor_image_version: read.read_u16::<LittleEndian>()?,
        major_subsystem_version: read.read_u16::<LittleEndian>()?,
        minor_subsystem_version: read.read_u16::<LittleEndian>()?,
        win32_version_value: read.read_u32::<LittleEndian>()?,
        size_of_image: read.read_u32::<LittleEndian>()?,
        size_of_headers: read.read_u32::<LittleEndian>()?,
        checksum: read.read_u32::<LittleEndian>()?,
        subsystem: read.read_u16::<LittleEndian>()?,
        dll_characteristics: read.read_u16::<LittleEndian>()?,
        size_of_stack_reserve: read.read_u32::<LittleEndian>()?,
        size_of_stack_commit: read.read_u32::<LittleEndian>()?,
        size_of_heap_reserve: read.read_u32::<LittleEndian>()?,
        size_of_heap_commit: read.read_u32::<LittleEndian>()?,
        loader_flags: read.read_u32::<LittleEndian>()?,
        number_of_rva_and_sizes: read.read_u32::<LittleEndian>()?,
        data_directory: [
            read_data_directory(read)?, read_data_directory(read)?, read_data_directory(read)?, read_data_directory(read)?, 
            read_data_directory(read)?, read_data_directory(read)?, read_data_directory(read)?, read_data_directory(read)?, 
            read_data_directory(read)?, read_data_directory(read)?, read_data_directory(read)?, read_data_directory(read)?, 
            read_data_directory(read)?, read_data_directory(read)?, read_data_directory(read)?, read_data_directory(read)?, 
        ],
    })
}

#[derive(Debug)]
pub struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

pub fn read_data_directory<R: io::Read>(read: &mut R) -> io::Result<DataDirectory> {
    Ok(DataDirectory {
        virtual_address: read.read_u32::<LittleEndian>()?,
        size: read.read_u32::<LittleEndian>()?,
    })
}

#[derive(Debug)]
pub struct SectionHeader {
    name: [u8; 8],
    phys_addr_or_virt_size: u32,
    virt_addr: u32,
    size_of_raw_data: u32,
    ptr_to_raw_data: u32,
    ptr_to_relocations: u32,
    ptr_to_line_numbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
}

pub fn read_section_header<R: io::Read>(read: &mut R) -> io::Result<SectionHeader> {
    Ok(SectionHeader {
        name: [
            read.read_u8()?, read.read_u8()?, read.read_u8()?, read.read_u8()?, 
            read.read_u8()?, read.read_u8()?, read.read_u8()?, read.read_u8()?, 
        ],
        phys_addr_or_virt_size: read.read_u32::<LittleEndian>()?,
        virt_addr: read.read_u32::<LittleEndian>()?,
        size_of_raw_data: read.read_u32::<LittleEndian>()?,
        ptr_to_raw_data: read.read_u32::<LittleEndian>()?,
        ptr_to_relocations: read.read_u32::<LittleEndian>()?,
        ptr_to_line_numbers: read.read_u32::<LittleEndian>()?,
        number_of_relocations: read.read_u16::<LittleEndian>()?,
        number_of_line_numbers: read.read_u16::<LittleEndian>()?,
        characteristics: read.read_u32::<LittleEndian>()?,
    })
}

fn main() {
    let matches = clap::clap_app!(myapp =>
        (version: crate_version!())
        (author: crate_authors!())
        (about: crate_description!())
        (@arg INPUT: +required "Sets the input file to use")
    ).get_matches();
    let input_file = matches.value_of("INPUT").unwrap();
    let path = Path::new(input_file);
    let mut file = OpenOptions::new().read(true).open(path)
        .expect("open file");
    let dos_head = read_dos_head(&mut file)
        .expect("parse dos head");
    println!("dos_head.e_lfanew = {:x}", dos_head.e_lfanew);
    file.seek(SeekFrom::Start(dos_head.e_lfanew as u64))
        .expect("seek into NT head");
    let nt_head = read_nt_head(&mut file).expect("read NT head");
    assert_eq!(nt_head.signature, 0x4550, "NT signature must be 0x4550");
    println!("Number of sections: {}", nt_head.file_header.number_of_sections);
    println!("Size of optional header: {}", nt_head.file_header.size_of_optional_header);
    println!("Size of code: {}", nt_head.optional_header.size_of_code);
    println!("Address of entry point: {}", nt_head.optional_header.address_of_entry_point);
    println!("Image base: {}", nt_head.optional_header.image_base);
    println!("Section alignment: {}", nt_head.optional_header.section_alignment);
    println!("File alignment: {}", nt_head.optional_header.file_alignment);
    println!("Size of image: {}", nt_head.optional_header.size_of_image);
    println!("Number of Rva and sizes: {}", nt_head.optional_header.number_of_rva_and_sizes); 
    for i in 0..nt_head.file_header.number_of_sections {
        let section_header = read_section_header(&mut file)
            .expect("read section header");
        let name = String::from_utf8_lossy(&section_header.name);
        println!(
            "Section #{}: {}\t, va: {:#08x}, raw ptr: {:#08x}, size: {:#08x}", 
            i, name, section_header.virt_addr,
            section_header.ptr_to_raw_data, section_header.size_of_raw_data,
        );
    }
}
