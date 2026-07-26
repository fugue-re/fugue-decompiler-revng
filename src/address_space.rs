use std::ffi::{CString, c_char, c_void};
use std::ptr;
use std::rc::Rc;
use std::slice;

use crate::binary::Binary;

struct Mapping {
    start: CString,
    name: CString,
    base: u64,
    virtual_size: u64,
    backing_size: u64,
    readable: bool,
    writable: bool,
    executable: bool,
}

pub(crate) struct AddressSpace {
    binary: Rc<Binary>,
    architecture: CString,
    entry: CString,
    mappings: Vec<Mapping>,
}

impl AddressSpace {
    pub(crate) fn new(binary: Rc<Binary>, entry: u64) -> Self {
        let architecture_name = binary.architecture().revng_name();
        let architecture = CString::new(architecture_name).expect("architecture name has no NUL");
        let entry = CString::new(format!("{entry:#x}:Code_{architecture_name}"))
            .expect("meta address has no NUL");

        let mappings = binary
            .segments()
            .iter()
            .map(|segment| Mapping {
                start: CString::new(format!("{:#x}:Generic64", segment.address().value()))
                    .expect("meta address has no NUL"),
                name: CString::new(segment.name().replace('\0', "_"))
                    .unwrap_or_else(|_| CString::new("segment").expect("segment name has no NUL")),
                base: segment.address().value(),
                virtual_size: segment.size(),
                backing_size: if segment.is_initialised() {
                    segment.size()
                } else {
                    0
                },
                readable: segment.is_readable(),
                writable: segment.is_writable(),
                executable: segment.is_executable(),
            })
            .collect();

        Self {
            binary,
            architecture,
            entry,
            mappings,
        }
    }

    pub(crate) fn callbacks(&self) -> revng_sys::rp_address_space_callbacks {
        revng_sys::rp_address_space_callbacks {
            opaque: ptr::from_ref(self).cast_mut().cast(),
            architecture: Some(architecture),
            entry_point: Some(entry_point),
            mapping_count: Some(mapping_count),
            mapping_at: Some(mapping_at),
            read: Some(read),
            extra_code_address_count: Some(extra_code_address_count),
            extra_code_address_at: None,
            release: None,
        }
    }
}

unsafe fn space<'a>(opaque: *mut c_void) -> &'a AddressSpace {
    unsafe { &*opaque.cast::<AddressSpace>() }
}

unsafe extern "C" fn architecture(opaque: *mut c_void) -> *const c_char {
    unsafe { space(opaque) }.architecture.as_ptr()
}

unsafe extern "C" fn entry_point(opaque: *mut c_void) -> *const c_char {
    unsafe { space(opaque) }.entry.as_ptr()
}

unsafe extern "C" fn mapping_count(opaque: *mut c_void) -> u64 {
    unsafe { space(opaque) }.mappings.len() as u64
}

unsafe extern "C" fn mapping_at(
    opaque: *mut c_void,
    index: u64,
    output: *mut revng_sys::rp_address_space_mapping,
) -> bool {
    let space = unsafe { space(opaque) };
    let Ok(index) = usize::try_from(index) else {
        return false;
    };
    let Some(mapping) = space.mappings.get(index) else {
        return false;
    };
    if output.is_null() {
        return false;
    }
    unsafe {
        *output = revng_sys::rp_address_space_mapping {
            start: mapping.start.as_ptr(),
            virtual_size: mapping.virtual_size,
            backing_size: mapping.backing_size,
            readable: mapping.readable,
            writeable: mapping.writable,
            executable: mapping.executable,
            name: mapping.name.as_ptr(),
        };
    }
    true
}

unsafe extern "C" fn read(
    opaque: *mut c_void,
    index: u64,
    offset: u64,
    destination: *mut u8,
    size: u64,
) -> bool {
    let space = unsafe { space(opaque) };
    let Ok(index) = usize::try_from(index) else {
        return false;
    };
    let Some(mapping) = space.mappings.get(index) else {
        return false;
    };
    let (Ok(offset), Ok(size)) = (usize::try_from(offset), usize::try_from(size)) else {
        return false;
    };
    if destination.is_null() {
        return size == 0;
    }
    let Some(address) = mapping.base.checked_add(offset as u64) else {
        return false;
    };
    let buffer = unsafe { slice::from_raw_parts_mut(destination, size) };
    space.binary.read(address, buffer).is_ok()
}

unsafe extern "C" fn extra_code_address_count(_: *mut c_void) -> u64 {
    0
}
