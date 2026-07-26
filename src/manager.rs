use std::ffi::{CStr, CString, c_char};
use std::ptr;
use std::slice;

use revng_sys::{
    rp_address_space_callbacks, rp_buffer, rp_buffer_data, rp_buffer_destroy, rp_buffer_size,
    rp_cabi_argument, rp_container_targets_map, rp_container_targets_map_add,
    rp_container_targets_map_create, rp_container_targets_map_destroy, rp_diff_map_destroy,
    rp_document_error_get_error_message, rp_document_error_reasons_count, rp_error,
    rp_error_create, rp_error_destroy, rp_error_get_document_error, rp_error_get_simple_error,
    rp_invalidations_create, rp_invalidations_destroy, rp_lifter_callbacks, rp_manager,
    rp_manager_add_imported_function, rp_manager_create_cabi_type,
    rp_manager_create_from_address_space, rp_manager_decompile_function_to_ptml,
    rp_manager_destroy, rp_manager_get_container_identifier_from_name,
    rp_manager_get_kind_from_name, rp_manager_get_step_from_name, rp_manager_produce_targets,
    rp_manager_run_analysis, rp_manager_set_cabi_prototype, rp_manager_set_default_abi,
    rp_manager_set_function_prototype, rp_set_lifter, rp_simple_error_get_message,
    rp_step_get_container, rp_target, rp_target_create, rp_target_destroy, rp_typed_argument,
};

use crate::Import;
use crate::error::Error;
use crate::prototype::Prototype;

pub(crate) struct Manager {
    manager: *mut rp_manager,
    error: *mut rp_error,
}

impl Manager {
    pub(crate) fn create(callbacks: &rp_address_space_callbacks) -> Result<Self, Error> {
        let error = unsafe { rp_error_create() };
        if error.is_null() {
            return Err(Error::pipeline("rp_error_create failed"));
        }
        let manager = unsafe {
            rp_manager_create_from_address_space(callbacks, 0, 0, ptr::null(), c"".as_ptr(), error)
        };
        if manager.is_null() {
            let failure = error_message(error, "failed to create the revng manager");
            unsafe { rp_error_destroy(error) };
            return Err(failure);
        }
        Ok(Self { manager, error })
    }

    pub(crate) fn error(&self, fallback: &str) -> Error {
        error_message(self.error, fallback)
    }

    pub(crate) fn set_default_abi(&mut self, abi: &CStr) -> Result<(), Error> {
        if unsafe { rp_manager_set_default_abi(self.manager, abi.as_ptr(), self.error) } {
            Ok(())
        } else {
            Err(self.error("failed to set the default ABI"))
        }
    }

    pub(crate) fn set_lifter(&mut self, callbacks: &rp_lifter_callbacks) -> Result<(), Error> {
        if unsafe { rp_set_lifter(self.manager, callbacks, self.error) } {
            Ok(())
        } else {
            Err(self.error("failed to install the lifter"))
        }
    }

    pub(crate) fn register_imports(
        &mut self,
        abi: &CStr,
        imports: &[Import],
        pointer_size: u64,
    ) -> Result<(), Error> {
        for import in imports {
            let name = CString::new(import.name.as_str()).expect("import name has no NUL");
            let definition = self.create_cabi_type(abi, &import.prototype, pointer_size)?;
            if !unsafe {
                rp_manager_add_imported_function(
                    self.manager,
                    name.as_ptr(),
                    definition,
                    self.error,
                )
            } {
                return Err(self.error("failed to register the imported function"));
            }
        }
        Ok(())
    }

    pub(crate) fn set_prototype(
        &mut self,
        address: &CStr,
        abi: &CStr,
        prototype: &Prototype,
        pointer_size: u64,
    ) -> Result<(), Error> {
        if let Some((arguments, returns)) = prototype.as_primitives() {
            let names = argument_names(arguments.len());
            let cabi_arguments = arguments
                .iter()
                .zip(&names)
                .map(|(primitive, name)| rp_cabi_argument {
                    name: name.as_ptr(),
                    type_: primitive.to_ffi(),
                })
                .collect::<Vec<_>>();
            let returns = returns.to_ffi();
            let name = CString::new("function").expect("function name has no NUL");
            let set = unsafe {
                rp_manager_set_cabi_prototype(
                    self.manager,
                    address.as_ptr(),
                    abi.as_ptr(),
                    name.as_ptr(),
                    cabi_arguments.len() as u64,
                    cabi_arguments.as_ptr(),
                    &returns,
                    self.error,
                )
            };
            return if set {
                Ok(())
            } else {
                Err(self.error("failed to set the prototype"))
            };
        }

        let definition = self.create_cabi_type(abi, prototype, pointer_size)?;
        if unsafe {
            rp_manager_set_function_prototype(
                self.manager,
                address.as_ptr(),
                definition,
                self.error,
            )
        } {
            Ok(())
        } else {
            Err(self.error("failed to set the function prototype"))
        }
    }

    fn create_cabi_type(
        &mut self,
        abi: &CStr,
        prototype: &Prototype,
        pointer_size: u64,
    ) -> Result<u64, Error> {
        let names = argument_names(prototype.arguments().len());
        let argument_types = prototype
            .arguments()
            .iter()
            .map(|ty| unsafe { ty.materialise(self.manager, pointer_size, self.error) })
            .collect::<Result<Vec<_>, Error>>()?;
        let return_type = unsafe {
            prototype
                .returns()
                .materialise(self.manager, pointer_size, self.error)?
        };
        let arguments = argument_types
            .iter()
            .zip(&names)
            .map(|(argument, name)| rp_typed_argument {
                name: name.as_ptr(),
                comment: ptr::null(),
                type_: argument.ffi(),
            })
            .collect::<Vec<_>>();
        let definition = unsafe {
            rp_manager_create_cabi_type(
                self.manager,
                c"".as_ptr(),
                ptr::null(),
                abi.as_ptr(),
                arguments.len() as u64,
                arguments.as_ptr(),
                &return_type.ffi(),
                ptr::null(),
                self.error,
            )
        };
        if definition == u64::MAX {
            return Err(self.error("failed to create the CABI function type"));
        }
        Ok(definition)
    }

    pub(crate) fn produce_root(&mut self) -> Result<(), Error> {
        let step = unsafe { rp_manager_get_step_from_name(self.manager, c"lift".as_ptr()) };
        let identifier = unsafe {
            rp_manager_get_container_identifier_from_name(self.manager, c"root.bc.zstd".as_ptr())
        };
        let kind = unsafe { rp_manager_get_kind_from_name(self.manager, c"root".as_ptr()) };
        if step.is_null() || identifier.is_null() || kind.is_null() {
            return Err(Error::pipeline(
                "revng is missing the lift step or root kind",
            ));
        }
        let container = unsafe { rp_step_get_container(step, identifier) };
        let components: [*const c_char; 0] = [];
        let target = unsafe { rp_target_create(kind, 0, components.as_ptr()) };
        let targets: [*const rp_target; 1] = [target];
        let buffer = unsafe {
            rp_manager_produce_targets(
                self.manager,
                step,
                container,
                1,
                targets.as_ptr(),
                self.error,
            )
        };
        unsafe { rp_target_destroy(target) };
        if buffer.is_null() {
            return Err(self.error("failed to lift the root function"));
        }
        unsafe { rp_buffer_destroy(buffer) };
        Ok(())
    }

    pub(crate) fn detect_abi(&mut self) -> Result<(), Error> {
        let step = unsafe { rp_manager_get_step_from_name(self.manager, c"lift".as_ptr()) };
        let identifier = unsafe {
            rp_manager_get_container_identifier_from_name(self.manager, c"root.bc.zstd".as_ptr())
        };
        let kind = unsafe { rp_manager_get_kind_from_name(self.manager, c"root".as_ptr()) };
        if step.is_null() || identifier.is_null() || kind.is_null() {
            return Err(Error::pipeline(
                "revng is missing the lift step or root kind",
            ));
        }
        let container = unsafe { rp_step_get_container(step, identifier) };
        let components: [*const c_char; 0] = [];
        let target = unsafe { rp_target_create(kind, 0, components.as_ptr()) };
        let map = unsafe { rp_container_targets_map_create() };
        unsafe { rp_container_targets_map_add(map, container, target) };
        let result = self.run_analysis(c"lift", c"detect-abi", Some(map.cast_const()));
        unsafe {
            rp_container_targets_map_destroy(map);
            rp_target_destroy(target);
        }
        result
    }

    pub(crate) fn run_data_layout(&mut self, functions: &[CString]) -> Result<(), Error> {
        let step =
            unsafe { rp_manager_get_step_from_name(self.manager, c"make-segment-ref".as_ptr()) };
        let identifier = unsafe {
            rp_manager_get_container_identifier_from_name(
                self.manager,
                c"functions.bc.zstd".as_ptr(),
            )
        };
        let kind = unsafe {
            rp_manager_get_kind_from_name(self.manager, c"stack-accesses-segregated".as_ptr())
        };
        if step.is_null() || identifier.is_null() || kind.is_null() {
            return Err(Error::pipeline(
                "revng is missing the make-segment-ref step or stack-accesses-segregated kind",
            ));
        }
        let container = unsafe { rp_step_get_container(step, identifier) };
        let map = unsafe { rp_container_targets_map_create() };
        let targets = functions
            .iter()
            .map(|address| {
                let components: [*const c_char; 1] = [address.as_ptr()];
                let target = unsafe { rp_target_create(kind, 1, components.as_ptr()) };
                unsafe { rp_container_targets_map_add(map, container, target) };
                target
            })
            .collect::<Vec<_>>();
        let result = self.run_analysis(
            c"make-segment-ref",
            c"analyze-data-layout",
            Some(map.cast_const()),
        );
        unsafe {
            rp_container_targets_map_destroy(map);
            for target in targets {
                rp_target_destroy(target);
            }
        }
        result
    }

    pub(crate) fn run_analysis(
        &mut self,
        step: &CStr,
        analysis: &CStr,
        targets: Option<*const rp_container_targets_map>,
    ) -> Result<(), Error> {
        let owned = targets.is_none();
        let map =
            targets.unwrap_or_else(|| unsafe { rp_container_targets_map_create().cast_const() });
        let invalidations = unsafe { rp_invalidations_create() };
        let diff = unsafe {
            rp_manager_run_analysis(
                self.manager,
                step.as_ptr(),
                analysis.as_ptr(),
                map,
                ptr::null(),
                invalidations,
                self.error,
            )
        };
        unsafe { rp_invalidations_destroy(invalidations) };
        if owned {
            unsafe { rp_container_targets_map_destroy(map.cast_mut()) };
        }
        if diff.is_null() {
            return Err(self.error("analysis failed"));
        }
        unsafe { rp_diff_map_destroy(diff) };
        Ok(())
    }

    pub(crate) fn decompile_to_ptml(&self, address: &CStr) -> Result<String, Error> {
        let buffer = unsafe {
            rp_manager_decompile_function_to_ptml(self.manager, address.as_ptr(), self.error)
        };
        if buffer.is_null() {
            return Err(self.error("decompilation failed"));
        }
        let bytes = unsafe { take_buffer(buffer) };
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        unsafe {
            rp_manager_destroy(self.manager);
            rp_error_destroy(self.error);
        }
    }
}

fn argument_names(count: usize) -> Vec<CString> {
    (0..count)
        .map(|index| CString::new(format!("argument_{index}")).expect("argument name has no NUL"))
        .collect()
}

unsafe fn take_buffer(buffer: *mut rp_buffer) -> Vec<u8> {
    let size = unsafe { rp_buffer_size(buffer) };
    let data = unsafe { rp_buffer_data(buffer) };
    let bytes = if size == 0 || data.is_null() {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(data.cast(), size as usize) }.to_vec()
    };
    unsafe { rp_buffer_destroy(buffer) };
    bytes
}

fn error_message(error: *mut rp_error, fallback: &str) -> Error {
    if error.is_null() {
        return Error::pipeline(fallback);
    }

    let simple = unsafe { rp_error_get_simple_error(error) };
    if !simple.is_null() {
        let message = unsafe { rp_simple_error_get_message(simple) };
        if !message.is_null() {
            return Error::pipeline(unsafe { CStr::from_ptr(message) }.to_string_lossy());
        }
    }

    let document = unsafe { rp_error_get_document_error(error) };
    if !document.is_null() && unsafe { rp_document_error_reasons_count(document) } != 0 {
        let message = unsafe { rp_document_error_get_error_message(document, 0) };
        if !message.is_null() {
            return Error::pipeline(unsafe { CStr::from_ptr(message) }.to_string_lossy());
        }
    }

    Error::pipeline(fallback)
}
