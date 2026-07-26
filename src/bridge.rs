#[cxx::bridge(namespace = "revng_fugue")]
mod ffi {
    unsafe extern "C++" {
        include!("revng-fugue/cxx/include/tags.h");
        include!("revng-fugue/cxx/include/lifter.h");

        unsafe fn tag_helper(function: usize);
        unsafe fn tag_csv(global: usize);
        unsafe fn emit_unsupported(block: usize, name: &str, reads: &[usize], writes: &[usize]);
        unsafe fn emit_jump_to_symbol(terminator: usize, symbol: &str);
        fn default_pipeline() -> String;

        unsafe fn fugue_lifter_new(
            model: usize,
            view: usize,
            module: usize,
            architecture: u8,
            pc_name: &str,
            sp_name: &str,
            entry: u64,
        ) -> usize;
        unsafe fn fugue_lifter_free(state: usize);
        unsafe fn fugue_lifter_peek(state: usize, address: &mut u64) -> usize;
        unsafe fn fugue_lifter_diverge(state: usize, block: usize, address: u64) -> bool;
        unsafe fn fugue_lifter_new_pc(
            state: usize,
            block: usize,
            address: u64,
            size: u64,
            is_first: bool,
        );
        unsafe fn fugue_lifter_exit_constant(state: usize, block: usize, target: u64);
        unsafe fn fugue_lifter_exit_dynamic(state: usize, block: usize, value: usize);
        unsafe fn fugue_lifter_exit_call(
            state: usize,
            block: usize,
            target: u64,
            return_address: u64,
            link_register: usize,
            is_import: bool,
        );
        unsafe fn fugue_lifter_register_direct_jumps(state: usize);
        unsafe fn fugue_lifter_finalize(state: usize);
    }
}

pub(crate) use ffi::{
    default_pipeline, emit_jump_to_symbol, emit_unsupported, fugue_lifter_diverge,
    fugue_lifter_exit_call, fugue_lifter_exit_constant, fugue_lifter_exit_dynamic,
    fugue_lifter_finalize, fugue_lifter_free, fugue_lifter_new, fugue_lifter_new_pc,
    fugue_lifter_peek, fugue_lifter_register_direct_jumps, tag_csv, tag_helper,
};
