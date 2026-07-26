#pragma once

#include <cstdint>

#include "rust/cxx.h"

namespace revng_fugue {

void tag_helper(std::uintptr_t Function);
void tag_csv(std::uintptr_t Global);
void emit_unsupported(std::uintptr_t Block, rust::Str Name,
                      rust::Slice<const std::uintptr_t> Reads,
                      rust::Slice<const std::uintptr_t> Writes);
void emit_jump_to_symbol(std::uintptr_t Terminator, rust::Str Symbol);
rust::String default_pipeline();

}
