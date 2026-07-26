#pragma once

#include <cstdint>

#include "rust/cxx.h"

namespace revng_fugue {

std::uintptr_t fugue_lifter_new(std::uintptr_t Model, std::uintptr_t View,
                                std::uintptr_t Module, std::uint8_t Architecture,
                                rust::Str PCName, rust::Str SPName,
                                std::uint64_t Entry);
void fugue_lifter_free(std::uintptr_t State);
std::uintptr_t fugue_lifter_peek(std::uintptr_t State, std::uint64_t &Address);
bool fugue_lifter_diverge(std::uintptr_t State, std::uintptr_t Block,
                          std::uint64_t Address);
void fugue_lifter_new_pc(std::uintptr_t State, std::uintptr_t Block,
                         std::uint64_t Address, std::uint64_t Size,
                         bool IsFirst);
void fugue_lifter_exit_constant(std::uintptr_t State, std::uintptr_t Block,
                                std::uint64_t Target);
void fugue_lifter_exit_dynamic(std::uintptr_t State, std::uintptr_t Block,
                               std::uintptr_t Value);
void fugue_lifter_exit_call(std::uintptr_t State, std::uintptr_t Block,
                            std::uint64_t Target, std::uint64_t ReturnAddress,
                            std::uintptr_t LinkRegister, bool IsImport);
void fugue_lifter_register_direct_jumps(std::uintptr_t State);
void fugue_lifter_finalize(std::uintptr_t State);

}
