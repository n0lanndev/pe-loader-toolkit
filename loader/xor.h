#pragma once

#include <cstdint>
#include <cstddef>

void xorDecryptPayload(uint8_t* data, size_t size, uint8_t XOR_KEY);