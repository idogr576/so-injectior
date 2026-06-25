#pragma once

#define PRINT printf

#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) PRINT("[DEBUG] " fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) // Becomes nothing in regular compilation

#endif