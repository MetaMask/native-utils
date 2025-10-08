// Conditional Botan implementation inclusion
// This file automatically includes the appropriate Botan implementation based on target architecture

#include "botan_conditional.h"

// Include the appropriate implementation based on architecture detection
#if defined(__APPLE__)
    #include <TargetConditionals.h>
    #if TARGET_OS_IOS
        // iOS device or simulator
        #if defined(__aarch64__) || defined(_M_ARM64)
            // iOS ARM64 (physical devices) - hardware accelerated
            #include "botan_generated/botan_ios_arm64.cpp"
        #else
            // iOS simulator (x86_64) - portable implementation
            #include "botan_generated/botan_generic.cpp"
        #endif
    #else
        // macOS
        #if defined(__aarch64__) || defined(_M_ARM64)
            // Apple Silicon Mac - use iOS ARM64 optimized build
            #include "botan_generated/botan_ios_arm64.cpp"
        #else
            // Intel Mac - portable implementation
            #include "botan_generated/botan_generic.cpp"
        #endif
    #endif
#elif defined(__ANDROID__)
    // Android platform
    #if defined(__aarch64__) || defined(_M_ARM64)
        // Android ARM64 (arm64-v8a) - hardware accelerated
        #include "botan_generated/botan_android_arm64.cpp"
    #else
        // Android other architectures - portable implementation
        #include "botan_generated/botan_generic.cpp"
    #endif
#else
    // Generic fallback for other platforms
    #include "botan_generated/botan_generic.cpp"
#endif

// No global instances needed - everything is inline or compile-time
