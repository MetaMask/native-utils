#pragma once

// Architecture detection and conditional Botan inclusion
// This header automatically selects the optimal Botan build based on target architecture

// Platform and architecture detection
#if defined(__APPLE__)
    #include <TargetConditionals.h>
    #if TARGET_OS_IOS
        // iOS device or simulator
        #if defined(__aarch64__) || defined(_M_ARM64)
            // iOS ARM64 (physical devices)
            #include "botan_generated/botan_ios_arm64.h"
            #define BOTAN_ARCH_OPTIMIZED 1
            #define BOTAN_ARCH_NAME "iOS-ARM64-optimized"
            #define BOTAN_PLATFORM "iOS"
        #else
            // iOS simulator (x86_64)
            #include "botan_generated/botan_generic.h"
            #define BOTAN_ARCH_OPTIMIZED 0
            #define BOTAN_ARCH_NAME "iOS-Simulator-generic"
            #define BOTAN_PLATFORM "iOS-Simulator"
        #endif
    #else
        // macOS
        #if defined(__aarch64__) || defined(_M_ARM64)
            // Apple Silicon Mac
            #include "botan_generated/botan_ios_arm64.h"
            #define BOTAN_ARCH_OPTIMIZED 1
            #define BOTAN_ARCH_NAME "macOS-ARM64-optimized"
            #define BOTAN_PLATFORM "macOS"
        #else
            // Intel Mac
            #include "botan_generated/botan_generic.h"
            #define BOTAN_ARCH_OPTIMIZED 0
            #define BOTAN_ARCH_NAME "macOS-Intel-generic"
            #define BOTAN_PLATFORM "macOS"
        #endif
    #endif
#elif defined(__ANDROID__)
    // Android platform
    #if defined(__aarch64__) || defined(_M_ARM64)
        // Android ARM64 (arm64-v8a)
        #include "botan_generated/botan_android_arm64.h"
        #define BOTAN_ARCH_OPTIMIZED 1
        #define BOTAN_ARCH_NAME "Android-ARM64-optimized"
        #define BOTAN_PLATFORM "Android"
    #else
        // Android other architectures (x86, x86_64, armeabi-v7a)
        #include "botan_generated/botan_generic.h"
        #define BOTAN_ARCH_OPTIMIZED 0
        #define BOTAN_ARCH_NAME "Android-generic"
        #define BOTAN_PLATFORM "Android"
    #endif
#else
    // Generic fallback for other platforms
    #include "botan_generated/botan_generic.h"
    #define BOTAN_ARCH_OPTIMIZED 0
    #define BOTAN_ARCH_NAME "Generic-portable"
    #define BOTAN_PLATFORM "Generic"
#endif

// Unified namespace - all Botan headers use the same namespace
using namespace Botan;
