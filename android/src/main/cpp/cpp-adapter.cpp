#include <jni.h>
#include "nitrosecp256k1OnLoad.hpp"

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  return margelo::nitro::nitrosecp256k1::initialize(vm);
}
