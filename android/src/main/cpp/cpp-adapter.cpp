#include <jni.h>
#include "metamask_nativeutilsOnLoad.hpp"

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  return margelo::nitro::metamask_nativeutils::initialize(vm);
}
