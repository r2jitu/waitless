// uni/native_main.cc — Entry point for the native host process.
//
// Provides int main() which initialises the platform layer (SIGINT handler,
// SIGPIPE suppression, $PORT parsing) and then calls uni_main(), the same
// application entry point used by the unikernel.

#include "uni/uni.h"

// Provided by the application (e.g. apps/webserver/main.cc).
extern "C" int uni_main();

int main() {
  uni::init_native(); // also reads $PORT into uni::config_port()
  return uni_main();
}
