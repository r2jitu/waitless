// uni/native_main.cc — Entry point for the native host process.
//
// Calls uni_init_native() (SIGINT handler, SIGPIPE suppression, $PORT parsing)
// then uni_main(), the same application entry point used by the unikernel.

// Provided by native.cc
extern "C" void uni_init_native();
// Provided by the Rust application (e.g. apps/webserver/main.rs).
extern "C" int uni_main();

int main() {
  uni_init_native();
  return uni_main();
}
