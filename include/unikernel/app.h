#pragma once

// UniKernel Application API
//
// Your application implements uni_main() as its entry point.
// The unikernel runtime initializes hardware, networking, and memory
// before calling your function. All driver and network calls are
// direct in-process function calls — zero syscall overhead.
//
// Example:
//   #include <unikernel/app.h>
//   #include "net/http.h"
//
//   int uni_main() {
//       net::http::Server server(80);
//       server.route("/", my_handler);
//       server.run();
//       return 0;
//   }

// Application entry point — implement this in your application.
// Called after all subsystems are initialized.
// Return 0 for success, non-zero for error.
extern "C" int uni_main();
