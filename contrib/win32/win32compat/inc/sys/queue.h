/* Windows compat shim: redirect <sys/queue.h> to the openbsd-compat queue
 * implementation. Upstream (commit eeb671fa2) always shims <sys/queue.h> via
 * configure, which generates this redirect on every platform. Windows does not
 * run configure, so provide the equivalent redirect here. */
#include "openbsd-compat/sys-queue.h"
