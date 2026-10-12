/* Windows compat shim: redirect <sys/tree.h> to the openbsd-compat tree
 * implementation. Upstream (commit eeb671fa2) always shims <sys/tree.h> via
 * configure, which generates this redirect on every platform. Windows does not
 * run configure, so provide the equivalent redirect here. */
#include "openbsd-compat/sys-tree.h"
