/* Windows compat shim: redirect <glob.h> to the openbsd-compat glob
 * implementation. Upstream (commit ecaaa4f) moved the USE_SYSTEM_GLOB
 * selection into configure, which generates a glob.h shim on platforms that
 * cannot use the system glob. Windows does not run configure, so this shim
 * provides the equivalent redirect. */
#include "openbsd-compat/glob.h"
