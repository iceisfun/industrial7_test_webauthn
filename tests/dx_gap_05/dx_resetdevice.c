/* State-changing area for WebAuthNCtapResetDevice. The call selects a physical authenticator and
 * issues a CTAP reset, which erases credentials, and no argument combination is rejected before
 * device work; therefore it is intentionally never invoked. Resolve-only. */
#include "t.h"

TEST(dx_gap5_resetdevice_resolves_only) {
    FARPROC p = t_proc_in("webauthn.dll", "WebAuthNCtapResetDevice");
    REQUIRE(p);
    CHECK(p != NULL);
    t_note("destructive export; deliberately not called");
}
