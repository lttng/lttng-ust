#include <ust/tracepoint.h>

DECLARE_TRACE(hello_tptest,
	      TPPROTO(int anint),
	      TPARGS(anint));
