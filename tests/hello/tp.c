#include "tp.h"
#include <ust/marker.h>
#include "usterr.h"

DEFINE_TRACE(hello_tptest);

void tptest_probe(int anint)
{
	DBG("in tracepoint probe...");
	trace_mark(ust, tptest, "anint %d", anint);
}

static void __attribute__((constructor)) init()
{
	DBG("connecting tracepoint...");
	register_trace_hello_tptest(tptest_probe);
}
