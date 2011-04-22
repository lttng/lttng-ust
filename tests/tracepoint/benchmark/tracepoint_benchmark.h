#include <ust/tracepoint.h>

DECLARE_TRACEPOINT(ust_event, TP_PROTO(unsigned int v), TP_ARGS(v));
