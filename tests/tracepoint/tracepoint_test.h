#include <ust/tracepoint.h>

DECLARE_TRACE(ust_event, TP_PROTO(unsigned int v), TP_ARGS(v));
DECLARE_TRACE(ust_event2, TP_PROTO(unsigned int v), TP_ARGS(v));

struct message {
	char *payload;
};
