#include <ust/tracepoint.h>

DECLARE_TRACEPOINT(ust_event, TP_PROTO(unsigned int v), TP_VARS(v));
DECLARE_TRACEPOINT(ust_event2, TP_PROTO(unsigned int v), TP_VARS(v));

struct message {
	char *payload;
};
