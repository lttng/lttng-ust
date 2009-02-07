#define __printf(a,b)			__attribute__((format(printf,a,b)))

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

#define notrace __attribute__((no_instrument_function))
