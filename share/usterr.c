#include <stdarg.h>
#include <unistd.h>

int safe_printf(const char *fmt, ...)
{
	static char buf[500];
	va_list ap;
	int n;

	va_start(ap, fmt);

	n = vsnprintf(buf, sizeof(buf), fmt, ap);

	write(STDOUT_FILENO, buf, n);

	va_end(ap);
}

