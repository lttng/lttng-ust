#include <stdio.h>
#include <string.h>

int main()
{
	char buf[100];

	char *expected;

	expected = "header 9999, hello, 005, '    9'";
	ust_safe_snprintf(buf, 99, "header %d, %s, %03d, '%3$*d'", 9999, "hello", 5, 9);
	if(strcmp(buf, expected) != 0) {
		printf("Error: expected \"%s\" and got \"%s\"\n", expected, buf);
		return 1;
	}

	return 0;
}
