char testsym[9] __attribute__((weak, visibility("hidden")));

void *fct1(void)
{
	return testsym;
}
