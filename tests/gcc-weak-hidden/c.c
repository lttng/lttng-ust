char testsym[9] __attribute__((weak, visibility("hidden")));

void *fctlib1(void)
{
	return testsym;
}
