char testsym[9] __attribute__((weak, visibility("hidden")));

void *fctlib2(void)
{
	return testsym;
}
