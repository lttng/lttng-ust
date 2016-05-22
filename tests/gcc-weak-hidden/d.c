int testint __attribute__((weak, visibility("hidden")));
void *testptr __attribute__((weak, visibility("hidden")));
struct {
	char a[24];
} testsym_24_bytes __attribute__((weak, visibility("hidden")));

void *testlibfct2_int(void)
{
	return &testint;
}

void *testlibfct2_ptr(void)
{
	return &testptr;
}

void *testlibfct2_24_bytes(void)
{
	return &testsym_24_bytes;
}
