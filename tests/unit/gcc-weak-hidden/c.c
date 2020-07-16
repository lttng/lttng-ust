int testint __attribute__((weak, visibility("hidden")));
void *testptr __attribute__((weak, visibility("hidden")));
struct {
	char a[24];
} testsym_24_bytes __attribute__((weak, visibility("hidden")));

void *testlibfct1_int(void)
{
	return &testint;
}

void *testlibfct1_ptr(void)
{
	return &testptr;
}

void *testlibfct1_24_bytes(void)
{
	return &testsym_24_bytes;
}
