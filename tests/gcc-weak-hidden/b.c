int testint __attribute__((weak, visibility("hidden")));
void *testptr __attribute__((weak, visibility("hidden")));
struct {
	char a[24];
} testsym_24_bytes __attribute__((weak, visibility("hidden")));

void *testfct_int(void)
{
	return &testint;
}

void *testfct_ptr(void)
{
	return &testptr;
}

void *testfct_24_bytes(void)
{
	return &testsym_24_bytes;
}
