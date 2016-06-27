This examples shows how to use LTTng-UST in a project that uses
CMake as the build system generator.

Build the libraries and applications
=====

```bash
mkdir build
cd build
cmake ..
make
```

3 shared libraries will be generated

```
libaligner-lib.so
libtester-lib.so
libtracepoint-provider.so
```


and 2 executables will be generated

```
aligner
tester
```



Trace the application tester
============================

The script trace.sh can be used.

```bash
lttng create
lttng enable-event -u 'gydle_om:*'
lttng start
./tester
lttng stop
lttng view > trace.txt
cat trace.txt
```

The content of trace.txt should be:

```
[21:45:34.940246019] (+?.?????????) osiris gydle_om:align_query: { cpu_id = 2 }, { query_name = "moleculeX" }
[21:45:34.940263188] (+0.000017169) osiris gydle_om:test_alignment: { cpu_id = 2 }, { alignment = "my-alignment" }
```
