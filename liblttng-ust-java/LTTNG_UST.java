class LTTNG_UST {
	public static native void lttng_ust_java_string(String name, String arg);
	static {
		System.loadLibrary("lttng-ust-java");
	}
}

