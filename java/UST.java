import java.util.*;

class UST {
	public static native void ust_java_event(String name, String arg);
	static {
		System.loadLibrary("ustjava");
	}
}

