public class Test2 {

    static {
        System.loadLibrary("native");
    }
    
    public static void main(String[] args) {
        new Test2().heapbufferoverflow();
    }

    private native int heapbufferoverflow();
}
