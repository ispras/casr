public class Test1 {
     public static void main(String args[]) throws HighLevelException{
         try {
             ma();
         } catch(HighLevelException e) {
            throw e;
         }
     }
     static void ma() throws HighLevelException {
        a();
     }
     static void a() throws HighLevelException {
         try {
             b();
         } catch(MidLevelException e) {
             throw new HighLevelException(e);
         }
     }
     static void b() throws MidLevelException {
         c();
     }
     static void c() throws MidLevelException {
         try {
             d();
         } catch(LowLevelException e) {
             f(e);
         }
     }
     static void d() throws LowLevelException {
        e();
     }
     static void e() throws LowLevelException {
         throw new LowLevelException();
     }
     static void f(LowLevelException e) throws MidLevelException {
         e.addSuppressed(new MidLevelException(new LowLevelException()));
         throw new MidLevelException(e);
     }
 }

 class HighLevelException extends Exception {
     HighLevelException(Throwable cause) { super(cause); }
 }

 class MidLevelException extends Exception {
     MidLevelException(Throwable cause)  { super(cause); }
 }

 class LowLevelException extends Exception {
 }
