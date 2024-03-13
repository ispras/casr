using SharpFuzz;

public class Program {
    public static void Main(string[] args) {
        Fuzzer.OutOfProcess.Run(stream => {
            using (var reader = new StreamReader(args[0])) {
                if (reader.BaseStream.Length < 4)
                    return;

                string buffer = reader.ReadLine();
                f1(buffer);
            }
        });
    }

    public static void f1(string s) {
        Module.f2(s);
    }
}
