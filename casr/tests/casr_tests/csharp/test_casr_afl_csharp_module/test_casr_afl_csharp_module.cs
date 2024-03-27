using System;
using System.IO;

public static class Module {
    public static void f2(string s) {
        if (s[0] == 'b')
            Console.WriteLine("Path 1T");
        else
            throw new IndexOutOfRangeException("Index out of range");

        if (s[1] == 'a')
            Console.WriteLine("Path 1T");
        else
            throw new ArgumentException("Parameter cannot be null");

        if (s[2] == 'd')
            Console.WriteLine("Path 1T");
        else
            throw new System.IO.IOException("IO error");
    }
}
