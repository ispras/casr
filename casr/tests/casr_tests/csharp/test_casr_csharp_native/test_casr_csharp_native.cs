using System;
using System.IO;
using System.Runtime.InteropServices;

public class Program
{
  public static void Seg()
  {
    [DllImport("native.so", EntryPoint="seg")]
    static extern void seg(int size);

    seg(100000000);
  }

  public static void Main(string[] args)
  {
    Seg();
  }
}
