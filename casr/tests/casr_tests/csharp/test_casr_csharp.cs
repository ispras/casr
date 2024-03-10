using System;

public class Program
{
  public static void Main(string[] args)
  {
    f1();
  }
  
  public static void f1() {
    f2();
  }

  public static void f2() {
    throw new ArgumentException("Parameter cannot be null");
  }
}
