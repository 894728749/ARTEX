using System;
public class ArtexFixture {
    public static string Frame(string input) {
        if (input == null) throw new ArgumentNullException("input");
        return "demo:" + input.Trim().ToUpperInvariant();
    }
    public static void Main() { Console.WriteLine(Frame(" artex ")); }
}
