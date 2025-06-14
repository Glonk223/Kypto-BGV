using System;
using System.Diagnostics;

public class Benchmark
{
    public static void Maiin()
    {

        var bfv = new BFV();
        // Tworzenie wiadomości o długości Rq.N
        var m1arr = new int[Rq.N];
        var m2arr = new int[Rq.N];
        m1arr[0] = 1;
        m2arr[0] = 2;
        var m1 = new Rq(m1arr);
        var m2 = new Rq(m2arr);

        // Encrypt
        var sw = Stopwatch.StartNew();
        var ct1 = bfv.Encrypt(m1);
        var ct2 = bfv.Encrypt(m2);
        sw.Stop();
        Console.WriteLine($"Encrypt time: {sw.ElapsedMilliseconds} ms");

        // Add
        sw.Restart();
        var ctAdd = bfv.Add(ct1, ct2);
        sw.Stop();
        Console.WriteLine($"Add time: {sw.ElapsedMilliseconds} ms");

        // Mul
        sw.Restart();
        var ctMul = bfv.Mul(ct1, ct2);
        sw.Stop();
        Console.WriteLine($"Mul time: {sw.ElapsedMilliseconds} ms");

        // Wielokrotne mnożenie (np. 10x)
        var ct = ct1;
        sw.Restart();
        for (int i = 0; i < 10; i++)
        {
            ct = bfv.Mul(ct, ct2);
        }
        sw.Stop();
        Console.WriteLine($"10x Mul chain time: {sw.ElapsedMilliseconds} ms");

        // Decrypt
        sw.Restart();
        var dec = bfv.Decrypt(ct);
        sw.Stop();
        Console.WriteLine($"Decrypt time: {sw.ElapsedMilliseconds} ms");
    }
}
