public class Program
{
    public static void Main()
    {
        // Ustaw N=6 przed jakąkolwiek operacją na Rq/BFV
        Rq.SetN(6);
        var bfv = new BFV();

        // Test 1: Dodawanie i mnożenie prostych wiadomości
        var m1arr = new int[Rq.N];
        var m2arr = new int[Rq.N];
        m1arr[0] = 1; // wiadomość = 1
        m2arr[0] = 2; // wiadomość = 2
        var m1 = new Rq(m1arr);
        var m2 = new Rq(m2arr);

        var ct1 = bfv.Encrypt(m1);
        var ct2 = bfv.Encrypt(m2);

        var ct_sum = bfv.Add(ct1, ct2);
        var ct_mul = bfv.Mul(ct1, ct2);
        var decrypted_sum = bfv.Decrypt(ct_sum);
        var decrypted_mul = bfv.Decrypt(ct_mul);

        Console.WriteLine($"Test 1: N = {Rq.N}, t = {BFV.t}, q = {BFV.q}");
        Console.WriteLine($"M1: {m1}");
        Console.WriteLine($"M2: {m2}");
        Console.WriteLine($"Dec(M1 + M2): {decrypted_sum}");
        Console.WriteLine($"Dec(M1 * M2): {decrypted_mul}");

        // Test 2: Dodawanie wielomianów z kilkoma współczynnikami
        var m3arr = new int[Rq.N];
        var m4arr = new int[Rq.N];
        m3arr[0] = 3; m3arr[2] = 4; m3arr[5] = 1;
        m4arr[1] = 2; m4arr[2] = 1; m4arr[4] = 5;
        var m3 = new Rq(m3arr);
        var m4 = new Rq(m4arr);
        var ct3 = bfv.Encrypt(m3);
        var ct4 = bfv.Encrypt(m4);
        var ct3_add_4 = bfv.Add(ct3, ct4);
        var ct3_mul_4 = bfv.Mul(ct3, ct4);
        var dec3_add_4 = bfv.Decrypt(ct3_add_4);
        var dec3_mul_4 = bfv.Decrypt(ct3_mul_4);

        Console.WriteLine("\nTest 2: Wielomiany");
        Console.WriteLine($"M3: {m3}");
        Console.WriteLine($"M4: {m4}");
        Console.WriteLine($"Dec(M3 + M4): {dec3_add_4}");
        Console.WriteLine($"Dec(M3 * M4): {dec3_mul_4}");

        // Test 3: Homomorficzne sumowanie 5x tej samej wiadomości
        var m5arr = new int[Rq.N];
        m5arr[0] = 1;
        var m5 = new Rq(m5arr);
        var ct5 = bfv.Encrypt(m5);
        var ct_sum5 = ct5;
        for (int i = 0; i < 4; i++) ct_sum5 = bfv.Add(ct_sum5, ct5);
        var dec_sum5 = bfv.Decrypt(ct_sum5);
        Console.WriteLine("\nTest 3: Homomorficzne sumowanie 5x tej samej wiadomości");
        Console.WriteLine($"Dec(5 * M5): {dec_sum5}");

        // Test 4: Homomorficzne mnożenie 3x tej samej wiadomości
        var ct_mul3 = ct5;
        for (int i = 0; i < 2; i++) ct_mul3 = bfv.Mul(ct_mul3, ct5);
        var dec_mul3 = bfv.Decrypt(ct_mul3);
        Console.WriteLine("\nTest 4: Homomorficzne mnożenie 3x tej samej wiadomości");
        Console.WriteLine($"Dec(M5^3): {dec_mul3}");
    }
}
