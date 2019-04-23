using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            var n = p * q;
            var x = kiki(n, M, e);
            return x;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            var n = p * q;
            var a = (p - 1) * (q - 1);
            var d = koko(a, e);
            var x = kiki(n, C, d);
            return x;
        }
        public static int koko(int mod, int number)
        {
            var a = mod;
            var res = 0;
            var w = 1;
            int z = 0;
            var temp = 0;
            for (int j = 0; number > 0; j++)
            {
                var temp1 = a / number;
                var x = number;
                number = a % x;
                temp = x;
                a = temp;
                temp = w;
                x = temp;
                temp = temp1 * x;
                w = res - temp;
                temp = x;
                res = temp;
            }
            temp = res % mod;
            res = temp;
            if (res >= 0)
            {
                z++;
            }
            else
                temp = res + mod;
            res = temp % mod;
            return res;
        }

        public static int kiki(int q, int alpha, int xb)
        {
            var Yb = 0.0;

            if (xb % 2 == 0)
            {


                int i = xb / 2;
                var a1 = Math.Pow(alpha, 2) % q;
                var temp = 1.0;
                for (int j = 0; j < i; j++)
                {
                    temp *= a1;
                    temp %= q;
                }

                Yb = temp % q;

            }
            else
            {
                xb = xb - 1;
                int i = xb / 2;
                var aa1 = Math.Pow(alpha, 2) % q;
                var temp = Math.Pow(alpha, 1) % q;

                for (int j = 0; j < i; j++)
                {
                    temp *= aa1;
                    temp %= q;
                }

                Yb = temp % q;
                xb++;
            }
            return (int)Yb;
        }


    }
}
