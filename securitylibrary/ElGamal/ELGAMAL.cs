using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>



        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> res = new List<long> { };


            long c1 = kiki(q, alpha, k);
            int K = kiki(q, y, k);
            long C2 = (K * m) % q;
            res.Add(c1);
            res.Add(C2);

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

        public int Decrypt(int c1, int c2, int x, int q)
        {
            int K = kiki(q, c1, x);
            var extented_res = koko(q, K);
            c2 = c2 % q;
            int M = (c2 * extented_res) % q;
            return M;
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



    }
}
