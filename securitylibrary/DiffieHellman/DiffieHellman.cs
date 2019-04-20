using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {

            List<int> key = new List<int>();


            var Ya = 0.0;

            var Yb = 0.0;

            if (xa % 2 == 0)
            {


                int i = xa / 2;
                var a1 = Math.Pow(alpha, 2) % q;
                var temp = 1.0;
                for (int j = 0; j < i; j++)
                {
                    temp *= a1;
                    temp %= q;
                }

                Ya = temp % q;


            }
            else
            {
                xa = xa - 1;
                int i = xa / 2;
                var aa1 = Math.Pow(alpha, 2) % q;
                var temp = Math.Pow(alpha, 1) % q;

                for (int j = 0; j < i; j++)
                {
                    temp *= aa1;
                    temp %= q;
                }

                Ya = temp % q;
                xa++;
            }




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



            var Ka = 0.0;
            if (xa % 2 == 0)
            {


                int i = xa / 2;
                var x1 = Math.Pow(Yb, 2) % q;
                var temp = 1.0;
                for (int j = 0; j < i; j++)
                {
                    temp *= x1;
                    temp %= q;
                }

                Ka = temp % q;


            }
            else
            {
                xa = xa - 1;
                int i = xa / 2;
                var x1 = Math.Pow(Yb, 2) % q;
                var temp = Math.Pow(Yb, 1) % q;

                for (int j = 0; j < i; j++)
                {
                    temp *= x1;
                    temp %= q;
                }

                Ka = temp % q;

            }


            var Kb = 0.0;


            if (xb % 2 == 0)
            {

                int i = xb / 2;
                var x1 = Math.Pow(Ya, 2) % q;
                var temp = 1.0;
                for (int j = 0; j < i; j++)
                {
                    temp *= x1;
                    temp %= q;
                }

                Kb = temp % q;

            }
            else
            {
                xb = xb - 1;
                int i = xb / 2;
                var x1 = Math.Pow(Ya, 2) % q;
                var temp = Math.Pow(Ya, 1) % q;

                for (int j = 0; j < i; j++)
                {
                    temp *= x1;
                    temp %= q;
                }

                Kb = temp % q;
            }

            int ka = (int)Ka;
            key.Add(ka);
            int kb = (int)Kb;
            key.Add(kb);

            return key;


        }
    }
}
