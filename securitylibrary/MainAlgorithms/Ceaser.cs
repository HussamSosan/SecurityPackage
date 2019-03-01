using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        char[] alpha = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
        public string Encrypt(string plainText, int key)
        {
            char[] original = plainText.ToCharArray();
            for (int i = 0; i < original.Length; i++)
            {
                char letter = original[i];
                char first = alpha[0];
                int index = letter - first;
                int cypherindex = (index + key) % alpha.Length;
                original[i] = alpha[cypherindex];

            }
            return new string(original);
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();

            char[] original = cipherText.ToCharArray();

            for (int i = 0; i < original.Length; i++)
            {
                char letter = original[i];
                char first = alpha[0];
                int index = letter - first;
                int oindex = (index - key);
                if (oindex < 0)
                {
                    oindex = Math.Abs(oindex + 26);
                    original[i] = alpha[oindex];

                }
                else
                    original[i] = alpha[oindex];

            }

            return new string(original);

        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            char[] original_cipherText = cipherText.ToCharArray();
            char[] original_plainText = plainText.ToCharArray();


            char letter_ci = original_cipherText[1];
            char letter_pl = original_plainText[1];
            char first = alpha[0];
            int index_ci = letter_ci - first;
            int index_pl = letter_pl - first;

            int key = (index_ci - index_pl);
            if (key < 0)
            {
                return Math.Abs(key + 26);
            }

            else
            {

                return key;
            }
        }
    }
}
