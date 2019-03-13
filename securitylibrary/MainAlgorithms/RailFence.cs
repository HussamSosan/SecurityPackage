using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int depth = 0, index = 0,length=plainText.Length;
            cipherText = cipherText.ToLower();
            while(true)
            {
                index = cipherText.IndexOf(plainText[1],index+1);
                depth =(int)Math.Ceiling(Convert.ToDecimal(length /(float)index));

                if (cipherText[1] == plainText[depth%length]) break;
            }
            return depth;
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText;
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            string cipherText;
            return cipherText;
        }
    }
}
