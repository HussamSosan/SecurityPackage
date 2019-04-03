using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES algorithm = new DES();
            string plain = algorithm.Decrypt(cipherText, key[0]);
            plain = algorithm.Encrypt(plain, key[1]);
            plain = algorithm.Decrypt(plain, key[0]);
            return plain;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES algorithm = new DES();
            string cipher = algorithm.Encrypt(plainText, key[0]);
            cipher = algorithm.Decrypt(cipher, key[1]);
            cipher = algorithm.Encrypt(cipher, key[0]);
            return cipher;
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
