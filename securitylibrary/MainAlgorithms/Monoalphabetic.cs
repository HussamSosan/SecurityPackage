using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            char[] key = new char[26];
            for (int index = 0; index < plainText.Length; index++)
            {
                int chars = ((plainText[index]) - 'a');
                key[chars] = (cipherText[index]);
            }
            char ch = 'A';
            for (int i = 0; i < 26; i++)
            {
                if (key[i] == '\0')
                {
                    while (key.Contains(ch)) { ch++; }
                    key[i] = ch;
                }

            }
            return new string(key).ToLower();
        }
        
        public string Decrypt(string cipherText, string key)
        {
            string plainText="" ;
            cipherText = cipherText.ToLower();
            foreach(char x in cipherText)
            {
                int index = key.IndexOf(x);
                plainText += (char)('a'+index);
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {

            char[] cipherText = new char[plainText.Length];
            for (int index = 0; index < plainText.Length; index++)
            {

                int chars = (char)(plainText[index] - 97);
                cipherText[index] += (char)key[chars];
            }

            return new string(cipherText);
        }
        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            char[] char_analysis = {'e','t','a','o','i','n',
                                    's','r','h','l','d','c',
                                    'u','m','f','p','g','w',
                                    'y','b','v','k','x','j','q','z'};
            string Plaintext ="";
            Dictionary<char, int> char_freq = new Dictionary<char, int>();
            Dictionary<char, char> char_map = new Dictionary<char, char>();
            int index = 0;
            foreach (char ch in cipher)
            {
                if (!char_freq.ContainsKey(ch))
                    char_freq.Add(ch, 1);
                else
                    char_freq[ch] ++;
            }
            foreach (KeyValuePair<char, int> elemnt in char_freq.OrderByDescending(key => key.Value))
            {
                char_map.Add(elemnt.Key,char_analysis[index++]);
            }
            foreach (char ch in cipher)
            {
                Plaintext+= char_map[ch];
            }
            return Plaintext;
        }
    }
}
