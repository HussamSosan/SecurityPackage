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
            cipherText = cipherText.ToLower();
            int len = (int)Math.Ceiling(Convert.ToDecimal(cipherText.Length / (float)key));
            string plainText = "";
            char[,] temp = new char[key, len];
            int index = 0;
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < len; j++)
                {
                    if (index == cipherText.Length) break;
                    temp[i, j] = cipherText[index++];
                }
            }

            for (int i = 0; i < len; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (temp[j, i] == '\0') break;
                    plainText += temp[j, i];
                }
            }
            
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            plainText = plainText.ToUpper();
            int len=(int)Math.Ceiling(Convert.ToDecimal(plainText.Length /(float)key));
            string cipherText="";
            char[,] temp =new char[key,len];
            int index=0;
            for (int i = 0; i < len; i++)
            {
                for(int j =0;j < key ;j++)
                {
                    if (index == plainText.Length) break;
                    temp[j, i] = plainText[index++];
                }
            }

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < len; j++)
                {
                    if (temp[i, j] == '\0') break;
                    cipherText += temp[i , j];
                }
            }

            return cipherText;
        }
    }
}
