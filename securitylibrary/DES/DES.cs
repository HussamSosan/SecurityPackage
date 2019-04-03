using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        string[] toBin =
        {
            "0000","0001","0010","0011","0100","0101","0110","0111",
            "1000","1001","1010","1011","1100","1101","1110","1111"
        };
        int[] LeftShifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        int[] PC1 =
        {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };
        int[] PC2 =
      {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };
        int[] IP =
        {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };
        int[] ExpansionMat =
        {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };
        int[] P =
        {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
        };
       int[] IPinverse =
       {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };
        int[,] SBoxes =
        {
            {
                14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
            },
            {
                15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
            },
            {
                10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
            },
            {
                7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
            },
            {
                2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
            },
            {
                12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
            },
            {
                4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
            },
            {
                13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
            }
        };


        char XOR(char x,char y)
        { 
            if((x == '0' && y == '1') || (x == '1' && y == '0'))
            {
                return '1';
            }
            else
            {
                return '0';
            }
        }

        int toInt2(string input)
        {
            if(input == "00")
            {
                return 0;
            }
            else if (input == "01")
            {
                return 1;
            }
            else if (input == "10")
            {
                return 2;
            }
            else
            {
                return 3;
            }
        }

        int toInt4(string input)
        {
            if (input == "0000")
            {
                return 0;
            }
            else if (input == "0001")
            {
                return 1;
            }
            else if (input == "0010")
            {
                return 2;
            }
            else if (input == "0011")
            {
                return 3;
            }
            else if (input == "0100")
            {
                return 4;
            }
            else if (input == "0101")
            {
                return 5;
            }
            else if (input == "0110")
            {
                return 6;
            }
            else if (input == "0111")
            {
                return 7;
            }
            else if (input == "1000")
            {
                return 8;
            }
            else if (input == "1001")
            {
                return 9;
            }
            else if (input == "1010")
            {
                return 10;
            }
            else if (input == "1011")
            {
                return 11;
            }
            else if (input == "1100")
            {
                return 12;
            }
            else if (input == "1101")
            {
                return 13;
            }
            else if (input == "1110")
            {
                return 14;
            }
            else
            {
                return 15;
            }

        }

        char toHEX(string input)
        {
            if (input == "0000")
            {
                return '0';
            }
            else if (input == "0001")
            {
                return '1';
            }
            else if (input == "0010")
            {
                return '2';
            }
            else if (input == "0011")
            {
                return '3';
            }
            else if (input == "0100")
            {
                return '4';
            }
            else if (input == "0101")
            {
                return '5';
            }
            else if (input == "0110")
            {
                return '6';
            }
            else if (input == "0111")
            {
                return '7';
            }
            else if (input == "1000")
            {
                return '8';
            }
            else if (input == "1001")
            {
                return '9';
            }
            else if (input == "1010")
            {
                return 'A';
            }
            else if (input == "1011")
            {
                return 'B';
            }
            else if (input == "1100")
            {
                return 'C';
            }
            else if (input == "1101")
            {
                return 'D';
            }
            else if (input == "1110")
            {
                return 'E';
            }
            else
            {
                return 'F';
            }

        }

        public override string Decrypt(string cipherText, string key)
        {
            string plainText = String.Empty;
           

            //convert key to string of 1's and 0's
            StringBuilder binaryKey = new StringBuilder();
            for (int i = 2; i < key.Length; i++)
            {
                binaryKey.Append(toBin[int.Parse(key[i].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
            }

            // apply PC1
            StringBuilder PC1key = new StringBuilder();
            for (int i = 0; i < PC1.Length; i++)
            {
                PC1key.Append(binaryKey[PC1[i] - 1]);
            }

            //calculate Cn and Dn 
            string[] C = new string[17];
            string[] D = new string[17];

            C[0] = PC1key.ToString().Substring(0, 28);
            D[0] = PC1key.ToString().Substring(28, 28);

            string shifted_C = C[0];
            string shifted_D = D[0];
            char rightMost;
            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < LeftShifts[i]; j++)
                {
                    rightMost = shifted_C[0];
                    shifted_C = shifted_C.Remove(0, 1);
                    shifted_C += rightMost;

                    rightMost = shifted_D[0];
                    shifted_D = shifted_D.Remove(0, 1);
                    shifted_D += rightMost;
                }
                C[i + 1] = shifted_C;
                D[i + 1] = shifted_D;
            }

            //calculate Kn
            string[] K = new string[16];
            for (int i = 0; i < K.Length; i++)
            {
                K[i] = C[i + 1] + D[i + 1];
            }

            //apply PC2
            StringBuilder[] roundKey = new StringBuilder[16];
            for (int i = 0; i < K.Length; i++)
            {
                roundKey[i] = new StringBuilder();
                for (int j = 0; j < PC2.Length; j++)
                {
                    roundKey[i].Append(K[i][PC2[j] - 1]);
                }
            }

            //start decrypting cipher text

            //conver palint text to array of 0's and 1's
            StringBuilder binaryCipherText = new StringBuilder();
            for (int i = 2; i < key.Length; i++)
            {
                binaryCipherText.Append(toBin[int.Parse(cipherText[i].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
            }

            //apply initial permutation
            StringBuilder initialPermutation = new StringBuilder();
            for (int i = 0; i < IP.Length; i++)
            {
                initialPermutation.Append(binaryCipherText[IP[i] - 1]);
            }

            //calculate Ln and Rn
            string[] L = new string[17];
            string[] R = new string[17];

            L[0] = initialPermutation.ToString().Substring(0, 32);
            R[0] = initialPermutation.ToString().Substring(32, 32);

            StringBuilder expandedR;
            StringBuilder xorOutput;
            StringBuilder sboxOutput;
            StringBuilder permutationOutput;
            string Bn;
            int row;
            int column;
            
            //repeat process for 16 round
            for (int i = 1; i < 17; i++)
            {
                L[i] = R[i - 1];
                expandedR = new StringBuilder();
                xorOutput = new StringBuilder();
                sboxOutput = new StringBuilder();
                permutationOutput = new StringBuilder();
                //expand R
                for (int j = 0; j < ExpansionMat.Length; j++)
                {
                    expandedR.Append(R[i - 1][ExpansionMat[j] - 1]);
                }
                // E(Ri) xor Ki
                for (int j = 0; j < expandedR.Length; j++)
                {
                    xorOutput.Append(XOR(expandedR[j], roundKey[15-(i - 1)][j]));
                }
                // apply sbox
                for (int j = 0; j < 8; j++)
                {
                    Bn = xorOutput.ToString().Substring(6 * j, 6);
                    row = toInt2(Bn[0] + string.Empty + Bn[5]);
                    column = toInt4(Bn.Substring(1, 4));
                    sboxOutput.Append(toBin[SBoxes[j, (row * 16) + column]]);
                }
                //apply permutation
                for (int j = 0; j < P.Length; j++)
                {
                    permutationOutput.Append(sboxOutput[P[j] - 1]);
                }
                //calculate Ri
                xorOutput = new StringBuilder();
                for (int j = 0; j < permutationOutput.Length; j++)
                {
                    xorOutput.Append(XOR(L[i - 1][j], permutationOutput[j]));
                }
                R[i] = xorOutput.ToString();
            }

            string R16L16 = R[16] + L[16];
            StringBuilder binaryPlainText = new StringBuilder();
            //apply p^-1
            for (int i = 0; i < IPinverse.Length; i++)
            {
                binaryPlainText.Append(R16L16[IPinverse[i] - 1]);
            }

            //conver output to HEX
            plainText += "0x";
            for (int i = 0; i < 16; i++)
            {
                plainText += toHEX(binaryPlainText.ToString().Substring(4 * i, 4));
            }
            return plainText;
        }

        public override string Encrypt(string plainText, string key)
        {
            string cipherText = String.Empty;

            //convert key to string of 1's and 0's
            StringBuilder binaryKey = new StringBuilder();
            for(int i=2;i<key.Length;i++)
            {
              binaryKey.Append(toBin[int.Parse(key[i].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
            }

            // apply PC1
            StringBuilder PC1key = new StringBuilder();
            for(int i=0;i<PC1.Length;i++)
            {
                PC1key.Append(binaryKey[PC1[i]-1]);
            }

            //calculate Cn and Dn 
            string[] C = new string[17];
            string[] D = new string[17];

            C[0] = PC1key.ToString().Substring(0  , 28);
            D[0] = PC1key.ToString().Substring(28 , 28);

            string shifted_C = C[0] ;
            string shifted_D = D[0] ;
            char rightMost ;
            for(int i=0;i<16;i++)
            {
                for (int j=0;j<LeftShifts[i];j++)
                {
                    rightMost = shifted_C[0];
                    shifted_C = shifted_C.Remove(0, 1);
                    shifted_C += rightMost;

                    rightMost = shifted_D[0];
                    shifted_D = shifted_D.Remove(0, 1);
                    shifted_D += rightMost;
                }
                C[i + 1] = shifted_C;
                D[i + 1] = shifted_D;
            }

            //calculate Kn
            string[] K = new string[16];
            for(int i=0;i<K.Length;i++)
            {
                K[i] = C[i + 1] + D[i + 1];
            }

            //apply PC2
            StringBuilder[] roundKey = new StringBuilder[16];
            for(int i=0;i<K.Length;i++)
            {
                roundKey[i] = new StringBuilder();
                for(int j=0;j<PC2.Length;j++)
                {
                    roundKey[i].Append(K[i][ PC2[j] - 1 ]);
                }
            }

            //start encrypting plain text

            //conver palint text to array of 0's and 1's
            StringBuilder binaryPlainText = new StringBuilder();
            for (int i = 2; i < key.Length; i++)
            {
                binaryPlainText.Append(toBin[int.Parse(plainText[i].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
            }

            //apply initial permutation
            StringBuilder initialPermutation = new StringBuilder();
            for (int i = 0; i < IP.Length; i++)
            {
                initialPermutation.Append(binaryPlainText[IP[i] - 1]);
            }

            //calculate Ln and Rn
            string[] L = new string[17];
            string[] R = new string[17];

            L[0] = initialPermutation.ToString().Substring(0, 32);
            R[0] = initialPermutation.ToString().Substring(32, 32);

            StringBuilder expandedR;
            StringBuilder xorOutput;
            StringBuilder sboxOutput;
            StringBuilder permutationOutput;
            string Bn;
            int row;
            int column;
            //repeat process for 16 round
            for(int i=1;i<17;i++)
            {
                L[i] = R[i - 1];
                expandedR = new StringBuilder();
                xorOutput = new StringBuilder();
                sboxOutput = new StringBuilder();
                permutationOutput = new StringBuilder();
                //expand R
                for(int j=0;j<ExpansionMat.Length;j++)
                {
                    expandedR.Append(R[i-1][ ExpansionMat[j] - 1 ]);
                }
                // E(Ri) xor Ki
                for (int j = 0; j < expandedR.Length; j++)
                {
                    xorOutput.Append( XOR(expandedR[j], roundKey[i - 1][j]) );
                }
                // apply sbox
                for (int j = 0; j < 8; j++)
                {
                    Bn = xorOutput.ToString().Substring(6 * j, 6);
                    row = toInt2(Bn[0] + string.Empty + Bn[5]);
                    column = toInt4(Bn.Substring(1,4));
                    sboxOutput.Append(toBin[SBoxes[j, (row * 16) + column]]);
                }
                //apply permutation
                for (int j = 0; j < P.Length; j++)
                {
                    permutationOutput.Append(sboxOutput[P[j] - 1]);
                }
                //calculate Ri
                xorOutput = new StringBuilder();
                for (int j = 0; j < permutationOutput.Length; j++)
                {
                    xorOutput.Append( XOR(L[i - 1][j], permutationOutput[j]));
                }
                R[i] = xorOutput.ToString();
            }

            string R16L16 = R[16] + L[16];
            StringBuilder binaryCipherText = new StringBuilder();
            //apply p^-1
            for (int i = 0; i < IPinverse.Length; i++)
            {
                binaryCipherText.Append(R16L16[IPinverse[i] - 1]);
            }

            //conver output to HEX
            cipherText += "0x";
            for (int i = 0; i < 16; i++)
            {
                cipherText += toHEX( binaryCipherText.ToString().Substring(4 * i, 4) );
            }
            return cipherText;
        }
    }
}
