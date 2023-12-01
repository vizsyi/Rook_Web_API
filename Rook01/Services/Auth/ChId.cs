﻿using System.Collections.Generic;
using System.Text;

namespace Rook01.Services.Auth
{
    public class Chid
    {
        public static string NewChid(byte limit, short length)
        {
            if (limit > 64 || limit == 0 || length < 0 || length > 4095) throw new ArgumentException();

            Random rand = new();
            StringBuilder stringBuilder = new();
            for(var i = 0; i < length; i++)
            {
                var r = rand.Next(0, limit);
                var c = (Byte)(r > 35
                    ? (r > 61 ? (r == 62 ? 45 : 95) : r + 61)
                    : (r > 9 ? r + 55 : r + 48));
                stringBuilder.Append(Convert.ToChar(c));
            }
            return stringBuilder.ToString();
        }

        public static string NewFullChid(short length)
        {
            if (length < 0 || length > 4095) throw new ArgumentException();

            Random rand = new();
            StringBuilder stringBuilder = new();
            for (var i = 0; i < length; i++)
            {
                var c = (Byte)rand.Next(0, 255);
                stringBuilder.Append(Convert.ToChar(c));
            }
            return stringBuilder.ToString();
        }

    }
}
