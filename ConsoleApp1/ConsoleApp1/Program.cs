<<<<<<< HEAD
using Microsoft.Win32;
using System;
=======
﻿using System;
>>>>>>> d5be2ba87d3c38f581dca7c4248658564c1315ac

namespace ConsoleApp1
{
    public class Program
    {
<<<<<<< HEAD
        public static int Main()
=======
        public static void Main(string[] args)
>>>>>>> d5be2ba87d3c38f581dca7c4248658564c1315ac
        {
            Console.WriteLine("|----> Hello From .NET <----|");
            Console.WriteLine("Arguments: " + args.Length);
            if(args.Length > 0)
            {
                foreach(string arg in args)
                {
                    Console.WriteLine("\t|> Argument: " + arg);
                }
            }
<<<<<<< HEAD
            return 0;
=======
            return;
>>>>>>> d5be2ba87d3c38f581dca7c4248658564c1315ac
        }
    }
}
