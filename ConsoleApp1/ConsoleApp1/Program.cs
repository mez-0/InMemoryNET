using System;

namespace ConsoleApp1
{
    public class Program
    {
        public static void Main(string[] args)
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
            return;
        }
    }
}