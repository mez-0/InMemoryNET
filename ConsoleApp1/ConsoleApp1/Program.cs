using Microsoft.Win32;
using System;

namespace ConsoleApp1
{
    public class Program
    {
        public static int EntryPoint(string arguments)
        {
            string[] version_names = null;
            RegistryKey installed_versions = null;

            try
            {
                // Get the key
                installed_versions = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                Environment.Exit(1);
            }

            // Get all the subkeys
            version_names = installed_versions.GetSubKeyNames();

            if (version_names == null)
            {
                Console.WriteLine("No .NET Registry Keys found(?)");
                Environment.Exit(1);
            }
            else
            {
                version_names = installed_versions.GetSubKeyNames();
            }

            Console.WriteLine("[!]\tInstalled .NET Versions:");
            foreach (String version in version_names)
            {
                if (version.StartsWith("v"))
                {
                    Console.WriteLine(String.Format("[+]\t{0}", version));
                }
            }
            return 0;
        }
        public static void Main()
        {
        }
    }
}