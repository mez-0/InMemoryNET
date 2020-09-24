# InMemoryNET

This project is entirely a POC, it was my research into looking at how [execute-assembly](https://blog.cobaltstrike.com/2018/04/09/cobalt-strike-3-11-the-snake-that-eats-its-tail/) works within Cobalt Strike. The project contains two solutions:

1. [ConsoleApp1](./ConsoleApp1): An example C# Project that will be executed via the unmanaged code
2. [InMemoryNET](./InMemoryNET): The unmanaged code to execute .NET

As well as executing the .NET Assembly, it will patching AMSI and ETW and is intended to be purely a reference piece.

Referenced projects:

1. [HostingCLR](https://github.com/etormadiv/HostingCLR/)
2. [metasploit-execute-assembly](https://github.com/b4rtik/metasploit-execute-assembly)
3. [Hiding your .NET - ETW](https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/)