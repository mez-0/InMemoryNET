# InMemoryNET

This project is entirely a POC, it was my research into looking at how [execute-assembly](https://blog.cobaltstrike.com/2018/04/09/cobalt-strike-3-11-the-snake-that-eats-its-tail/) works within Cobalt Strike. 

I originally wrote this about two years ago, but I felt I needed to update to download file remotely in order to test [In-Process Patchless AMSI Bypass](https://gist.github.com/CCob/fe3b63d80890fafeca982f76c8a3efdf/raw/1fce7ac5e3e6b69c041816da03f883c14765dea4/patchless_amsi.h) from [EthicalChaos](https://twitter.com/_EthicalChaos_). Albeit, this project does NOT contain that POC. 

InMemoryNET will:

1. Reach out to a URL
2. Download a file to a buffer
3. Execute via CLR

Referenced projects:

1. [HostingCLR](https://github.com/etormadiv/HostingCLR/)
2. [metasploit-execute-assembly](https://github.com/b4rtik/metasploit-execute-assembly)
3. [Hiding your .NET - ETW](https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/)

Example:

```
 ~ InMemoryNET ~
InMemoryNET.exe <url> <assembly args>
```

![](/images/example.PNG)
