Fail2ban for Windows
====================

This project is an implmetation inspired by unix http://www.fail2ban.org.
F2B provides windows service that scans log data and detects attemps to guess
user password. Client IPv4/IPv6 address that causes significant login failures
can be automatically blocked for requested interval using windows firewall
configuration.



Requirements
------------

* Windows Vista and newer
* Visual C++ Redistributable for Visual Studio 2015
* .Net framework 4.5 (Windows Vista, 7, 2008 Server)
* Microsoft Message Queue (optional, for distributed Fali2ban)
* Visual Studio Community 2015 (optional, for building sources)

Building from sources
---------------------

* checkout sources from Git
```
  git clone https://github.com/vokac/F2B.git
```
* load F2B.sln project file in Visual Studio 2015
* Build -> Batch Build... -> Build
* create "Release" build with F2BWFP compiled as 32bit dll
  (if you want to build/use 64bit binaries you have to
   disable "prefered 32bit" compilation of the C#
   code and compile dll library as "Release|x64")

Installation
------------

No installation program exists and all binaries (F2BLogAnalyzer.exe,
F2BQueue.exe, F2BFirewall.exe, F2BWFP.dll) must be placed in one directory
(e.g. c:\F2B). F2B service code was written in C# which requires at least
.Net framework version 4.5. This .Net version is not integral part of older
windows (Vista, 7, 2008 Server) and must be installed on these systems.

F2B is using WFP API (Windows Filtering Platform) to access directly
functions that manages windows firewall configuration. This functionality
is provided by native C++/CLI code used to build F2BWFP.dll library and
it requires redistributable Visual C++ package (x86/x64). You can download
and install redistributable package directly from Microsoft or you can
just copy all required libraries in the F2B directory. Be aware that debug
build of the F2B code needs debug version of C++ libraries and they come
only with full Visual Studio installation.

Filtering rules in WFP can be associated with F2B application after we
apply few changes in WFP configuration using
```
c:\F2B\F2BFirewall.exe add-wfp
```


Configuration
-------------

F2B configuration is stored in F2BLogAnalyzer XML file. Source distribution
of this application contain example with all supported configuration options.

* Standalone

```
c:\F2B\F2BFirewall.exe add-wfp
c:\F2B\F2BLogAnalyzer.exe install -c c:\F2B\F2BLogAnalyzer.exe.config \
        -g c:\F2B\F2BLogAnalyzer.log -l ERROR
sc start F2BLA
```

* Distributed

 * log analyzer machine
 ```
c:\F2B\F2BLogAnalyzer.exe install -g c:\F2B\F2BLogAnalyzer.log -l ERROR \
        -c c:\F2B\F2BLogAnalyzer.exe.config
sc start F2BLA
```
 * message queue machine (queuehost)
 ```
c:\F2B\F2BQueue.exe install -g c:\F2B\F2BLogAnalyzer.log -l ERROR \
        -H . -p F2BProducer -r F2BSubscription \
        -s c:\F2B\queue.dat -i 300 -n 150
sc start F2BQ
```
 * machine protected by Fail2ban firewall
 ```
c:\F2B\F2BFirewall.exe add-wfp
c:\F2B\F2BFirewall.exe install -g c:\F2B\F2BLogAnalyzer.log -l ERROR \
        -H queuehost -r F2BSubscription -i 240 -n 150
sc start F2BFW
```
