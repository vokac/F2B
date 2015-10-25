Fail2ban for Windows
====================

This project is an implementation inspired by unix http://www.fail2ban.org.
F2B provides windows service that scans log data and detects attempts to guess
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
* load F2B.sln project file with Visual Studio 2015
* Build -> Batch Build... -> Build
* create "Release" build with F2BWFP compiled as 32bit dll
  (if you want to build/use 64bit binaries you have to
   disable "preferred 32bit" compilation of the C#
   code and compile dll library as "Release|x64")


Installation
------------

### Executables and libraries

No installation program exists and all binaries (`F2BLogAnalyzer.exe`,
`F2BQueue.exe`, `F2BFirewall.exe`, `F2BWFP.dll`) must be placed in one directory
(e.g. `c:\F2B`). F2B service code was written in C# which requires at least
.Net framework version 4.5. This .Net version is not integral part of older
windows (Vista, 7, 2008 Server) and must be installed on these systems.

F2B use WFP API (Windows Filtering Platform) to access directly functions
that can modify windows firewall configuration. This functionality is
provided by native C++/CLI code compiled in `F2BWFP.dll` library and C++/CLI
requires redistributable Visual C++ package (x86/x64). You can download
and install redistributable package directly from Microsoft or you can
just copy all required libraries in the F2B directory. Be aware that debug
build of the F2B code needs debug version of C++ libraries and they come
only with full Visual Studio installation.

### WFP modifications

Filtering rules in WFP must be associated with F2B application using
specific WFP provider and sublayer. It is necessary to create these
structures otherwise F2B will not be able to add new firewall filters.
All necessary changes in WFP can be done using
```
c:\F2B\F2BFirewall.exe add-wfp
```
If you want to run F2B service using non-privileged user account (instead of
default LocalSystem), sufficient privileges to change firewall rules in WFP
must be assigned to such account using:
```
c:\F2B\F2BFirewall.exe add-privileges -u username
```
To rollback changes in WFP (uninstall F2B) use
```
c:\F2B\F2BFirewall.exe remove-privileges -u username
c:\F2B\F2BFirewall.exe remove-wfp
```

### Windows logging

Fail2ban can only work if log data produced by various services contains
all necessary information. This is not the case for most of default
windows installations (with exception of domain controllers), because
windows by default doesn't log login failure events. Configuration can
be modified using `gpedit.msc` (GPO support was added in Windows 7
and Windows 2008 R2) or with `auditpol.exe` (`secpol.msc`) on older
Windows versions. Details about windows logging is summarized in
https://www.sans.org/reading-room/whitepapers/forensics/windows-logon-forensics-34132

* `gpedit.msc` (preferred)

  * Computer Configuration\Windows Settings\Security Settings\Local Policies\Advanced Audit Policy Configuration\System Audit Policies - Local Group Policy Object
  * Computer Configuration
    * Windows Settings
      * Security Settings
        * Local Policies
          * Advanced Audit Policy Configuration
            * System Audit Policies - Local Group Policy Object
  ```
  Logon/Logoff -> Audit Logon = Success and Failure
  Logon/Logoff -> Audit Logoff = Success and Failure
  Account Logon -> Audit Credential Validation
  ```

* `auditpol.exe`

  ```
  auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable
  auditpol.exe /get /subcategory:"Logon"
  auditpol.exe /set /subcategory:"Logoff" /success:enable /failure:disable
  auditpol.exe /get /subcategory:"Logoff"
  auditpol.exe /set /subcategory:"Credential Validation" /success:enable /failure:enable
  auditpol.exe /get /subcategory:"Credential Validation"
  ```

The second issue comes from different security mechanisms supported by
windows services. Unfortunately NTLM authentication doesn't log client
IP address and that means fail2ban is not able to correctly process
these login failures. There is no elegant solution to work around this
problem, you can either completely disable NTLM (and possibly face some
issues with clients that support only NTLM) or it would be necessary
to implement service that could correlate incoming connections with NTLM
login failures. You can at least disable old and insecure NTLM methods:

* `gpedit.msc`
  * Computer Configuration
    * Windows Settings
      * Security Settings
        * Local Policies
          * Security Options
  ```
  Network security: Restrict NTLM: Incoming NTLM traffic -- Deny all accounts
  ```
  ~~Network security: LAN Manager authentication level -- Send NTLMv2 response only. Refuse LM & NTLM~~
  ~~Network security: Restrict NTLM: Audit Incoming NTLM Traffic -- Enable auditing for all accounts~~

Windows event log data can be browsed with `Eventvwr.msc` GUI
or powershell eventlog API can be used to display data in plain text

```powershell
Get-EventLog -LogName Security
        | Where-Object { $_.EventID -match "^(680|528|672|4768|4776)$" `
		      –AND $_.UserName -notmatch 'SYSTEM|NETWORK SERVICE|LOCAL SERVICE|ANONYMOUS LOGON' `
			  –AND $_.TimeGenerated -gt [datetime]::today } `
        | Sort-Object -Property TimeGenerated `
		| Select-Object -Last 100 `
		| Format-Table -AutoSize -Wrap
```


F2B Configuration
-----------------

Main F2B configuration is stored in F2BLogAnalyzer application XML file
`App.config` and source code contains example with all supported config
options. All remaining executables (`F2BQueue.exe`, `F2BFirewall.exe`)
use just command line options for their configuration.

### Fail2ban log analyzer configuration

Almost all F2B configurations are enclosed in `f2bconfig` element.

```xml
<f2bconfig>
</f2bconfig>
```

Source code distribution includes three configuration examples

* `F2BLogAnalyzer\App.config` - configuration with few useful features
  enabled (this is good starting point to create customized production
  config file)
* `F2BLogAnalyzer\App.config.minimal` - minimal fail2ban config file
* `F2BLogAnalyzer\App.config.full` - examples of all available
  configuration options which also include basic documentation
  as XML comments

#### Input section

First F2B configuration must define at least one input that provides
log data for `F2BLogAnalyzer.exe` and currently two input data types
are supported:
* `EventLog` - windows event log (local or remote)
* `FileLog` - application log files with all information on one line
   parsed by regex

Most common fail2ban configuration can use just simple local windows
event log input and specify required `name` and `type` attributes.
The `name` attribute must contain _unique_ input name that can be later
referenced in `selector` section. Input configuration `type` attribute
contains class name to be used.

```xml
<inputs>
  <!-- Subscribe to local windows event log -->
  <input name="local_eventlog" type="EventLog"/>
</inputs>
```

To subscribe windows event log (especially Security log) special privileges
are required. LocalSystem service account has by default sufficient rights
or F2BLA service can be executed under arbitrary user account that satisfy
one of following conditions:

* service user is member of "Event Log Readers" group
* special ACL was applied to event log

  ```
  wevtutil gl "LOG_NAME"
  wevtutil sl "LOG_NAME" /ca:"original SDDL"(A;;0x3;;;"user SID")
  ```

  (LOG_NAME can be e.g. Security, Application, ...)

Following log input configurations are currently supported:
* subscribe to local event log

  ```xml
  <input name="local_eventlog" type="EventLog"/>
  ```
* subscribe to event log on given machine with service credentials

  ```xml
  <input name="remote_eventlog" type="EventLog" server="win1.example.com"/>
  ```
* subscribe to event log on given machine with custom credentials

  ```xml
  <input name="remote_eventlog_auth" type="EventLog" server="win1.example.com"
         domain="EXAMPLE.COM" username="username" password="secret"/>
  ```
* subscribe to changes in local log file

  ```xml
  <input name="apache" type="FileLog" logpath="c:\apache\log\access_log"/>
  ```

#### Selector section

It is necessary to parse input events into F2B internal event structure.
Selector configuration provides flexible (although not always very simple)
way to access and assign all required (e.g. client address) and optional
(e.g. client port, login username, ...) components.

Fail2ban is usually used to deal with login failure events produced
by windows services and stored in security EventLog. These kinds of events
can be selected by applying filter on "Security" event log with keyword
attribute set to audit failure value (0x10000000000000). These events
include e.g. Kerberos tgt requests, failed logins to Windows, ... If we want
to ignore Kerberos failures except "bad password" it is possible to discard
messages using "Suppress" element.

```xml
<selectors>
  <!-- Audit failures (Keywords=0x10000000000000) -->
  <selector name="login" input_type="EventLog">
    <query>
      <![CDATA[
        <Select Path="Security">*[System[(band(Keywords,13510798882111488))]]</Select>
        <Suppress Path="Security">
          (*[System[(EventID='4768')]] or *[System[(EventID='4771')]])
          and
          *[EventData[Data[@Name='Status'] and (Data!='0x18')]]
        </Suppress>
      ]]>
    </query>
    <!-- Select event XML element with XPath and parse data using regexp -->
    <address xpath="Event/EventData/Data[@Name='IpAddress']"/>
    <port xpath="Event/EventData/Data[@Name='IpPort']"/>
    <username xpath="Event/EventData/Data[@Name='TargetUserName']"/>
    <domain xpath="Event/EventData/Data[@Name='TargetDomainName']"/>
  </selector>
</selectors>
```

Every selector element can use these attributes
* `name` - _unique_ selector name
* `input_name` - event input name (input_name or input type must be defined)
* `input_type` - event input type (input_name or input type must be defined)
* `login` - optional event kind unknown, success, fail
  (default: unknown, autodetected for eventlog using keyword)
* `processor` - processor name used for selected events
  (default: first processor defined in `<processors>` section)

Currently two input types (EventLog, FileLog) are supported by F2B selector
implementation:

* EventLog selector configuration (`input_type="EventLog"`):

  Selector query is required configuration option and it is used by log API
  (see https://msdn.microsoft.com/en-us/library/bb399427%28v=VS.90%29.aspx).
  You can use mmc Event Viewer snap-in to visually build required query with
  help of "Create Custom View" -> "Define your filter" -> "XML".

  Client IP address, port, username and domain can be extracted from eventlog
  data using XPath + regex. Definition for IP address is required and must
  match valid IPv4/IPv6 address.

* Flat log file configuration (`input_type="FileLog"`):

  List of regular expressions are used to match log lines and extract required
  data (e.g. IP address). There are several types of regular expression
  - ignore - matched line is completely ignored
  - fail - matched line means login failure
  - success - matched line means login success

  ```xml
    ...
    <!-- Selector for ssh log file -->
    <selector name="secure_log" input_name="ssh">
      <regexps>
        <regexp type="fail"><![CDATA[^(?<time_b>...) (?<time_e>..) (?<time_H>..):(?<time_M>..):(?<time_S>..) (?<hostname>\S+) sshd\[\d+\]: Failed password for (?<user>.*) from (?<address>\S+) port (?<port>\d+) ssh2$]]></regexp>
      </regexps>
    </selector>
	...
  ```

Special selector defined below this section can be used for
debugging and performance tests. It catches events logged
with `LogEvents.exe`. This application can be used to inject
arbitrary data in our processor chain (see `LogEvents.exe`
command line options).

```xml
  ...
  <!-- Test selector for eventlog data produced by LogEvents.exe -->
  <selector name="test" input_type="EventLog" processor="first">
    <query><![CDATA[<Select Path="Application">*[System[(Provider/@Name='F2B test log event') and (EventID=1)]]</Select>]]></query>
    <address xpath="Event/EventData/Data"><![CDATA[(?<username>.+)@(?<address>.+):(?<port>.+)]]></address>
    <port xpath="Event/EventData/Data"><![CDATA[(?<username>.+)@(?<address>.+):(?<port>.+)]]></port>
    <username xpath="Event/EventData/Data"><![CDATA[(?<username>.+)@(?<address>.+):(?<port>.+)]]></username>
  </selector>
  ...
```

#### Processors

#### Other configurations

##### Queue

Internal event queue options that allows to limit number of unprocessed log
events to prevent memory exhaustion. In case this limit is reached, further
events will be immediately dropped. This is just another safety mechanism
in case F2B implementation misbehaves.

Event processors can be implemented thread safe or thread safety can be
guaranteed by global lock. This means that log events can be processed
in parallel, but most of currently implemented processors are so simple
that there is basically no gain in performance when we allow more
consumers (initial tests shows in average 1M increase in memory usage
per each consumer thread).

```xml
<!-- Parameters for log event producer/consumer queue -->
<queue>
  <!-- maximum length of event queue (0 ... no limit) -->
  <maxsize>100000</maxsize>
  <!-- number of event consumer threads -->
  <consumers>10</consumers>
</queue>
```

##### SMTP

Global configuration for sending mail from F2B. This configuration
is used by `Mail` processor.

```xml
<smtp>
  <host>smtp.example.com</host>
  <port>25</port>
  <ssl>false</ssl>
  <!-- SMTP AUTH with username/password requires SSL
  <ssl>true</ssl>
  <username>username</username>
  <password>secret</password>
  -->
</smtp>
```

##### Account

This configuration is used by `Account` processor.

```xml
<!-- User account configurations (used e.g. by AccountProcessor) -->
<accounts>
  <account name="file_accounts" type="File">
    <description>Use user names (+ account status) from CSV text file</description>
    <options>
      <option key="casesensitive" value="false"/>
      <option key="filename" value="c:\F2B\accounts.txt"/>
      <option key="separator" value="	"/>
    </options>
  </account>
  <account name="ad_accounts" type="Cached+AD">
    <description>Cached AD accounts</description>
    <options>
      <option key="casesensitive" value="false"/>
      <option key="hosts" value="ldap1.example.com,ldap2.example.com,ldap3.example.com"/>
      <option key="port" value="389"/>
      <option key="ssl" value="false"/>
      <option key="starttls" value="false"/>
      <option key="auth" value="basic"/>
      <option key="username" value="EXAMPLE\username"/>
      <option key="password" value="secret"/>
      <option key="base" value="DC=example,DC=com"/>
      <option key="filter" value="(objectClass=user)"/>
      <option key="cache_positive_time" value="600"/>
      <option key="cache_negative_time" value="60"/>
      <option key="cache_positive_max_size" value="10000"/>
      <option key="cache_negative_max_size" value="1000"/>
      <option key="refresh_inc" value="300"/>
      <option key="refresh_full" value="3600"/>
    </options>
  </account>
</accounts>
```

### Command line options

* Standalone (running F2B on one machine)

```
c:\F2B\F2BFirewall.exe add-wfp
c:\F2B\F2BLogAnalyzer.exe install -c c:\F2B\F2BLogAnalyzer.exe.config \
        -g c:\F2B\F2BLogAnalyzer.log -l ERROR
sc start F2BLA
```

* Distributed (analyze logs and configure firewall on groups of machines)

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


Performance
-----------

F2BLogAnalyzer in standalone configuration with Logger+Range+Fail2ban
and Fail2banWFP modules can process more than 1k selected events per
second on Intel Q9550 @ 2.83GHz (2009 desktop). The bottleneck is not
F2B, but windows logging which took more than 2/3 of CPU time during
performance tests. Next expensive operation are changes in WFP (in a
test environment this processor was called for each selected event),
but such operation should not happen very often and almost 10k filter
rules can be added/deleted within a second.

Reasonable performance was also behind decision to use WFP API,
because common interfaces like `netsh` use `FirewallAPI.dll` and
filter rules are inserted in application firewall layer. This
library has sufficient performance for manipulation with few
thousands filter rules, but it can cause issues once you reach
10k rules. `F2BWFP.dll` use IPv4/IPv6 firewall layer which simple
and operation like add/modify/delete filter rules are much cheaper.
It is possible to change 100k rules within 15 seconds where
`FirewallAPI.dll` needs more than 40 minutes to do same changes.
