Fail2ban for Windows
====================

This project is an implementation inspired by unix http://www.fail2ban.org.
F2B provides windows service that scans log data and detects attempts to guess
user password. Client IPv4/IPv6 address that causes significant login failures
can be automatically temporarily blocked using windows firewall configuration.


Requirements
------------

* Windows Vista and newer
* .Net framework 4.5 (Windows Vista, 7, 2008 Server)
* Visual C++ Redistributable for Visual Studio 2015 ("optional")
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
`F2BLogAnalyzer.nomsmq.exe`, `F2BLogAnalyzer.standalone.exe`, `F2BQueue.exe`,
`F2BFirewall.exe`, `F2BWFP.dll`) must be placed in one directory
(e.g. `c:\F2B`). F2B service code was written in C# which requires at least
.Net framework version 4.5. This .Net version is not integral part of older
windows (Vista, 7, 2008 Server) and must be installed on these systems.

F2B use WFP API (Windows Filtering Platform) to access directly functions
that can modify windows firewall configuration. This functionality is
provided by native C++/CLI code compiled in `F2BWFP.dll` library and C++/CLI
requires redistributable Visual C++ package (x86/x64). You can download
and install redistributable package directly from Microsoft or you can
just copy all required libraries in the F2B directory (`concrt140.dll`,
`mfc140.dll`, `mfcm140.dll`, `msvcp140.dll`, `ucrtbase.dll`, `vcamp140.dll`,
`vccorlib140.dll`, `vcomp140.dll`, `vcruntime140.dll`). Be aware that debug
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
  Network security: LAN Manager authentication level -- Send NTLMv2 response only. Refuse LM & NTLM
  ```
  ~~Network security: Restrict NTLM: Audit Incoming NTLM Traffic -- Enable auditing for all accounts~~
  ~~Network security: Restrict NTLM: Incoming NTLM traffic -- Deny all accounts~~

Windows event log data can be browsed with `Eventvwr.msc` GUI, `wevtutil`
or `powershell` eventlog API

```
wevtutil gp microsoft-windows-security-kerberos /ge /gm
wevtutil qe Security /q:"*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4624)] and EventData[Data[@Name='LogonType']='2']]" /e:Events
```

```powershell
Get-EventLog -LogName Security
        | Where-Object { $_.EventID -match "^(680|528|672|4768|4776)$" `
		      –AND $_.UserName -notmatch 'SYSTEM|NETWORK SERVICE|LOCAL SERVICE|ANONYMOUS LOGON' `
			  –AND $_.TimeGenerated -gt [datetime]::today } `
        | Sort-Object -Property TimeGenerated `
		| Select-Object -Last 100 `
		| Format-Table -AutoSize -Wrap
```
or
```
$query = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Security-Auditing">
    <Select Path="Security">*[System[(band(Keywords,4503599627370496))]]</Select>
    <Suppress Path="Security">
      (*[System[(EventID='4768')]] or *[System[(EventID='4771')]])
      and
      (*[EventData[Data[@Name='Status']!='0x6']] and *[EventData[Data[@Name='Status']!='0x18']])
    </Suppress>
  </Qeury>
</QueryList>
"@

Get-WinEvent -LogName Security -FilterXPath $query -MaxEvents 10
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

Processors section is the most important part of the F2B configuration.
Each well defined log event structure created by F2B input modules and
filtered by one of the selectors can be passed to the chain of processor
instances with user defined configuration options. Different processing
path can be specified based on log event data.

Basic declaration of the processor is same and contains processor unique
name, type (processor class name), description and link to following
processor which is called in case execution of current processor did not
throw any (uncatched) exception. Next processor in configuration file
is used as a default value for successful processor execution and in
case of exception the default is empty processor which terminate event
log processing. Processing is also terminated in case unknown processor
name.

```xml
<processor name="unique processor name" type="ProcessorClassName">
  <description>User defined processor instance description</description>
  <options>
    <!-- processor configuration options -->
    <option key="key1" value="value1"/>
    <option key="key2" value="value2"/>
	<!-- ... -->
  </options>
  <!-- reference to the next processor (by default set to the
  processor name defined below this processor configuration)
  and to the processor called in case of execption (by default
  processor execution is terminated in case of exception) -->
  <goto next="label" error="last"/>
</processor>
```

#### Label

Simple label that can be used in attributes of the processor goto element.

```xml
<processor name="unique_label_name" type="Label"/>
```

#### Stop

This processor terminate processing chain.

```xml
<processor name="unique_stop_name" type="Stop"/>
```

#### Parallel

Run specified processors in parallel using separate worker threads.

```xml
<processor name="parallel" type="Parallel">
  <description>Example configuration for Parallel processor</description>
  <options>
    <option key="processors" value="processor1,processor2,processor3,fail2ban"/>
  </options>
</processor>
```

#### Filters

These kind of processors can be used to branch processor chains based on log
event data. Their configuration can/should provide two additional `goto`
element attributes `success` and `failure`.

##### Login

Filter log events according login (audit) success/failure defined as selector
attribute. This processor also define `procname.Success` and `procname.Failure`
variable when at least one login succeed in given time period. This information
can be used to determine that at least one successful login ocured from given
address range.

```xml
<processor name="login" type="Login">
  <description>Skip events that correspond successfull login</description>
  <options>
    <option key="maxsize" value="100000"/>
    <option key="findtime" value="86400"/>
    <option key="count" value="24"/>
    <option key="ipv4_prefix" value="32"/>
    <option key="ipv6_prefix" value="64"/>
    <option key="state" value="c:\F2B\login.state"/>
  </options>
  <goto success="last"/>
</processor>
```

##### Range

Filter log events according client address specified directly in XML
configuration file. It can be used for static list of the IPv4/IPv6
addresses that requires some special treatment (e.g. not to apply fail2ban
for your own address range).

```xml
<processor name="whitelist" type="Range">
 <description>Whitelist IP addresses</description>
  <ranges>
    <range network="127.0.0.0/8"/>
    <range network="192.0.2.0/24"/>
    <range network="::1/128"/>
    <range network="2001:db8::/32"/>
  </ranges>
  <options>
    <!-- create ${whitelist.Mail} variable on successful search -->
    <option key="mail" value="whitelist-admin@example.com"/>
  </options>
  <goto success="last"/>
</processor>
```

##### RangeFile

Filter log events according client address read from config file.
The `filename` is monitored for changes and this module is automatically
reconfigured with updated data.

```xml
<processor name="important_clients" type="RangeFile">
  <description>Read address ranges from text file</description>
  <options>
    <option key="filename" value="c:\F2B\important_clients.ranges"/>
  </options>
  <goto success="last"/>
</processor>
```

File format is very simple, each line contains IPv4/IPv6 address or address
range. Optionally mail separated from IPv4/IPv6 address by tabulator can be
provided and it is used to create `procname.Mail` variable that can be later
used e.g. in `Mail` processor. Hash character "#" at the beginning of the
line means start of comment and these lines are skipped when parsing data
from this address ranges configuration file.

```
192.168.123.123
192.168.0.0/16	f2b-private-range-admin@example.com
192.168.1.0/24	f2b-private-subrange-admin@example.com
fc00::1234:1233
fc00::/7	f2b-private-range-admin@example.com
```

##### Input

Filter log events according list of input types, input names and selector
names. Regexp can be used to match each name. This processor can be used
to group similar events and apply to them same processor chain.

```xml
<processor name="login_input" type="Input">
  <description>Select just login events from all local and remote inputs</description>
  <options>
    <!-- <option key="type" value="(EventLog|FileLog)"/> -->
    <option key="input" value="(local.*|remote.*)"/>
    <option key="selector" value="(login|specific_login)"/>
  </options>
  <goto success="if_filter_login_succeeded" failure="if_filter_login_failed"/>
</processor>
```

##### Account

Filter log events according user account properties. This processor requires
existing `<account>` definition that provides user account data. Account
processor can be used to deal with non-existing, locked or disabled accounts
different with respect to normal failed login due to bad password.

```xml
<processor name="if_ad_account_exists" type="Account">
  <description>Filter log events for non-existing accounts</description>
  <options>
    <!-- data "source" is reference to existing "account" name -->
    <option key="account" value="ad_accounts"/>
    <option key="mode" value="exists"/>
    <!--
    <option key="mode" value="disabled"/>
    <option key="mode" value="locked"/>
    <option key="mode" value="disabled|locked"/>
    -->
  </options>
  <goto success="ad_account_exists" failure="not_ad_account_exists" error="ad_account_error"/>
</processor>
```

#### Case

Use template to create next processor name. If the label after template
variable expansion doesn't correspond to any existing processor name than
standard `failure` processor will be called as next processor. If you leave
`failure` attribute empty than log event processing will follow standard
rules and no furter processor is called.

```xml
<processor name="case" type="Case">
  <description>Choose next processor according template</description>
  <options>
    <option key="template" value="label_for_${Event.Input}_${Event.Selector}"/>
  </options>
  <goto failure="last"/>
</processor>
```

#### Logger

Log selected events in a file (timestamp, hostname, selector_name, IP address,
...). Output data format is treated as template where all variables are
expanded and than stored in predefined file. To prevent excessive disk space
usage this module can rotate its output files when their size reached given
treshold. It is also possible to keep history of several rotated log files.

```xml
<processor name="logger" type="Logger">
  <description>Log all selected events in log file</description>
  <options>
    <option key="file" value="c:\F2B\full.log"/>
    <option key="size" value="1073741824"/>
    <option key="rotate" value="4"/>
    <option key="template" value="${Event.TimeCreated}\t${Event.EventId}\t${Event.RecordId}\t${Event.Address}\r\n"/>
    <option key="synchronized" value="true"/>
  </options>
</processor>
```

#### LoggerSQL

Log selected events in a SQL database using ODBC connection string and column
to F2B processor variable name map.

```sql
CREATE TABLE `f2b` (
    `inserted` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `timestamp` BIGINT DEFAULT NULL,
    `hostname` VARCHAR(50) DEFAULT NULL,
    `id` INTEGER DEFAULT NULL,
    `input` VARCHAR(50) DEFAULT NULL,
    `selector` VARCHAR(50) DEFAULT NULL,
    `status` VARCHAR(10) DEFAULT NULL,
    `event` INTEGER DEFAULT NULL,
    `record` INTEGER DEFAULT NULL,
    `machine` VARCHAR(50) DEFAULT NULL,
    `created` BIGINT DEFAULT NULL,
    `provider` VARCHAR(40) DEFAULT NULL,
    `address` VARCHAR(40) DEFAULT NULL,
    `port` SMALLINT DEFAULT NULL,
    `username` VARCHAR(25) DEFAULT NULL,
    `domain` VARCHAR(20) DEFAULT NULL
);
```

```xml
<processor name="logger_sql" type="LoggerSQL">
  <description>Log all selected events in MySQL database using ODBC</description>
  <options>
    <option key="odbc" value="DRIVER={MySQL ODBC 3.51 Driver};SERVER=mysql.example.com;PORT=3306;DATABASE=f2b;USER=username;PASSWORD=secret;OPTION=4194304"/>
    <option key="table" value="f2b"/>
    <option key="columns" value="id,timestamp,hostname,input,selector,status,event,record,machine,created,provider,address,port,username,domain"/>
    <option key="column.timestamp" value="${Event.Timestamp}"/>
    <option key="column.hostname" value="${Event.Hostname}"/>
    <option key="column.id" value="${Event.Id}"/>
    <option key="column.input" value="${Event.Input}"/>
    <option key="column.selector" value="${Event.Selector}"/>
    <option key="column.status" value="${Event.Status}"/>
    <option key="column.event" value="${Event.EventId}"/>
    <option key="column.record" value="${Event.RecordId}"/>
    <option key="column.machine" value="${Event.MachineName}"/>
    <option key="column.created" value="${Event.TimeCreated}"/>
    <option key="column.provider" value="${Event.ProviderName}"/>
    <option key="column.address" value="${Event.Address}"/>
    <option key="column.port" value="${Event.Port}"/>
    <option key="column.username" value="${Event.Username}"/>
    <option key="column.domain" value="${Event.Domain}"/>
  </options>
</processor>
```

#### Fail2ban

Provides fail to ban functionality.

```xml
<processor name="fail2ban" type="Fail2ban">
  <description>Test fail2ban processor</description>
  <options>
    <option key="state" value="c:\F2B\fail2ban.state"/>
    <option key="findtime" value="600"/>
    <option key="ipv4_prefix" value="32"/>
    <option key="ipv6_prefix" value="64"/>
    <option key="history" value="all"/>
    <!--
    <option key="history" value="all"/>
    <option key="history" value="one"/>
    <option key="history" value="fixed"/>
    <option key="history.fixed.count" value="10"/>
    <option key="history.fixed.decay" value="1.0"/>
    <option key="history" value="rrd"/>
    <option key="history.rrd.count" value="5"/>
    <option key="history.rrd.repeat" value="2"/>
    -->
    <option key="tresholds" value="test,soft,hard"/>
    <option key="treshold.test.function" value="simple"/>
    <option key="treshold.test.maxretry" value="0"/>
    <option key="treshold.test.repeat" value="0"/>
    <option key="treshold.test.bantime" value="300"/>
    <option key="treshold.test.action" value="action_test"/>
    <option key="treshold.soft.function" value="simple"/>
    <option key="treshold.soft.maxretry" value="7"/>
    <option key="treshold.soft.repeat" value="0"/>
    <option key="treshold.soft.bantime" value="-1"/>
    <option key="treshold.soft.action" value="action_soft"/>
    <option key="treshold.hard.function" value="simple"/>
    <option key="treshold.hard.maxretry" value="10"/>
    <option key="treshold.hard.repeat" value="0"/>
    <option key="treshold.hard.bantime" value="600"/>
    <option key="treshold.hard.action" value="action_hard"/>
    <!-- this should go to default filewall configuration options
    <option key="maxentries" value="100000"/>
    -->
  </options>
</processor>
```

#### Mail

Send email created from predefined template

```xml
<processor name="action_mail" type="Mail">
  <description>Test email sender processor</description>
  <options>
    <option key="sender" value="helpdesk@example.com"/>
    <option key="recipient" value="f2b-admin@example.com,${address_group.Mail}"/>
    <option key="subject" value="[F2B] Fail2Ban[${Fail2ban.Last}] reached ${${Fail2ban.Last}.Treshold} treshold for ${${Fail2ban.Last}.Address}/${${Fail2ban.Last}.Prefix}"/>
    <option key="body" value="Mail body text."/>
  </options>
  <goto on_error_next="true"/>
</processor>
```

#### Fail2banAction

Base class for `Fail2ban*` action processors that provides general
configuration option:
* `bantime` - default expiration time for F2B firewall rule that is
  used only if `Fail2ban` module doesn't provide its recommended value
* `max_ignore` - maximum time we ignore events with request to block
  same address

##### Fail2banMSMQ

Send information about banned IP address into F2BQueue that use MSMQ
to implement producer-subscriber queue. This can be used to implement
distributed F2B with many sources (F2BLogAnalyzers) and protected machines
that receives information about addresses that would be added in firewall
(F2BFirewall). Configuration options (queue_name) must correspond command
line arguments used to start F2BQueue.

```xml
<processor name="action_hard_msmq" type="Fail2banMSMQ">
  <description>Send message to F2BPS service using MSMQ</description>
  <options>
    <option key="queue_name" value=".\private$\F2BProductionQueue"/>
    <option key="max_ignore" value="60"/> <!-- maximum time in seconds we ignore message with same parameters (minimum is real bantime/100) -->
    <option key="bantime" value="600"/> <!-- used only if Fail2ban module doesn't provide specific value -->
    <option key="time_to_be_received" value="300"/> <!-- how long should message wait to be processed in MSMQ before we discard it -->
  </options>
  <goto on_error_next="true"/>
</processor>
```

##### Fail2banWFP

Module that can be used to add new rules into local firewall using directly WFP
API (F2BWFP.dll). This module also automatically cleanup expired F2B firewall
rules. This is recommended module in case you don't want to build distributed
F2B infrastructure (using F2BQueue + F2BFirewall) and it provides excelent
performance for milions firewall rules.

```xml
<processor name="action_hard_wfp" type="Fail2banWFP">
  <description>Ban IP address reaching fail2ban treshold with local firewall using WFP API (F2BWFP.dll)</description>
  <options>
  <option key="max_ignore" value="60"/> <!-- maximum time in seconds we ignore message with same parameters (minimum is real bantime/100) -->
    <option key="bantime" value="600"/> <!-- used only if Fail2ban module doesn't provide specific value -->
    <option key="cleanup" value="60"/> <!-- clean list of expired rules every cleanup seconds -->
    <option key="max_filter_rules" value="0"/> <!-- maximum number of active F2B filter rules (0 .. no limit) -->
    <option key="permit" value="false"/> <!-- add F2B permit filter rule (instead of blocking rule) -->
    <option key="persistent" value="false"/> <!-- F2B persistent filter rule (survive restart) -->
  </options>
  <goto on_error_next="true"/>
</processor>
```

##### Fail2banFw

Module that can be used to add new rules into local firewall using standard
COM Firewall API (FirewallAPI.dll). This module also automatically cleanup
expired F2B firewall rules. Use this module with caution because its perfromance
gets unusable with few tousands active firewall rule (packet processing is fine
but add/remove firewall rule can take excessive time).

```xml
<processor name="action_hard_fw" type="Fail2banFw">
  <description>Ban IP address reaching fail2ban treshold with local firewall using COM Firewall API (FirewallAPI.dll) ... much slower than WFP</description>
  <options>
    <option key="max_ignore" value="60"/> <!-- maximum time in seconds we ignore message with same parameters (minimum is real bantime/100) -->
    <option key="bantime" value="600"/> <!-- used only if Fail2ban module doesn't provide specific value -->
    <option key="cleanup" value="60"/> <!-- clean list of expired rules every cleanup seconds -->
    <option key="max_filter_rules" value="0"/> <!-- maximum number of active F2B filter rules (0 .. no limit) -->
    <option key="permit" value="false"/> <!-- add F2B permit filter rule (instead of blocking rule) -->
  </options>
  <goto on_error_next="true"/>
</processor>
```

##### Fail2banCmd

This module execute external application and can pass argumens that comes
from evaluated string expression

```xml
<processor name="action_test_cmd" type="Fail2banCmd">
  <description>Execute F2BFirewall.exe to add local WFP filter (this module can be used to run arbitrary executable / script)</description>
  <options>
    <option key="path" value="c:\F2B\F2BFirewall.exe"/> <!-- path to F2BFirewall.exe executable -->
    <option key="args" value="add-filter /address ${${Fail2ban.Last}.Address}/${${Fail2ban.Last}.Prefix} /expiration ${${Fail2ban.Last}.Expiration}"/> <!-- executable arguments -->
    <option key="max_ignore" value="60"/> <!-- maximum time in seconds we ignore message with same parameters (minimum is real bantime/100) -->
    <option key="bantime" value="600"/> <!-- used only if Fail2ban module doesn't provide specific value -->
  </options>
  <goto on_error_next="true"/>
</processor>
```

#### Other configurations

##### Queue

Internal event queue options that allows to limit number of unprocessed log
events to prevent memory exhaustion. In case this limit is reached, further
events will be immediately dropped. Also maximum time for whole processor
chain can be specified to protect execution from processor that hangs. This
is just another safety mechanism in case F2B implementation misbehaves.

Event processors can be implemented thread safe or thread safety can be
guaranteed by global lock. This means that log events can be processed
in parallel, but most of currently implemented processors are so simple
that there is basically no gain in performance when we allow more
consumers (initial tests shows in average 1M increase in memory usage
per each consumer thread).

```xml
<!-- Parameters for log event producer/consumer queue -->
<queue>
  <!-- maximum lenght of event queue (0 ... no limit) -->
  <maxsize>100000</maxsize>
  <!-- maximum run time for full chain of processors -->
  <maxtime>10</maxtime>
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

There are couple of options common to every F2B executable. To see all
available command line options with their description use `-h` option.
Useful informations are showed aslo once you call executable with `examples`
option (e.g. `F2BFirewall.exe examples`). This shows most common patterns
how to use command line interface including short description.

Every executable also supports options related to logging. If you run
F2B executable interactively it sends by default log data to standard
output and in service mode to the windows event log. You can save F2B
logging in a flat file by specifying `-g filename` command line option.
To change log level use `-l` command line option with `INFO`, `WARN`
or `ERROR` parameter.

Command line interface can be also used to manage F2B services that
corresponds to `F2BLogAnalyzer.exe`, `F2BQeueu.exe` and `F2BFirewall.exe`.
This applications support `install` (`uninstall`) option that is used
to install (uninstall) particular windows service. It is also possible
to start/stop corresponding windows service with `start` and `stop`
commandline option. It is possible to manage services with standard
windows tools like `sc.exe`, but especialy installing and uninstalling
F2B services should be done with their own command line interface,
because that ensures correct service options and also all necessery
modifications (e.g. F2BFirewall configures also WFP during service
installation).

Before installing / starting F2B services it is useful to start executables
interactively, because it is much faster to trace configuration issues
this way. Interactive mode is initiated with `run` command line option.
Be aware that F2B binaries may need special privileges (access to windows
event log, access to WFP, ...) and by default they'll work only when
executed with local administrator privileges. It is possible to run each
F2B executable with normal user account, but in that case you must first
add access rights to required user to windows event log and windows
filtering platform.

F2B binaries also support configuration of the memory limits enforced
by windows. With `-x size` option you can control windows Job Object
memory configuration. This can prevent memory exhaution in case of
non-optimal configuration (e.g. IPv6 Fail2ban configuration can cause
issues in case you use /128 prefix and attacker controls all 2^64
addresses on one subnet).

#### F2BLogAnalyzer (F2BLA service)

Main configuration is stored in XML file that was already described
in prior sections. Use `-c filename` command line option to select
required configuration.

Debug build of the F2BLogAnalyzer provides simple interface that can
be used to dump internal state of this application includig current
state of each configured processor. This is useful espetially for
new module development but it can also help troubleshooting issues
with configuration. When you run F2BLogAnalyzer interactively you can press
"d" key to dump program state in `c:\F2B\dump.txt` (different file can be
passed with `--dump-file filename` command line option). Special log event
that can be created with `LogEvent.exe dump filename` also dumps internal
F2BLogAnalyzer state in required filename.

#### F2BQueue (F2BQ service)

This executable doesn't use configuration file and its behavior is driven
only by command line arguments. TODO

#### F2BFirewall (F2BFW service)

This executable doesn't use configuration file and its behavior is driven
only by command line arguments. TODO

#### Simple examples how to use F2B executables

* Standalone I (F2B for one machine)

```
c:\F2B\F2BFirewall.exe add-wfp
c:\F2B\F2BLogAnalyzer.exe install \
        -c c:\F2B\F2BLogAnalyzer.exe.config \
        -g c:\F2B\F2BLogAnalyzer.log -l ERROR
sc start F2BLA
```

* Standalone II (F2B for one machine, no dependency on Microsoft Message
  Queue installation)

```
c:\F2B\F2BFirewall.exe add-wfp
c:\F2B\F2BLogAnalyzer.nomsmq.exe install \
        -c c:\F2B\F2BLogAnalyzer.exe.config \
        -g c:\F2B\F2BLogAnalyzer.log -l ERROR
sc start F2BLA
```

* Standalone III (F2B for one machine, use slow COM FirewallAPI that can't
  handle more than few tousands F2B filter rules, but this binary has no
  external dependency on Visual C++ Redistributable package or Microsoft
  Message Queue installation)

```
c:\F2B\F2BLogAnalyzer.standalone.exe install \
        -c c:\F2B\F2BLogAnalyzer.exe.config \
        -g c:\F2B\F2BLogAnalyzer.log -l ERROR
sc start F2BLA
```

* Distributed (analyze logs and configure firewall on groups of machines)

 * log analyzer machine
 ```
c:\F2B\F2BLogAnalyzer.exe install \
        -g c:\F2B\F2BLogAnalyzer.log -l ERROR \
        -c c:\F2B\F2BLogAnalyzer.exe.config
sc start F2BLA
```
 * message queue machine (queuehost)
 ```
c:\F2B\F2BQueue.exe install \
        -g c:\F2B\F2BLogAnalyzer.log -l ERROR \
        -H . -p F2BProducer -r F2BSubscription \
        -s c:\F2B\queue.dat -i 300 -n 150
sc start F2BQ
```
 * machine protected by Fail2ban firewall
 ```
c:\F2B\F2BFirewall.exe add-wfp
c:\F2B\F2BFirewall.exe install \
        -g c:\F2B\F2BLogAnalyzer.log -l ERROR \
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
because common interfaces like `netsh` use `FirewallAPI.dll` and filter
rules are inserted in application firewall layer. This library has
sufficient performance for manipulation with few thousands filter rules,
but it can cause issues once you reach 10k rules. WFP provides different
firewall layers and `FirewallAPI.dll` use complex application layer.
It is more efficient to use just IPv4/IPv6 packet layer to block remote
addresses, because add/remove operations are much faster. It is possible
to change 100k fail2ban rules within 15 seconds where `FirewallAPI.dll`
needs more than 40 minutes to do same changes.
