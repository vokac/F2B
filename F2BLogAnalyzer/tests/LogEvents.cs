//
// compile using csc.exe in MSBuild Command Prompt for VS2015
//   csc.exe /debug LogEvents.cs
//
using System;
using System.Linq;
using System.Net;
using System.Diagnostics;

namespace F2B.tests
{
    class LogEvents
    {
        static void Usage()
        {
            Console.WriteLine("");
            Console.WriteLine("Actions:");
            Console.WriteLine("  dump file");
            Console.WriteLine("  types");
            Console.WriteLine("  repeat [msgCnt [dataCnt [msg]]]");
            Console.WriteLine("  range addrLow addrHigh");
            Console.WriteLine("Examples:");
            Console.WriteLine("  {0} dump [c:\\F2B\\dump.log]", System.AppDomain.CurrentDomain.FriendlyName);
            Console.WriteLine("  {0} types", System.AppDomain.CurrentDomain.FriendlyName);
            Console.WriteLine("  {0} repeat 10 5 username@192.0.2.123:1234", System.AppDomain.CurrentDomain.FriendlyName);
            Console.WriteLine("  {0} ip 192.0.2.200", System.AppDomain.CurrentDomain.FriendlyName);
            Console.WriteLine("  {0} range 192.0.2.200 192.0.2.220 [ 1 ]", System.AppDomain.CurrentDomain.FriendlyName);
        }
        static void Main(string[] args)
        {
            foreach (string src in new string[]{ "F2BTest", "F2BDump", "F2BBench" })
            {
                if (!EventLog.SourceExists(src))
                {
                    Console.WriteLine("Trying to create missing \"{0}\" log event source", src);
                    Console.WriteLine("(admin privileges required for this operation)");
                    EventLog.CreateEventSource(src, "Application");
                }
            }

            if (args.Length == 0)
            {
                Usage();

                return;
            }

            if (args[0].ToLower() == "dump")
            {
                string msg = args.Length > 1 ? args[1] : "c:\\F2B\\dump.log";
                Console.WriteLine("Sending epecial event to trigger F2B debug info dump to {0}", msg);
                EventInstance evt = new EventInstance(0, Process.GetCurrentProcess().Id, EventLogEntryType.Error);
                EventLog.WriteEvent("F2BDump", evt, new object[] { msg });
            }
            else if (args[0].ToLower() == "types")
            {
                string sSource = "F2BTest";
                string sEvent = "Sample Event";

                // classic (old) eventlog
                EventLog.WriteEntry(sSource, sEvent);
                EventLog.WriteEntry(sSource, sEvent, EventLogEntryType.Warning);
                EventLog.WriteEntry(sSource, sEvent, EventLogEntryType.Warning, 234);
                EventLog.WriteEntry(sSource, sEvent, EventLogEntryType.Warning, 234, 567);

                EventInstance evt1 = new EventInstance(123, 456, EventLogEntryType.FailureAudit);
                EventLog.WriteEvent(sSource, evt1, new object[] { "test1", "test2", "test3" });
                EventInstance evt2 = new EventInstance(123, 456, EventLogEntryType.SuccessAudit);
                EventLog.WriteEvent(sSource, evt2, new object[] { "test1", "test2", "test3" });
                EventInstance evt3 = new EventInstance(123, 456, EventLogEntryType.Information);
                EventLog.WriteEvent(sSource, evt3, new object[] { "test1", "test2", "test3" });
                EventInstance evt4 = new EventInstance(123, 456, EventLogEntryType.Warning);
                EventLog.WriteEvent(sSource, evt4, new object[] { "test1", "test2", "test3" });
                EventInstance evt5 = new EventInstance(123, 456, EventLogEntryType.Error);
                EventLog.WriteEvent(sSource, evt5, new object[] { "test1", "test2", "test3" });
            }
            else if (args[0].ToLower() == "repeat")
            {
                int cnt = 1;
                int msgcnt = 1;
                string msg = "username@192.0.2.123:1234";

                if (args.Length > 1)
                {
                    try
                    {
                        cnt = int.Parse(args[1]);
                    }
                    catch (Exception)
                    {
                        Console.WriteLine("unable to parse int from " + args[1]);
                    }
                }

                if (args.Length > 2)
                {
                    try
                    {
                        msgcnt = int.Parse(args[2]);
                    }
                    catch (Exception)
                    {
                        Console.WriteLine("unable to parse int from " + args[2]);
                    }
                }

                if (args.Length > 3)
                {
                    msg = args[3];
                }

                object[] data = new object[msgcnt];
                for (int i = 0; i < data.Length; i++)
                {
                    data[i] = msg;
                }

                Process currentProcess = Process.GetCurrentProcess();
                Console.WriteLine(currentProcess.ProcessName + " repeat " + cnt + " " + msgcnt + " " + msg);
                Console.WriteLine("TIME: TotalProcessorTime(" + currentProcess.TotalProcessorTime
                    + "), UserProcessorTime(" + currentProcess.UserProcessorTime
                    + "), PrivilegedProcessorTime(" + currentProcess.PrivilegedProcessorTime +")");
                Console.WriteLine("START[{0}]: {1}", DateTime.Now.Ticks, DateTime.Now);

                EventLog.WriteEntry("F2BBench", "Benchmark event #" + cnt, EventLogEntryType.Information);
                EventInstance evt = new EventInstance(0, Process.GetCurrentProcess().Id, EventLogEntryType.Error);
                for (int i = 0; i < cnt; i++)
                {
                    if (i % 100 == 0)
                    {
                        Console.WriteLine("ENTRY{2:000000}[{0}]: {1}", DateTime.Now.Ticks, DateTime.Now, i);
                    }
                    EventLog.WriteEvent("F2BBench", evt, data);
                    //EventLog.WriteEvent("F2BBench", evt, new object[] { "test1", "test2", "test3", "username@192.0.2.123:1234" });
                }

                Console.WriteLine("TIME: TotalProcessorTime(" + currentProcess.TotalProcessorTime
                    + "), UserProcessorTime(" + currentProcess.UserProcessorTime
                    + "), PrivilegedProcessorTime(" + currentProcess.PrivilegedProcessorTime + ")");
                Console.WriteLine("END[{0}]: {1}", DateTime.Now.Ticks, DateTime.Now);
            }
            else if (args[0].ToLower() == "ip")
            {
                if (args.Length < 2)
                {
                    Usage();
                    return;
                }
                IPAddress address = IPAddress.Parse(args[1]);

                string msg = "username@" + address + ":1234";
                Console.WriteLine(msg);
                EventInstance evt = new EventInstance(0, 999, EventLogEntryType.Error);
                EventLog.WriteEvent("F2BBench", evt, new object[] { msg });
            }
            else if (args[0].ToLower() == "range")
            {
                if (args.Length < 3)
                {
                    Usage();
                    return;
                }

                int repeat = 1;
                if (args.Length > 3)
                {
                    repeat = int.Parse(args[3]);
                }

                EventInstance evt = new EventInstance(0, 999, EventLogEntryType.Error);

                IPAddress addrLow = IPAddress.Parse(args[1]);
                IPAddress addrHigh = IPAddress.Parse(args[2]);
                IPAddress address = addrLow;

                Process currentProcess = Process.GetCurrentProcess();
                Console.WriteLine(currentProcess.ProcessName + " range " + addrLow + " " + addrHigh + " " + repeat);
                Console.WriteLine("START[{0}]: {1}", DateTime.Now.Ticks, DateTime.Now);
                Console.WriteLine("TIME: TotalProcessorTime(" + currentProcess.TotalProcessorTime
                    + "), UserProcessorTime(" + currentProcess.UserProcessorTime
                    + "), PrivilegedProcessorTime(" + currentProcess.PrivilegedProcessorTime + ")");

                int i = 0;
                while (true)
                {
                    string msg = "username@" + address + ":1234";
                    if (i % 100 == 0)
                    {
                        Console.WriteLine("ENTRY{2:000000}[{0}]: {1} ({3})", DateTime.Now.Ticks, DateTime.Now, i*repeat, msg);
                    }
                    for (int j = 0; j < repeat; j++)
                    {
                        EventLog.WriteEvent("F2BBench", evt, new object[] { msg });
                    }

                    Byte[] addressBytes = address.GetAddressBytes();
                    UInt32 addressInteger = (((UInt32)addressBytes[0]) << 24) + (((UInt32)addressBytes[1]) << 16) + (((UInt32)addressBytes[2]) << 8) + ((UInt32)addressBytes[3]);
                    addressInteger++;
                    addressBytes[0] = (Byte)((addressInteger >> 24) & 0xFF);
                    addressBytes[1] = (Byte)((addressInteger >> 16) & 0xFF);
                    addressBytes[2] = (Byte)((addressInteger >> 8) & 0xFF);
                    addressBytes[3] = (Byte)(addressInteger & 0xFF);
                    address = new IPAddress(addressBytes);

                    if (address.GetAddressBytes().SequenceEqual(addrHigh.GetAddressBytes()))
                        break;

                    i++;
                }

                Console.WriteLine("TIME: TotalProcessorTime(" + currentProcess.TotalProcessorTime
                    + "), UserProcessorTime(" + currentProcess.UserProcessorTime
                    + "), PrivilegedProcessorTime(" + currentProcess.PrivilegedProcessorTime + ")");
                Console.WriteLine("END[{0}]: {1}", DateTime.Now.Ticks, DateTime.Now);
            }
            else
            {
                Usage();
            }

            // writing "new" event log (with user structured data) in .Net 4
            // http://blog.dlgordon.com/2012/06/writing-to-event-log-in-net-right-way.html
        }
    }
}
