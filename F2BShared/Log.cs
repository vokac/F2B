﻿#region Imports
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.IO;
#endregion

namespace F2B
{
    public sealed class Log
    {
        /*
        #region Fields
        private static volatile Log instance;
        private static object syncRoot = new Object();
        #endregion

        #region Singleton
        private Log() { }

        public static Log Instance
        {
            get
            {
                if (instance == null)
                {
                    lock (syncRoot)
                    {
                        if (instance == null)
                            instance = new Log();
                    }
                }

                return instance;
            }
        }
        #endregion
        */
        public enum Destinations
        {
            EventLog = 0x01,
            Console = 0x02,
            File = 0x04,
        };

        #region Fields
        private static bool elogExists = false;
        private static StreamWriter writer = null;
        private static object clock = new object();
        private static object flock = new object();
        #endregion

        #region Properties
        public static Destinations Dest { get; set; }
        public static EventLogEntryType Level { get; set; }
        public static string File { get; set; }
        #endregion

        static Log()
        {
            Dest = Log.Destinations.EventLog;
            Level = EventLogEntryType.Warning;
            if (!EventLog.SourceExists("F2B"))
            {
                try
                {
                    EventLog.CreateEventSource("F2B", "Application");
                }
                catch (Exception ex)
                {
                    EventLog.WriteEntry("Application",
                        "Unable to create F2B EventLog source: "
                        + ex.ToString(), EventLogEntryType.Error);
                }
            }
            elogExists = EventLog.SourceExists("F2B");

            AppDomain.CurrentDomain.ProcessExit += new EventHandler(ProcessExit);
        }

        static void ProcessExit(object sender, EventArgs e)
        {
            if (writer != null)
            {
                writer.Close();
            }
        }



        #region Members
        public static void Logger(string message, EventLogEntryType type,
                                [CallerFilePath] string file = "",
                                [CallerMemberName] string member = "",
                                [CallerLineNumber] int line = 0)
        {
            // skip logging for events with lower then required importance
            if (Level == EventLogEntryType.Warning)
            {
                if (type == EventLogEntryType.Information)
                {
                    return;
                }
            }
            else if (Level == EventLogEntryType.Error)
            {
                if (type != EventLogEntryType.Error)
                {
                    return;
                }
            }

            // log to the required destination
            if ((Dest & Log.Destinations.EventLog) != 0)
            {
                if (elogExists)
                {
                    EventLog.WriteEntry("F2B", message, type);
                }
            }

            if ((Dest & (Log.Destinations.Console | Log.Destinations.File)) != 0)
            {
                string stype = "UNKNOWN";
                ConsoleColor ctype = ConsoleColor.White;
                switch (type)
                {
                    case EventLogEntryType.Information: stype = "INFO"; ctype = ConsoleColor.Cyan; break;
                    case EventLogEntryType.Warning: stype = "WARN"; ctype = ConsoleColor.Yellow; break;
                    case EventLogEntryType.Error: stype = "ERROR"; ctype = ConsoleColor.Red; break;
                }
                string msg = string.Format("{0:MM/dd/yy HH:mm:ss} F2B[{1}]({2}:{3}): {4}",
                    DateTime.Now, stype, Path.GetFileName(file), line, message);

                if ((Dest & Log.Destinations.Console) != 0)
                {
                    //Console.Error.WriteLine(msg);
                    lock (clock)
                    {
                        Console.BackgroundColor = ConsoleColor.Black;
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.Write("{0:MM/dd/yy HH:mm:ss} F2B[", DateTime.Now);
                        Console.ForegroundColor = ctype;
                        Console.Write(stype);
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.WriteLine("]({0}:{1}): {2}", Path.GetFileName(file), line, message);
                        Console.ResetColor();
                    }
                }

                if ((Dest & Log.Destinations.File) != 0)
                {
                    try
                    {
                        lock (flock)
                        {
                            if (writer == null)
                            {
                                writer = new StreamWriter(
                                    new FileStream(Log.File, FileMode.Append,
                                        FileAccess.Write, FileShare.Read));
                            }
                            writer.WriteLine(msg);
                            writer.Flush();
                        }
                    }
                    catch (Exception ex)
                    {
                        // disable file logging in case of exception
                        Dest &= ~Log.Destinations.File;
                        Log.Error("Failed to log in file: " + ex.ToString());
                    }
                }
            }
        }

        public static void Info(string message,
                                [CallerFilePath] string file = "",
                                [CallerMemberName] string member = "",
                                [CallerLineNumber] int line = 0)
        {
            Logger(message, EventLogEntryType.Information, file, member, line);
        }

        public static void Warn(string message,
                                [CallerFilePath] string file = "",
                                [CallerMemberName] string member = "",
                                [CallerLineNumber] int line = 0)
        {
            Logger(message, EventLogEntryType.Warning, file, member, line);
        }

        public static void Error(string message,
                                [CallerFilePath] string file = "",
                                [CallerMemberName] string member = "",
                                [CallerLineNumber] int line = 0)
        {
            Logger(message, EventLogEntryType.Error, file, member, line);
        }
        #endregion
    }

    public sealed class LimitedLog
    {
        private int cnt;
        private int curr;
        private int last;
        private int limit;
        private int repeat;
        private EventLogEntryType levelNormal;
        private EventLogEntryType levelRepeat;

        public LimitedLog(int limit = 5, int repeat = 1000,
            EventLogEntryType levelNormal = EventLogEntryType.Information,
            EventLogEntryType levelRepeat = EventLogEntryType.Warning)
        {
            this.limit = limit;
            this.repeat = repeat;

            this.levelNormal = levelNormal;
            this.levelRepeat = levelRepeat;

            cnt = 0;
            Reset();
        }

        public void Reset()
        {
            last = 0;
            curr = limit;
        }

        public bool LogNext()
        {
            return curr >= 0 || (repeat > 0 && cnt % repeat == 0);
        }

        public void Msg(string message,
                        [CallerFilePath] string file = "",
                        [CallerMemberName] string member = "",
                        [CallerLineNumber] int line = 0)
        {
            if (curr == limit)
            {
                Log.Logger(message + " (repeat " + cnt + ")",
                    levelRepeat, file, member, line);
            }
            else if (curr > 0)
            {
                Log.Logger(message + " (repeat " + cnt + ")",
                    levelNormal, file, member, line);
            }
            else if (curr == 0)
            {
                Log.Logger(message + " (repeat " + cnt + ")"
                    +") ... disabling same messages till reset",
                    levelRepeat, file, member, line);
            }
            else if (cnt % repeat == 0)
            {
                Log.Logger(message + " (repeat " + cnt
                    + ") ... only on in " + repeat + " messages is logged",
                    levelRepeat, file, member, line);
            }

            cnt++;
            last++;
            curr--;
        }

        public int Cnt
        {
            get
            {
                return cnt;
            }
        }

        public int Last
        {
            get
            {
                return last;
            }
        }
    }
}
