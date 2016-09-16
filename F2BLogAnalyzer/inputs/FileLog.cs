#region Imports
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
#endregion

namespace F2B.inputs
{
    public class FileLogInput : BaseInput
    {
        #region Fields
        private string filename;
        private int interval;
        private Regex[] match;
        private Regex[] ignore;

        private bool onlyWatcher;
        private bool active;
        private StreamReader reader;
        private long lastMaxOffset;
        private AutoResetEvent wait;
        private AutoResetEvent exit;
        private FileSystemWatcher watcher;
        private Thread thread;
        private long errtime;
        #endregion

        #region Constructors
        public FileLogInput(InputElement input, SelectorElement selector, EventQueue equeue)
            : base(input, selector, equeue)
        {
            filename = input.LogPath;
            interval = input.Interval;
            onlyWatcher = false;
            active = false;

            List<Regex> tmpMatch = new List<Regex>();
            List<Regex> tmpIgnore = new List<Regex>();
            foreach (RegexpElement ree in selector.Regexps)
            {
                Regex re = new Regex(ree.Value, RegexOptions.Singleline);
                switch (ree.Type)
                {
                    case "match": tmpMatch.Add(re); break;
                    case "ignore": tmpIgnore.Add(re); break;
                    default: throw new Exception("unknown regex type: " + ree.Type);
                }
            }
            match = tmpMatch.ToArray();
            ignore = tmpMatch.ToArray();

            if (interval <= 0)
            {
                onlyWatcher = true;
            }

            // Create a new FileSystemWatcher and set its properties.
            watcher = new FileSystemWatcher();
            watcher.Path = Path.GetDirectoryName(filename);
            watcher.Filter = Path.GetFileName(filename);
            // Watch for changes (assuming we are monitoring log file
            // where we just append data to the end of the file)
            watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName;

            // Add event handlers.
            watcher.Created += new FileSystemEventHandler((s, e) => FileWatcherReplaced(s, e));
            watcher.Deleted += new FileSystemEventHandler((s, e) => FileWatcherReplaced(s, e));
            watcher.Renamed += new RenamedEventHandler((s, e) => FileWatcherReplaced(s, e));

            if (onlyWatcher)
            {
                watcher.NotifyFilter |= NotifyFilters.Size;
                watcher.Changed += new FileSystemEventHandler((s, e) => FileWatcherChanged(s, e));
                // Increase size of internal buffer used to monitor all changes in given directory.
                // It can help not to loose change events in case of heavy activity in log
                // directory - it is probably better not to use this watcher for changes
                // in monitored file by setting interval to some reasonable number (e.g.
                // 1000 microseconds), because of better reliability. This buffer is using
                // non-swappable memory (be careful with its size)
                //watcher.InternalBufferSize *= 16;

                // signal used to synchronize event processing deactivation with
                // currently running ProcessLines code
                exit = new AutoResetEvent(false);
            }
            else
            {
                // signal used to interupt waiting line processing thread
                wait = new AutoResetEvent(false);
            }
        }

        //~FileLogInput()
        //{
        //    if (reader != null)
        //    {
        //        reader.Close();
        //    }
        //}
        #endregion

        #region Methods
        public override void Start()
        {
            Log.Info(InputName + "/" + SelectorName + " activate: active=" + active + ", interval=" + interval);
            if (active)
            {
                return;
            }

            active = true;
            errtime = 0;
            lastMaxOffset = -1; // start at the end of log file
            if (!onlyWatcher)
            {
                wait.Reset();
                thread = new Thread(new ThreadStart(ProcessThread));
                thread.Start();
            }
            else
            {
                // must be called before enabling watcher events
                exit.Reset();
                ProcessLines();
                exit.Set();
            }
            watcher.EnableRaisingEvents = true;
        }

        public override void Stop()
        {
            Log.Info(InputName + "/" + SelectorName + " deactivate: active=" + active + ", interval=" + interval);
            if (!active)
            {
                return;
            }

            active = false;
            watcher.EnableRaisingEvents = false;
            if (thread != null)
            {
                wait.Set();
                thread.Join();
                thread = null;
            }

            if (onlyWatcher)
            {
                // wait till we finish processing current line (max 5s)
                exit.WaitOne(5 * 1000);
            }

            // free allocated resources
            if (reader != null)
            {
                reader.Close();
            }
        }

        //  This method is called when a file size is changed.
        private void FileWatcherChanged(object source, FileSystemEventArgs e)
        {
            WatcherChangeTypes wct = e.ChangeType;
            Log.Info(InputName + "/" + SelectorName + " FileWatcherChanged: " + wct.ToString() + ", " + e.FullPath + " (pos=" + lastMaxOffset + ")");
            // FileSystemWatcher process events in sequence so we
            // don't have to synchronize ProcessLines call here
            exit.Reset();
            ProcessLines();
            exit.Set();
        }

        //  This method is called when a file is created, renamed, or deleted.
        private void FileWatcherReplaced(object source, FileSystemEventArgs e)
        {
            WatcherChangeTypes wct = e.ChangeType;
            if (e is RenamedEventArgs)
            {
                Log.Info(InputName + "/" + SelectorName + " FileWatcherReplaced: " + wct.ToString() + " " + ((RenamedEventArgs)e).OldFullPath + " to " + e.FullPath);
            }
            else
            {
                Log.Info(InputName + "/" + SelectorName + " FileWatcherReplaced: " + wct.ToString() + ", " + e.FullPath);
            }

            // close old file
            if (reader != null)
            {
                reader.Close();
                reader = null;
                errtime = 0;
            }

            // signal log file reader thread
            if (!onlyWatcher)
            {
                wait.Set();
            }
            else
            {
                // FileSystemWatcher process events in sequence so we
                // don't have to synchronize ProcessLines call here
                exit.Reset();
                ProcessLines();
                exit.Set();
            }
        }

        //  This method is called in worker thread to monitor log file updates.
        private void ProcessThread()
        {
            while (active)
            {
                // call is synchronized, only called here in thread loop
                ProcessLines();
            }
        }

        // This method is called in worker thread to monitor log file updates.
        // It must by called synchronized
        //[MethodImpl(MethodImplOptions.Synchronized)]
        private void ProcessLines()
        {
            // skip processing because of recent fatal error (60s)
            if (errtime > 0 && errtime + 60 * TimeSpan.TicksPerSecond < DateTime.Now.Ticks)
            {
                return;
            }

            try
            {
                if (reader == null)
                {
                    if (!File.Exists(filename))
                    {
                        if (!onlyWatcher)
                        {
                            wait.WaitOne();
                        }
                        return;
                    }

                    Log.Info(InputName + "/" + SelectorName + " process lines: " + filename + " (pos=" + lastMaxOffset + ")");

                    reader = new StreamReader(new FileStream(filename,
                        FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete));

                    if (lastMaxOffset < 0)
                    {
                        // start at the end of log file after activation
                        lastMaxOffset = reader.BaseStream.Length;
                    }
                    else
                    {
                        // start at the beginnig of each new (renamed) file
                        lastMaxOffset = 0;
                    }
                }

                // new file size is smaller?! not appendable log file?!
                if (reader.BaseStream.Length < lastMaxOffset)
                {
                    Log.Warn(InputName + "/" + SelectorName + " process lines: " + filename + " new size "
                        + reader.BaseStream.Length + " is smaler than last size "
                        + lastMaxOffset);
                    lastMaxOffset = reader.BaseStream.Length;
                    return;
                }

                if (reader.BaseStream.Length == lastMaxOffset)
                {
                    // wait some time before we check if some new data arrived to
                    // monitored file or for "deactivate" signal from main thread
                    Log.Info(InputName + "/" + SelectorName + " process lines: " + filename + " (pos=" + lastMaxOffset + ")");
                    if (!onlyWatcher)
                    {
                        wait.WaitOne(interval);
                    }
                    return;
                }

                //seek to the last max offset
                reader.BaseStream.Seek(lastMaxOffset, SeekOrigin.Begin);

                //read out of the file until the EOF
                string line;
                while (active && (line = reader.ReadLine()) != null)
                {
                    ProcessLine(line);
                }

                //update the last max offset
                lastMaxOffset = reader.BaseStream.Position;
            }
            catch (Exception ex)
            {
                // unexpected error - disable this input for a minute
                // or till log file "rotation" (new log file)
                errtime = DateTime.Now.Ticks;
                Log.Error(InputName + "/" + SelectorName + " process lines failed: " + ex.ToString());
            }
        }

        private void ProcessLine(string line)
        {
            Match m = null;
            for (int i = 0; i < match.Length; i++)
            {
                m = match[i].Match(line);
                if (m.Success)
                {
                    break;
                }
            }

            if (m == null || !m.Success)
            {
                Log.Info("No matched rule from " + InputName + "/" + SelectorName
                    + " for line: " + line);
                return;
            }

            bool ignored = false;
            for (int i = 0; !ignored && i < ignore.Length; i++)
            {
                if (ignore[i].Match(line).Success)
                {
                    Log.Info("Ignored (rule #" + i + ") matched log line from "
                        + InputName + "/" + SelectorName);
                    return;
                }
            }

            string strTimestamp = GetGroupData(m, "timestamp");
            string strTimestampUtc = GetGroupData(m, "timestamp_utc");
            string strUnixTimestamp = GetGroupData(m, "unix_timestamp");
            string strUnixTimestampUtc = GetGroupData(m, "unix_timestamp_utc");
            string strTime_b = GetGroupData(m, "time_b");
            string strTime_B = GetGroupData(m, "time_B");
            string strTime_e = GetGroupData(m, "time_e");
            string strTime_y = GetGroupData(m, "time_y");
            string strTime_Y = GetGroupData(m, "time_Y");
            string strTime_H = GetGroupData(m, "time_H");
            string strTime_M = GetGroupData(m, "time_M");
            string strTime_S = GetGroupData(m, "time_S");
            string strHostname = GetGroupData(m, "hostname");
            string strAddress = GetGroupData(m, "address");
            string strPort = GetGroupData(m, "port");
            string strUsername = GetGroupData(m, "username");
            string strDomain = GetGroupData(m, "domain");

            // simple/ugly datetime parsing
            DateTime created = DateTime.Now;
            if (!string.IsNullOrEmpty(strTimestamp) || !string.IsNullOrEmpty(strTimestampUtc) || !string.IsNullOrEmpty(strUnixTimestamp) || !string.IsNullOrEmpty(strUnixTimestampUtc))
            {
                try
	            {
                    long timestamp = long.Parse(strTimestamp);
                    if (!string.IsNullOrEmpty(strTimestamp))
                    {
                        DateTime dt = new DateTime(timestamp, DateTimeKind.Local);
                        created = dt.ToLocalTime();
                    }
                    else if (!string.IsNullOrEmpty(strTimestampUtc))
                    {
                        DateTime dt = new DateTime(timestamp, DateTimeKind.Utc);
                        created = dt.ToLocalTime();
                    }
                    else if (!string.IsNullOrEmpty(strUnixTimestamp))
                    {
                        DateTime dt = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Local);
                        created = dt.AddSeconds(timestamp).ToLocalTime();
                    }
                    else if (!string.IsNullOrEmpty(strUnixTimestampUtc))
                    {
                        DateTime dt = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
                        created = dt.AddSeconds(timestamp).ToLocalTime();
                    }
                    else
                    {
                        throw new Exception("it is a bug in sources if you see this exception");
                    }
                }
                catch (Exception ex)
	            {
		            Log.Info("Unable to parse timestamp (" + ex.ToString() + "): " + line);
		            return;
	            }
            }
            else
            {
                DateTime curr = DateTime.Now;
                int day = curr.Day;
                int month = curr.Month;
                int year = curr.Year;
                int hour = curr.Hour;
                int minute = curr.Minute;
                int second = curr.Second;

                try 
	            {
                    if (strTime_b != null)
                    {
                        switch (strTime_b.ToLower())
                        {
                            case "jan": month = 1; break;
                            case "feb": month = 2; break;
                            case "mar": month = 3; break;
                            case "apr": month = 4; break;
                            case "may": month = 5; break;
                            case "jun": month = 6; break;
                            case "jul": month = 7; break;
                            case "aug": month = 8; break;
                            case "sep": month = 9; break;
                            case "oct": month = 10; break;
                            case "nov": month = 11; break;
                            case "dec": month = 12; break;
                            default: throw new Exception("Unknown month short name \"" + strTime_b + "\"");
                        }
                    }
                    if (strTime_B != null)
                    {
                        switch (strTime_B.ToLower())
                        {
                            case "january": month = 1; break;
                            case "february": month = 2; break;
                            case "march": month = 3; break;
                            case "april": month = 4; break;
                            case "may": month = 5; break;
                            case "june": month = 6; break;
                            case "july": month = 7; break;
                            case "august": month = 8; break;
                            case "september": month = 9; break;
                            case "october": month = 10; break;
                            case "november": month = 11; break;
                            case "december": month = 12; break;
                            default: throw new Exception("Unknown month short name \"" + strTime_B + "\"");
                        }
                    }
                    if (strTime_e != null) day = int.Parse(strTime_e);
		            if (strTime_y != null) year = year / 100 + int.Parse(strTime_y);
		            if (strTime_Y != null) year = int.Parse(strTime_Y);
		            if (strTime_H != null) hour = int.Parse(strTime_H);
		            if (strTime_M != null) minute = int.Parse(strTime_M);
		            if (strTime_S != null) second = int.Parse(strTime_S);

                    created = new DateTime(year, month, day, hour, minute, second);
                }
	            catch (Exception ex)
	            {
		            Log.Info("Unable to parse timestamp (" + ex.ToString() + "): " + line);
		            return;
	            }
            }

            if (strHostname == null)
            {
                strHostname = Environment.MachineName;
            }

            IPAddress address = null;
            try
            {
                address = IPAddress.Parse(strAddress.Trim()).MapToIPv6();
            }
            catch (FormatException ex)
            {
                Log.Info("Received EventLog message from " + InputName
                    + "/" + SelectorName + ", invalid IP address format: "
                    + strAddress.Trim() + " (" + ex.Message + ")");
                return;
            }

            int port = -1;
            try
            {
                port = int.Parse(strPort);
            }
            catch (Exception)
            {
                // intentionally skip parser exeption for optional parameter
            }

            EventEntry evt = new EventEntry(created, strHostname,
                address, port, strUsername, strDomain, Login, this, line);

            Log.Info("FileLog[" + evt.Id + "@" + Name + "] queued message "
                + strUsername + "@" + address + ":" + port + " from " + strHostname
                + " status " + Login);

            equeue.Produce(evt, Processor);
        }

        private string GetGroupData(Match match, string key)
        {
            Group group = match.Groups[key];

            if (group == null || !group.Success || string.IsNullOrWhiteSpace(group.Value))
            {
                Log.Info("Received EventLog message from " + InputName
                    + "/" + SelectorName + ", " + key + " missing in regex");
                return null;
            }

            return group.Value;
        }
        #endregion
    }
}
