#region Imports
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Timers;
#endregion

namespace F2B.processors
{
    public class LoginProcessor : BoolProcessor, IThreadSafeProcessor
    {

        private class LoginSlidingHistory
        {
            private long findtime;
            private int count;
            private int[] data;
            private long start;
            private long last;
            private int sum;

            public LoginSlidingHistory(long findtime, int count)
            {
                Init(findtime, count);
            }

            public LoginSlidingHistory(BinaryReader reader, long findtime, int count)
            {
                this.findtime = findtime;
                this.count = count;

                Load(reader);
            }

            public int Count
            {
                get
                {
                    Cleanup(DateTime.UtcNow.Ticks);

                    return sum;
                }
            }

            private void Init(long findtime, int count)
            {
                long now = DateTime.UtcNow.Ticks;

                this.findtime = findtime;
                this.count = count;
                this.data = new int[count];
                this.start = now;
                this.last = now - findtime;
                this.sum = 0;
            }

            private void Cleanup(long now)
            {
                if (sum == 0)
                {
                    return;
                }

                if (now < start)
                {
                    Log.Warn("LoginProcessor::LoginSlidingHistory: now(" + now
                        + ") < start(" + start + ") ... fixing to "
                        + ((now / findtime) * findtime + start % findtime));
                    start = (now / findtime) * findtime + start % findtime;
                }

                if (last + findtime <= now || last > now)
                {
                    if (last > now)
                    {
                        Log.Warn("LoginProcessor::LoginSlidingHistory: last(" + last + ") > now(" + now + ")");
                    }

                    for (int i = 0; i < data.Length; i++)
                    {
                        data[i] = 0;
                    }

                    sum = 0;
                }
                else
                {
                    long pos = (long)(((double)(now - start) / findtime) * data.Length) % data.Length;
                    long lastpos = (long)(((double)(last - start) / findtime) * data.Length) % data.Length;

                    if (lastpos != pos)
                    {
                        long endpos = (pos > lastpos) ? pos : pos + data.Length;
                        for (long i = lastpos + 1; i <= endpos; i++)
                        {
                            long currpos = i % data.Length;
                            sum -= data[currpos];
                            data[currpos] = 0;
                        }
                    }
                }
            }

            public int Add(long timestamp)
            {
                long now = DateTime.UtcNow.Ticks;

                Cleanup(now);

                // skip old log data
                if (timestamp + findtime < now)
                {
                    return sum;
                }

                // NOTE: we should use "timestamp" instead of "now"
                // but that requires also changes in Cleanup function
                long pos = (long)(((double)(now - start) / findtime) * data.Length) % data.Length;
                data[pos]++;
                sum++;
                last = now;

                return sum;
            }

            public void Load(BinaryReader reader)
            {
                long tmpFindtime = reader.ReadInt64();
                int tmpCount = reader.ReadInt32();
                if (tmpCount > LoginProcessor.MAX_COUNT)
                {
                    throw new InvalidDataException("invalid state file data count = " + tmpCount);
                }

                this.data = new int[tmpCount];
                for (int i = 0; i < tmpCount; i++)
                {
                    this.data[i] = reader.ReadInt32();
                }

                this.start = reader.ReadInt64();
                this.last = reader.ReadInt64();
                this.sum = reader.ReadInt32();

                if (tmpFindtime != this.findtime || tmpCount != this.count)
                {
                    // different configuration
                    Init(findtime, count);
                }
            }

            public void Save(BinaryWriter writer)
            {
                writer.Write(this.findtime);
                writer.Write(this.data.Length);
                for (int i = 0; i < data.Length; i++)
                {
                    writer.Write(data[i]);
                }
                writer.Write(this.start);
                writer.Write(this.last);
                writer.Write(this.sum);
            }

#if DEBUG
            public void Debug(StreamWriter output)
            {
                output.WriteLine("status " + GetType() + " findtime: " + findtime);
                output.WriteLine("status " + GetType() + " last: " + last);
                output.WriteLine("status " + GetType() + " start: " + start);
                output.WriteLine("status " + GetType() + " sum: " + sum);
                output.WriteLine("status " + GetType() + " data(" + data.Length
                    + "): " + string.Join<int>(",", data));
            }
#endif
        }


        #region Fields
        private int maxsize;
        private string stateFile;
        private long findtime;
        private int count;
        private int cleanup;
        private Timer cleanup_timer;
        private int ipv4_prefix;
        private int ipv6_prefix;

        private IDictionary<IPAddress, LoginSlidingHistory> success;
        private IDictionary<IPAddress, LoginSlidingHistory> failure;
        private Object lockSuccess = new Object();
        private Object lockFailure = new Object();

        private static int MAX_COUNT = 10000;
        #endregion

        #region Constructors
        public LoginProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            maxsize = 100000;
            stateFile = null;
            findtime = 86400;
            count = 24;
            ipv4_prefix = 32;
            ipv6_prefix = 64;

            if (config.Options["maxsize"] != null)
            {
                maxsize = int.Parse(config.Options["maxsize"].Value);
            }

            if (config.Options["state"] != null)
            {
                stateFile = config.Options["state"].Value;
            }

            if (config.Options["findtime"] != null)
            {
                findtime = long.Parse(config.Options["findtime"].Value);
            }
            if (config.Options["count"] != null)
            {
                count = int.Parse(config.Options["count"].Value);
            }

            if (config.Options["ipv4_prefix"] != null)
            {
                ipv4_prefix = int.Parse(config.Options["ipv4_prefix"].Value);
                if (ipv4_prefix < 128 - 32)
                {
                    ipv4_prefix += (128 - 32);
                }
            }
            if (config.Options["ipv6_prefix"] != null)
            {
                ipv6_prefix = int.Parse(config.Options["ipv6_prefix"].Value);
            }

            if (count > LoginProcessor.MAX_COUNT)
            {
                throw new ArgumentOutOfRangeException("Login option \"count\" must be within (0, 10000)");
            }

            if (findtime == 0 || count == 0)
            {
                // login history disabled
                findtime = 0;
                count = 0;
                cleanup = 0;
            }
            else
            {
                cleanup = (int)(findtime / count) > 0 ? (int)(findtime / count) : 1;

                cleanup_timer = new Timer(cleanup * 1000);
                cleanup_timer.Elapsed += Cleanup;
                cleanup_timer.Enabled = true;
            }

            success = new Dictionary<IPAddress, LoginSlidingHistory>();
            failure = new Dictionary<IPAddress, LoginSlidingHistory>();
        }

        ~LoginProcessor()
        {
            if (cleanup_timer != null && cleanup_timer.Enabled)
            {
                cleanup_timer.Enabled = false;
                cleanup_timer.Dispose();
            }
        }
        #endregion

        #region Methods
        private void Cleanup(object sender, ElapsedEventArgs e)
        {
            if (!cleanup_timer.Enabled)
            {
                // this should prevent race condition, because elapsed
                // event is queued for execution on a thread poole thread
                return;
            }

            Cleanup();
        }

        private void Cleanup()
        {
            int successCountBefore, successCountAfter;
            int failureCountBefore, failureCountAfter;

            // cleanup empty / expired fail objects from "data" dictionary
            Log.Info("Login[" + Name + "]: cleanup expired data started");

            lock (lockSuccess)
            {
                successCountBefore = success.Count;
                foreach (var s in success.Where(kv => kv.Value.Count == 0).ToList())
                {
                    success.Remove(s.Key);
                }
                successCountAfter = success.Count;
            }

            lock (lockFailure)
            {
                failureCountBefore = failure.Count;
                foreach (var s in failure.Where(kv => kv.Value.Count == 0).ToList())
                {
                    failure.Remove(s.Key);
                }
                failureCountAfter = failure.Count;
            }

            Log.Info("Login[" + Name + "]: cleanup expired data finished: "
                + successCountBefore + "/" + failureCountBefore
                + " -> "
                + successCountAfter + "/" + failureCountAfter
                + ")");
        }

        private void ReadState(string filename)
        {
            using (Stream stream = File.Open(filename, FileMode.Open))
            using (BinaryReader reader = new BinaryReader(stream))
            {
                lock (lockSuccess)
                {
                    int nsuccess = reader.ReadInt32();
                    for (int i = 0; i < nsuccess; i++)
                    {
                        IPAddress addr = new IPAddress(reader.ReadBytes(16));
                        LoginSlidingHistory data = new LoginSlidingHistory(reader, TimeSpan.FromSeconds(findtime).Ticks, count);
                        if (data.Count > 0)
                        {
                            success[addr] = data;
                        }
                    }
                }
                lock (lockFailure)
                {
                    int nfailure = reader.ReadInt32();
                    for (int i = 0; i < nfailure; i++)
                    {
                        IPAddress addr = new IPAddress(reader.ReadBytes(16));
                        LoginSlidingHistory data = new LoginSlidingHistory(reader, TimeSpan.FromSeconds(findtime).Ticks, count);
                        if (data.Count > 0)
                        {
                            failure[addr] = data;
                        }
                    }
                }
            }
        }

        private void WriteState(string filename)
        {
            Cleanup();

            using (Stream stream = File.Open(filename, FileMode.Create))
            using (BinaryWriter writer = new BinaryWriter(stream))
            {
                lock (lockSuccess)
                {
                    writer.Write(success.Count);
                    foreach (var item in success)
                    {
                        IPAddress addr = item.Key;
                        LoginSlidingHistory data = item.Value;

                        writer.Write(addr.GetAddressBytes());
                        data.Save(writer);
                    }
                }
                lock (lockFailure)
                {
                    writer.Write(failure.Count);
                    foreach (var item in failure)
                    {
                        IPAddress addr = item.Key;
                        LoginSlidingHistory data = item.Value;

                        writer.Write(addr.GetAddressBytes());
                        data.Save(writer);
                    }
                }
            }
        }
        #endregion

        #region Override
        public override void Start()
        {
            if (stateFile == null)
                return;

            if (File.Exists(stateFile))
            {
                Log.Info("Login[" + Name + "]: Load processor state from \""
                    + stateFile + "\"");

                try
                {
                    ReadState(stateFile);
                }
                catch (Exception ex)
                {
                    Log.Warn("Login[" + Name + "]: Unable to read state file \""
                        + stateFile + "\": " + ex.Message);
                }
            }
        }

        public override void Stop()
        {
            if (stateFile == null)
                return;

            Log.Info("Login[" + Name + "]: Save processor state to \""
                + stateFile + "\"");

            try
            {
                WriteState(stateFile);
            }
            catch (Exception ex)
            {
                Log.Warn("Login[" + Name + "]: Unable to write state file \""
                    + stateFile + "\": " + ex.Message);
            }
        }

        public override string Execute(EventEntry evtlog)
        {
            if (count != 0)
            {
                // get network address for given IP and prefix
                IPAddress addr = evtlog.Address;
                int prefix = ipv6_prefix;
                if (evtlog.Address.IsIPv4MappedToIPv6)
                {
                    prefix = ipv4_prefix;
                    if (prefix <= 32)
                    {
                        prefix += 96;
                    }
                }
                if (prefix != 128)
                {
                    addr = Utils.GetNetwork(evtlog.Address, prefix);
                }

                // apply sliding windows for success/failure logins
                int cnt;
                LoginSlidingHistory history;
                long timestamp = evtlog.Created.ToUniversalTime().Ticks;
                evtlog.SetProcData("Login.Last", Name);

                cnt = 0;
                history = null;
                lock (lockSuccess)
                {
                    if (!success.TryGetValue(evtlog.Address, out history))
                    {
                        // number of records stored in dictionary has maxsize limit
                        if (evtlog.Login == LoginStatus.SUCCESS && (maxsize == 0 || success.Count < maxsize))
                        {
                            history = new LoginSlidingHistory(TimeSpan.FromSeconds(findtime).Ticks, count);
                            success[evtlog.Address] = history;
                        }
                    }

                    if (history != null)
                    {
                        if (evtlog.Login == LoginStatus.SUCCESS)
                        {
                            cnt = history.Add(timestamp);
                        }
                        else
                        {
                            cnt = history.Count;
                        }
                    }
                }

                // Store address historical data only if there was at least one
                // successfull login. This should limit number of records stored
                // in memory (unless malicious use of stolen username+password
                // e.g. for spam using SMTP AUTH ... in that case we should
                // limit number of records in success/failure dictionaries)
                if (cnt > 0)
                {
                    evtlog.SetProcData(Name + ".Success", cnt);

                    cnt = 0;
                    history = null;
                    lock (lockFailure)
                    {
                        if (!failure.TryGetValue(evtlog.Address, out history))
                        {
                            if (evtlog.Login == LoginStatus.FAILURE)
                            {
                                history = new LoginSlidingHistory(TimeSpan.FromSeconds(findtime).Ticks, count);
                                failure[evtlog.Address] = history;
                            }
                        }

                        if (history != null)
                        {
                            if (evtlog.Login == LoginStatus.FAILURE)
                            {
                                cnt = history.Add(timestamp);
                            }
                            else
                            {
                                cnt = history.Count;
                            }
                        }
                    }
                    evtlog.SetProcData(Name + ".Failure", cnt);
                }
                else
                {
                    evtlog.SetProcData(Name + ".Success", 0);
                    evtlog.SetProcData(Name + ".Failure", 0);
                }
            }

            if (evtlog.Login == LoginStatus.SUCCESS)
            {
                return goto_success;
            }
            else if (evtlog.Login == LoginStatus.FAILURE)
            {
                return goto_failure;
            }
            else
            {
                return goto_next;
            }
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            output.WriteLine("config maxsize: " + maxsize);
            output.WriteLine("config state: " + stateFile);
            output.WriteLine("config findtime: " + findtime);
            output.WriteLine("config count: " + count);
            output.WriteLine("config ipv4_prefix: " + ipv4_prefix);
            output.WriteLine("config ipv6_prefix: " + ipv6_prefix);
            lock (lockSuccess)
            {
                foreach (var item in success)
                {
                    IPAddress addr = item.Key;
                    LoginSlidingHistory data = item.Value;

                    output.WriteLine("status address success " + addr);
                    data.Debug(output);
                }
            }
            lock (lockFailure)
            {
                foreach (var item in failure)
                {
                    IPAddress addr = item.Key;
                    LoginSlidingHistory data = item.Value;

                    output.WriteLine("status address failure " + addr);
                    data.Debug(output);
                }
            }
        }
#endif
        #endregion
    }
}
