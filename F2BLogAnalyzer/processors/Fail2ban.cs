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
    public class Fail2banProcessor : BaseProcessor, IThreadSafeProcessor
    {
        #region Fields
        private string address;
        private string stateFile;
        private long findtime;
        private int ipv4_prefix;
        private int ipv6_prefix;

        private HistoryType history;
        private int history_fixed_count;
        private double history_fixed_decay;
        private int history_rrd_count;
        private int history_rrd_repeat;

        private List<Treshold> tresholds;

        //        private Dictionary<IPAddress, Queue<long>> data;
        //        private Dictionary<IPAddress, long> dataLast;
        private Dictionary<IPAddress, IFail> data;
        private int cleanup;
        private Timer cleanup_timer;
        private long clockskew;

        private Object thisLock = new Object();

        private static int MAX_COUNT = 10000;
        #endregion

        private enum HistoryType
        {
            ALL,
            ONE,
            FIXED,
            RRD,
        }

        private enum TresholdFunction
        {
            SIMPLE,
        }

        private class Treshold
        {
            public string Name { get; private set; }
            public TresholdFunction Function { get; private set; }
            public int Repeat { get; private set; }
            public int MaxRetry { get; private set; }
            public int Bantime { get; private set; }
            public string Action { get; private set; }
            public IDictionary<IPAddress, long> Last { get; set; }
            public Treshold(string name, TresholdFunction function, int maxretry, int repeat, int bantime, string action)
            {
                Name = name;
                Function = function;
                MaxRetry = maxretry;
                Repeat = repeat;
                Bantime = bantime;
                Action = action;
                Last = new Dictionary<IPAddress, long>();
            }
            public Treshold(ProcessorElement config, string name)
            {
                Name = name;
                Function = TresholdFunction.SIMPLE;
                MaxRetry = 10;
                Repeat = 0;
                Bantime = -1;
                Action = null;
                Last = new Dictionary<IPAddress, long>();

                if (config.Options["treshold." + name + ".function"] != null)
                {
                    string function = config.Options["treshold." + name + ".function"].Value.ToLower();
                    if (function == "simple")
                    {
                        Function = TresholdFunction.SIMPLE;
                    }
                    else
                    {
                        throw new ArgumentException("Unknown treshold." + name + ".function: " + function);
                    }
                }
                if (config.Options["treshold." + name + ".repeat"] != null)
                {
                    Repeat = int.Parse(config.Options["treshold." + name + ".repeat"].Value);
                }
                if (config.Options["treshold." + name + ".bantime"] != null)
                {
                    Bantime = int.Parse(config.Options["treshold." + name + ".bantime"].Value);
                }
                if (config.Options["treshold." + name + ".maxretry"] != null)
                {
                    MaxRetry = int.Parse(config.Options["treshold." + name + ".maxretry"].Value);
                }
                //if (config.Options["treshold." + name + ".actions"] != null)
                //{
                //    foreach (string action in config.Options["treshold." + name + ".actions"].Value.Split(','))
                //    {
                //        Actions.Add(action);
                //    }
                //}
                if (config.Options["treshold." + name + ".action"] != null)
                {
                    Action = config.Options["treshold." + name + ".action"].Value;
                }
            }
        }

        private interface IFail
        {
            int Count { get; }
            int Add(long timestamp);
            void Load(BinaryReader reader);
            void Save(BinaryWriter writer);
#if DEBUG
            void Debug(StreamWriter output);
#endif
        }

        private class FailAll : IFail
        {
            private long findtime;
            private Queue<long> data;
            private long last;

            public FailAll(long findtime)
            {
                Init(findtime);
            }

            public FailAll(BinaryReader reader, long findtime)
            {
                this.findtime = findtime;

                Load(reader);
            }

            private void Init(long findtime)
            {
                this.findtime = findtime;
                this.data = new Queue<long>();
                this.last = DateTime.Now.Ticks - findtime;
            }

            // clear expired entries
            private void Cleanup(long now)
            {
                if (last + findtime <= now)
                {
                    data.Clear();
                }
                else
                {
                    while (data.Peek() + findtime < now)
                    {
                        data.Dequeue();
                    }
                }
            }

            public int Count
            {
                get
                {
                    Cleanup(DateTime.Now.Ticks);

                    return data.Count;
                }
            }

            public int Add(long timestamp)
            {
                long now = DateTime.Now.Ticks;

                Cleanup(now);

                // skip old log data
                if (timestamp + findtime < now)
                {
                    return data.Count;
                }

                // NOTE: we should use "timestamp" instead of "now"
                // but that needs sortable "data" collection
                // and changes in Cleanup function
                data.Enqueue(now);
                last = now;

                return data.Count;
            }

            public void Load(BinaryReader reader)
            {
                long tmpFindtime = reader.ReadInt64();
                int tmpCount = reader.ReadInt32();

                this.data = new Queue<long>(Math.Min(tmpCount, Fail2banProcessor.MAX_COUNT));
                for (int i = 0; i < tmpCount; i++)
                {
                    this.data.Enqueue(reader.ReadInt64());
                }

                this.last = reader.ReadInt64();

                if (tmpFindtime != this.findtime)
                {
                    // different configuration
                    Init(findtime);
                }
            }

            public void Save(BinaryWriter writer)
            {
                writer.Write(findtime);
                writer.Write(data.Count);
                foreach (var item in data)
                {
                    writer.Write(item);
                }
                writer.Write(last);
            }

#if DEBUG
            public void Debug(StreamWriter output)
            {
                output.WriteLine("status " + GetType() + " findtime: " + findtime);
                output.WriteLine("status " + GetType() + " last: " + last);
                output.WriteLine("status " + GetType() + " data(" + data.Count
                    + "): " + string.Join<long>(",", data));
            }
#endif
        }

        private class FailOne : IFail
        {
            private long findtime;
            private int data;
            private long last; // last cleanup

            public FailOne(long findtime)
            {
                Init(findtime);
            }

            public FailOne(BinaryReader reader, long findtime)
            {
                this.findtime = findtime;

                Load(reader);
            }

            private void Init(long findtime)
            {
                this.findtime = findtime;
                this.data = 0;
                this.last = DateTime.Now.Ticks - findtime;
            }

            public int Count
            {
                get
                {
                    Cleanup(DateTime.Now.Ticks);

                    return data;
                }
            }

            private void Cleanup(long now)
            {
                // no or empty history (reset last cleanup time)
                if (data == 0)
                {
                    last = now;
                    return;
                }

                // history data too old (older than findtime, reset last cleanup time)
                if (last + findtime <= now)
                {
                    data = 0;
                    last = now;
                    return;
                }

                // substract from treshold data number that corresponds
                // data fraction from last call to cleanup
                double findtime_fraction = (double)(now - last) / findtime;
                int substract = (int)(findtime_fraction * data);

                if (substract == 0)
                {
                    return;
                }

                if (substract > data)
                {
                    data = 0;
                }
                else
                {
                    data -= substract;
                }
                last = now;
            }

            public int Add(long timestamp)
            {
                long now = DateTime.Now.Ticks;

                Cleanup(now);

                // skip old log data
                if (timestamp + findtime < now)
                {
                    return data;
                }

                data++;

                return data;
            }

            public void Load(BinaryReader reader)
            {
                long tmpFindtime = reader.ReadInt64();
                this.data = reader.ReadInt32();
                this.last = reader.ReadInt64();

                if (tmpFindtime != this.findtime)
                {
                    // different configuration
                    Init(findtime);
                }
            }

            public void Save(BinaryWriter writer)
            {
                writer.Write(findtime);
                writer.Write(data);
                writer.Write(last);
            }

#if DEBUG
            public void Debug(StreamWriter output)
            {
                output.WriteLine("status " + GetType() + " findtime: " + findtime);
                output.WriteLine("status " + GetType() + " last: " + last);
                output.WriteLine("status " + GetType() + " data: " + data);
            }
#endif
        }

        private class FailFixed : IFail
        {
            private long findtime;
            private int count;
            private double[] decay;
            private int[] data;
            private long start;
            private long last;
            private int sum;

            public FailFixed(long findtime, int count, double decay = 1.0)
            {
                Init(findtime, count);
            }

            public FailFixed(BinaryReader reader, long findtime, int count, double decay = 1.0)
            {
                this.findtime = findtime;
                this.count = count;
                this.decay = null;

                if (decay != 1.0)
                {
                    this.decay = new double[count];
                    this.decay[0] = 1.0;
                    for (int i = 1; i < count; i++)
                    {
                        this.decay[i] = this.decay[i - 1] * decay;
                    }
                }

                Load(reader);
            }

            private void Init(long findtime, int count)
            {
                long now = DateTime.Now.Ticks;

                this.findtime = findtime;
                this.count = count;
                this.data = new int[count];
                this.start = now;
                this.last = now - findtime;
                this.sum = 0;
            }

            public int Count
            {
                get
                {
                    Cleanup(DateTime.Now.Ticks);

                    if (decay == null)
                    {
                        return sum;
                    }
                    else
                    {
                        double tmp = 0;
                        for (int i = 0; i < data.Length; i++)
                        {
                            tmp += data[i] * decay[i];
                        }

                        return (int) tmp;
                    }
                }
            }

            private void Cleanup(long now)
            {
                if (sum == 0)
                {
                    return;
                }

                if (now < start)
                {
                    Log.Warn("Fail2ban::FailFixed: now(" + now
                        + ") < start(" + start + ") ... fixing to "
                        + ((now / findtime) * findtime + start % findtime));
                    start = (now / findtime) * findtime + start % findtime;
                }

                if (last + findtime <= now || last > now)
                {
                    if (last > now)
                    {
                        Log.Warn("Fail2ban::FailFixed: last(" + last + ") > now(" + now + ")");
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
                long now = DateTime.Now.Ticks;

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
                if (tmpCount > Fail2banProcessor.MAX_COUNT)
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
                writer.Write(findtime);
                writer.Write(data.Length);
                foreach (var item in data)
                {
                    writer.Write(item);
                }
                writer.Write(start);
                writer.Write(last);
                writer.Write(sum);
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

        private class FailRRD : IFail
        {
            private long findtime;
            private int count;
            private int repeat;

            public FailRRD(long findtime, int count, int repeat)
            {
                Init(findtime, count, repeat);
            }

            public FailRRD(BinaryReader reader, long findtime, int count, int repeat)
            {
                this.findtime = findtime;
                this.count = count;
                this.repeat = repeat;

                Init(findtime, count, repeat);
            }

            private void Init(long findtime, int count, int repeat)
            {
                this.findtime = findtime;
                this.count = count;
                this.repeat = repeat;
                throw new NotImplementedException("FailRRD is not implemented");
            }

            public int Count
            {
                get { throw new NotImplementedException(); }
            }

            public int Add(long timestamp)
            {
                throw new NotImplementedException();
            }

            public void Load(BinaryReader reader)
            {
                throw new NotImplementedException();
            }

            public void Save(BinaryWriter writer)
            {
                throw new NotImplementedException();
            }

#if DEBUG
            public void Debug(StreamWriter output)
            {
                throw new NotImplementedException();
            }
#endif
        }


        #region Constructors
        public Fail2banProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            // default values
            address = "Event.Address";
            stateFile = null;
            findtime = 600;
            ipv4_prefix = 32;
            ipv6_prefix = 64;
            cleanup = 300;

            history = HistoryType.ALL;
            history_fixed_count = 10;
            history_fixed_decay = 1.0;
            history_rrd_count = 2;
            history_rrd_repeat = 2;

            tresholds = new List<Fail2banProcessor.Treshold>();

            if (config.Options["address"] != null)
            {
                address = config.Options["address"].Value;
            }

            // set values from config file
            if (config.Options["state"] != null)
            {
                stateFile = config.Options["state"].Value;
            }

            if (config.Options["findtime"] != null)
            {
                findtime = long.Parse(config.Options["findtime"].Value);
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
            if (config.Options["cleanup"] != null)
            {
                cleanup = int.Parse(config.Options["cleanup"].Value);
            }

            if (config.Options["history"] != null)
            {
                switch (config.Options["history"].Value.ToLower())
                {
                    case "all": history = HistoryType.ALL; break;
                    case "one": history = HistoryType.ONE; break;
                    case "fixed": history = HistoryType.FIXED; break;
                    case "rrd": history = HistoryType.RRD; break;
                    default:
                        throw new ArgumentException("Unknown history type: "
                   + config.Options["history"].Value.ToLower());
                }
            }
            if (config.Options["history.fixed.count"] != null)
            {
                history_fixed_count = int.Parse(config.Options["history.fixed.count"].Value);
            }
            if (config.Options["history.fixed.decay"] != null)
            {
                history_fixed_decay = double.Parse(config.Options["history.fixed.decay"].Value);
            }
            if (config.Options["history.rrd.count"] != null)
            {
                history_rrd_count = int.Parse(config.Options["history.rrd.count"].Value);
            }
            if (config.Options["history.rrd.repeat"] != null)
            {
                history_rrd_repeat = int.Parse(config.Options["history.rrd.repeat"].Value);
            }

            if (config.Options["tresholds"].Value != null)
            {
                foreach (string treshold in config.Options["tresholds"].Value.Split(','))
                {
                    tresholds.Add(new Treshold(config, treshold));
                }
            }

            data = new Dictionary<IPAddress, IFail>();
            // create timer to periodically cleanup expired data
            if (cleanup > 0)
            {
                cleanup_timer = new Timer(cleanup * 1000);
                cleanup_timer.Elapsed += Cleanup;
                cleanup_timer.Enabled = true;
            }

            clockskew = 0;
        }


        ~Fail2banProcessor()
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
            int dataCountBefore, dataCountAfter;
            DateTime dataTimeBefore, dataTimeAfter;
            int[] tresholdCountBefore = new int[tresholds.Count];
            int[] tresholdCountAfter = new int[tresholds.Count];
            DateTime tresholdTimeBefore, tresholdTimeAfter;

            // cleanup empty / expired fail objects from "data" dictionary
            Log.Info("Fail2ban[" + Name + "]: cleanup expired data started");

            lock (thisLock)
            {
                dataCountBefore = data.Count;
                dataTimeBefore = DateTime.UtcNow;

                foreach (var s in data.Where(kv => kv.Value.Count == 0).ToList())
                {
                    data.Remove(s.Key);

                    foreach (Treshold treshold in tresholds)
                    {
                        if (treshold.Last.ContainsKey(s.Key))
                        {
                            treshold.Last.Remove(s.Key);
                        }
                    }
                }

                dataTimeAfter = DateTime.UtcNow;
                dataCountAfter = data.Count;

                tresholdTimeBefore = DateTime.UtcNow;

                int tresholdIndex = 0;
                long now = DateTime.Now.Ticks;
                foreach (Treshold treshold in tresholds)
                {
                    tresholdCountBefore[tresholdIndex] = treshold.Last.Count;
                    tresholdCountAfter[tresholdIndex] = treshold.Last.Count;
                    tresholdIndex++;

                    if (treshold.Repeat == 0)
                        continue;

                    foreach (var s in treshold.Last.Where(kv => kv.Value + treshold.Repeat * TimeSpan.TicksPerSecond <= now).ToList())
                    {
                        treshold.Last.Remove(s.Key);
                    }

                    tresholdCountAfter[0] = treshold.Last.Count;
                }

                tresholdTimeAfter = DateTime.UtcNow;
            }

            Log.Info("Fail2ban[" + Name + "]: cleanup expired data ("
                + dataCountBefore + " -> " + dataCountAfter + ") in "
                + dataTimeAfter.Subtract(dataTimeBefore).TotalMilliseconds
                + "ms");

            Log.Info("Fail2ban[" + Name + "]: cleanup expired tresholds ("
                + string.Join("/", tresholds) + ": "
                + string.Join("/", tresholdCountBefore) + " -> "
                + string.Join("/", tresholdCountAfter) + ") in "
                + tresholdTimeAfter.Subtract(tresholdTimeBefore).TotalMilliseconds
                + "ms");
        }


        private bool Check(IPAddress addr, Treshold treshold, int cnt)
        {
            bool over = false;
            long last = 0;
            bool hasLast = treshold.Last.TryGetValue(addr, out last);

            //Log.Error("XXX addr=" + addr
            //    + ", cnt=" + cnt
            //    + ", Name=" + treshold.Name
            //    + ", MaxRetry=" + treshold.MaxRetry
            //    + ", Repeat=" + treshold.Repeat
            //    + ", Last(" + treshold.Last.Count + ")=" + last
            //    + ", now=" + DateTime.Now.Ticks);
            // is number of failed logins over treshold according
            // configured treshold function and number of failed logins
            if (treshold.Function == TresholdFunction.SIMPLE)
            {
                if (cnt > treshold.MaxRetry)
                {
                    over = true;
                }
            }

            if (!over)
            {
                if (hasLast)
                {
                    treshold.Last.Remove(addr);
                }

                return false;
            }

            // check rules for repeated over treshold notifications
            long now = DateTime.Now.Ticks;

            if (treshold.Repeat == 0 && last != 0)
            {
                return false;
            }
            else if (treshold.Repeat > 0 && last + treshold.Repeat * TimeSpan.TicksPerSecond > now)
            {
                return false;
            }
            else
            {
                treshold.Last[addr] = now;
                return true;
            }
        }
        private void ReadState(string filename)
        {
            using (Stream stream = File.Open(filename, FileMode.Open))
            using (BinaryReader reader = new BinaryReader(stream))
            {
                lock (thisLock)
                {
                    int nhistory = reader.ReadInt32();
                    for (int i = 0; i < nhistory; i++)
                    {
                        IPAddress addr = new IPAddress(reader.ReadBytes(16));
                        IFail fail = null;

                        switch (history)
                        {
                            case HistoryType.ALL: fail = new FailAll(reader, findtime * TimeSpan.TicksPerSecond); break;
                            case HistoryType.ONE: fail = new FailOne(reader, findtime * TimeSpan.TicksPerSecond); break;
                            case HistoryType.FIXED: fail = new FailFixed(reader, findtime * TimeSpan.TicksPerSecond, history_fixed_count, history_fixed_decay); break;
                            case HistoryType.RRD: fail = new FailRRD(reader, findtime * TimeSpan.TicksPerSecond, history_rrd_count, history_rrd_repeat); break;
                        }

                        if (fail.Count > 0)
                        {
                            data[addr] = fail;
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
                lock (thisLock)
                {
                    writer.Write(data.Count);
                    foreach (var item in data)
                    {
                        IPAddress addr = item.Key;
                        IFail fail = item.Value;

                        writer.Write(addr.GetAddressBytes());
                        fail.Save(writer);
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
                Log.Info("Fail2ban[" + Name + "]: Load processor state from \""
                    + stateFile + "\"");

                try
                {
                    ReadState(stateFile);
                }
                catch (Exception ex)
                {
                    Log.Warn("Fail2ban[" + Name + "]: Unable to read state file \""
                        + stateFile + "\": " + ex.Message);
                }
            }
        }

        public override void Stop()
        {
            if (stateFile == null)
                return;

            Log.Info("Fail2ban[" + Name + "]: Save processor state to \""
                + stateFile + "\"");

            try
            {
                WriteState(stateFile);
            }
            catch (Exception ex)
            {
                Log.Warn("Fail2ban[" + Name + "]: Unable to write state file \""
                    + stateFile + "\": " + ex.Message);
            }
        }

        public override string Execute(EventEntry evtlog)
        {
            string strAddress = evtlog.GetProcData<string>(address);
            if (string.IsNullOrEmpty(strAddress))
            {
                Log.Info("Fail2ban[" + Name
                    + "]: empty address attribute: " + address);

                return goto_error;
            }

            IPAddress addr = null;
            try
            {
                addr = IPAddress.Parse(strAddress.Trim()).MapToIPv6();
            }
            catch (FormatException ex)
            {
                Log.Info("Fail2ban[" + Name
                    + "]: invalid address " + address
                    + "[" + strAddress + "]: " + ex.Message);

                return goto_error;
            }

            // get fail2ban network address for given IP and prefix
            int prefix = ipv6_prefix;
            if (addr.IsIPv4MappedToIPv6)
            {
                prefix = ipv4_prefix;
                if (prefix <= 32)
                {
                    prefix += 96;
                }
            }
            if (prefix != 128)
            {
                addr = Utils.GetNetwork(addr, prefix);
            }

            // fix log event that came from future(?!), _we_ have correct time!
            long now = DateTime.Now.Ticks;
            long logtime = evtlog.Created.Ticks;

            if (logtime > now)
            {
                // is clock skew too hight!? occasionally log warning
                if (logtime > now + 300 * TimeSpan.TicksPerSecond)
                {
                    if (clockskew + 60 * TimeSpan.TicksPerSecond < now)
                    {
                        clockskew = now;

                        Log.Warn("Fail2ban[" + Name + "]: logtime from future ("
                            + ((logtime - now) / TimeSpan.TicksPerSecond) + " seconds) for "
                            + evtlog.Input + "/" + evtlog.Input.SelectorName
                            + " from " + evtlog.Machine);
                    }
                }

                logtime = now;
            }

            int failcnt = 0;
            bool[] tresholdCheck = new bool[tresholds.Count];

            lock (thisLock)
            {
                // update failed login fail2ban data
                IFail fail;
                if (!data.TryGetValue(addr, out fail))
                {
                    switch (history)
                    {
                        case HistoryType.ALL: fail = new FailAll(findtime * TimeSpan.TicksPerSecond); break;
                        case HistoryType.ONE: fail = new FailOne(findtime * TimeSpan.TicksPerSecond); break;
                        case HistoryType.FIXED: fail = new FailFixed(findtime * TimeSpan.TicksPerSecond, history_fixed_count, history_fixed_decay); break;
                        case HistoryType.RRD: fail = new FailRRD(findtime * TimeSpan.TicksPerSecond, history_rrd_count, history_rrd_repeat); break;
                    }

                    data[addr] = fail;
                }
                failcnt = fail.Add(logtime);

                for (int i = 0; i < tresholds.Count; i++)
                {
                    tresholdCheck[i] = Check(addr, tresholds[i], failcnt);
                }
            }

            // evaluate all defined tresholds
            for (int i = 0; i < tresholds.Count; i++)
            {
                if (!tresholdCheck[i])
                    continue;

                Treshold treshold = tresholds[i];
                int tmpPrefix = prefix;
                IPAddress tmpAddr = addr;
                long expiration = now + TimeSpan.FromSeconds(treshold.Bantime).Ticks;

                if (addr.IsIPv4MappedToIPv6)
                {
                    // workaround for buggy MapToIPv4 implementation
                    tmpAddr = Fixes.MapToIPv4(addr);
                    tmpPrefix = prefix - 96;
                }

                Log.Info("Fail2ban[" + Name + "]: reached treshold "
                        + treshold.Name + " (" + treshold.MaxRetry + "&"
                        + failcnt + ") for " + tmpAddr + "/" + tmpPrefix);

                if (evtlog.HasProcData("Fail2ban.All"))
                {
                    string all = evtlog.GetProcData<string>("Fail2ban.All");
                    evtlog.SetProcData("Fail2ban.All", all + "," + Name);
                }
                else
                {
                    evtlog.SetProcData("Fail2ban.All", Name);
                }
                evtlog.SetProcData("Fail2ban.Last", Name);

                evtlog.SetProcData(Name + ".Address", tmpAddr);
                evtlog.SetProcData(Name + ".Prefix", tmpPrefix);
                evtlog.SetProcData(Name + ".FailCnt", failcnt);
                evtlog.SetProcData(Name + ".Bantime", treshold.Bantime);
                evtlog.SetProcData(Name + ".Expiration", expiration);
                evtlog.SetProcData(Name + ".Treshold", treshold.Name);

                // Add to "action" queue
                Produce(new EventEntry(evtlog), treshold.Action, EventQueue.Priority.High);
            }

            return goto_next;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            output.WriteLine("config address: " + address);
            output.WriteLine("config findtime: " + findtime);
            output.WriteLine("config ipv4_prefix: " + ipv4_prefix);
            output.WriteLine("config ipv6_prefix: " + ipv6_prefix);
            output.WriteLine("config cleanup: " + cleanup);
            output.WriteLine("config history: " + history);
            output.WriteLine("config history_fixed_count: " + history_fixed_count);
            output.WriteLine("config history_fixed_decay: " + history_fixed_decay);
            output.WriteLine("config history_rrd_count: " + history_rrd_count);
            output.WriteLine("config history_rrd_repeat: " + history_rrd_repeat);
            foreach (Treshold treshold in tresholds)
            {
                output.WriteLine("config treshold " + treshold.Name + " function: " + treshold.Function);
                output.WriteLine("config treshold " + treshold.Name + " repeat: " + treshold.Repeat);
                output.WriteLine("config treshold " + treshold.Name + " maxretry: " + treshold.MaxRetry);
                output.WriteLine("config treshold " + treshold.Name + " bantime: " + treshold.Bantime);
                output.WriteLine("config treshold " + treshold.Name + " action: " + treshold.Action);
                output.Write("config treshold " + treshold.Name + " last(" + treshold.Last.Count + "): ");
                foreach (var kvs in treshold.Last)
                {
                    output.Write(kvs.Key + "(" + kvs.Value + "),");
                }
                output.WriteLine();
            }

            lock (thisLock)
            {
                foreach (var item in data)
                {
                    IPAddress addr = item.Key;
                    IFail fail = item.Value;

                    output.WriteLine("status address " + addr);
                    fail.Debug(output);
                }
            }
        }
#endif
        #endregion
    }
}
