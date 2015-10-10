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
    public class Fail2banProcessor : BaseProcessor
    {
        #region Fields
        private long findtime;
        private int ipv4_prefix;
        private int ipv6_prefix;

        private HistoryType history;
        private int history_fixed_count;
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
            private int[] data;
            private long start;
            private long last;
            private int sum;

            public FailFixed(long findtime, int cnt)
            {
                long now = DateTime.Now.Ticks;

                this.findtime = findtime;
                this.data = new int[cnt];
                this.start = now;
                this.last = now - findtime;
                this.sum = 0;
            }

            public int Count
            {
                get
                {
                    Cleanup(DateTime.Now.Ticks);

                    return sum;
                }
            }

            private void Cleanup(long now)
            {
                if (sum == 0)
                {
                    return;
                }

                if (last + findtime <= now)
                {
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
            private int cnt;
            private int repeat;
            public FailRRD(long findtime, int cnt, int repeat)
            {
                this.findtime = findtime;
                this.cnt = cnt;
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
            findtime = 600;
            ipv4_prefix = 32;
            ipv6_prefix = 64;
            cleanup = 300;

            history = HistoryType.ALL;
            history_fixed_count = 10;
            history_rrd_count = 2;
            history_rrd_repeat = 2;

            tresholds = new List<Fail2banProcessor.Treshold>();

            // set values from config file
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

            // cleanup empty / expired fail objects from "data" dictionary
            lock (thisLock)
            {
                Log.Info("Fail2ban[" + Name + "]: cleanup expired data started: "
                    + data.Count + ")");

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

                Log.Info("Fail2ban[" + Name + "]: cleanup expired data finished: "
                    + data.Count + ")");

                long now = DateTime.Now.Ticks;
                foreach (Treshold treshold in tresholds)
                {
                    if (treshold.Repeat == 0)
                        continue;

                    Log.Info("Fail2ban[" + Name + "]: cleanup expired treshold "
                        + treshold.Name + " started: " + treshold.Last.Count + ")");

                    foreach (var s in treshold.Last.Where(kv => kv.Value + treshold.Repeat * TimeSpan.TicksPerSecond <= now).ToList())
                    {
                        treshold.Last.Remove(s.Key);
                    }

                    Log.Info("Fail2ban[" + Name + "]: cleanup expired treshold "
                        + treshold.Name + " finished: " + treshold.Last.Count + ")");
                }
            }
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
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            // get fail2ban network address for given IP and prefix
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

            // fix log event that came from future(?!), _we_ have correct time!
            long now = DateTime.Now.Ticks;
            long logtime = evtlog.Timestamp;

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
                            + " from " + evtlog.Hostname);
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
                        case HistoryType.FIXED: fail = new FailFixed(findtime * TimeSpan.TicksPerSecond, history_fixed_count); break;
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

                Log.Info("Fail2ban[" + Name + "]: reached treshold "
                    + treshold.Name + " (" + treshold.MaxRetry + "&"
                    + failcnt + ") for " + addr + "/" + prefix);

                if (string.IsNullOrEmpty(treshold.Action))
                    continue;

                evtlog.SetProcData("Fail2ban.module", Name);
                evtlog.SetProcData("Fail2ban.address", addr);
                evtlog.SetProcData("Fail2ban.prefix", prefix);
                evtlog.SetProcData("Fail2ban.bantime", treshold.Bantime);
                evtlog.SetProcData("Fail2ban.treshold", treshold.Name);
                //evtlog.SetProcData("Fail2ban", Name);
                //evtlog.SetProcData(Name + ".address", addr);
                //evtlog.SetProcData(Name + ".prefix", prefix);
                //evtlog.SetProcData(Name + ".failcnt", failcnt);
                //evtlog.SetProcData(Name + ".treshold", treshold.Name);
                //evtlog.SetProcData(Name + "." + treshold.Name + ".MaxRetry", treshold.MaxRetry);
                //evtlog.SetProcData(Name + "." + treshold.Name + ".Action", treshold.Action);

                // Add to "action" queue
                Produce(new EventEntry(evtlog), treshold.Action);
            }

            return goto_next;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            output.WriteLine("config findtime: " + findtime);
            output.WriteLine("config ipv4_prefix: " + ipv4_prefix);
            output.WriteLine("config ipv6_prefix: " + ipv6_prefix);
            output.WriteLine("config cleanup: " + cleanup);
            output.WriteLine("config history: " + history);
            output.WriteLine("config history_fixed_count: " + history_fixed_count);
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
