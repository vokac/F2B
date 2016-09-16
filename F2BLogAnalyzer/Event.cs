#region Imports
using F2B.inputs;
using F2B.processors;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Threading;
using System.Timers;
#endregion

namespace F2B
{
    public enum LoginStatus
    {
        UNKNOWN,
        SUCCESS,
        FAILURE,
    }


    public interface IEventEntry
    {
        long Id { get; }
        DateTime Created { get; }
        string Hostname { get; }
        IPAddress Address { get; }
        int Port { get; }
        string Username { get; }
        string Domain { get; }
        LoginStatus Login { get; }
        BaseInput Input { get; }
        object LogData { get; }
        IReadOnlyDictionary<string, object> ProcData { get; }
        bool HasProcData(string key);
        T GetProcData<T>(string key, T def);
        void SetProcData(string key, object val);
    }


    public class EventEntry : IEventEntry
    {
        #region Properties
        public long Id { get; private set; }
        public DateTime Created { get; set; }
        public string Hostname { get; set; }
        public IPAddress Address { get; set; }
        public int Port { get; set; }
        public string Username { get; set; }
        public string Domain { get; set; }
        public LoginStatus Login { get; set; }
        public BaseInput Input { get; set; }
        public object LogData { get; set; }
        public IReadOnlyDictionary<string, object> ProcData {
            get {
                return (IReadOnlyDictionary<string, object>) _procData;
            }
        }
        #endregion

        #region Fields
        private static long _counter = 0;
        private IDictionary<string, object> _procData;
        #endregion

        #region Constructors
        public EventEntry(DateTime created, string hostname,
            IPAddress address, int port, string username, string domain,
            LoginStatus login, BaseInput input, object ldata)
        {
            Id = Interlocked.Increment(ref _counter);

            Created = created;
            Hostname = hostname;
            Address = address;
            Port = port;
            Username = username;
            Domain = domain;
            Login = login;
            Input = input;
            LogData = ldata;

            _procData = new Dictionary<string, object>();
        }

        // copy constructor with individual ProcData
        public EventEntry(EventEntry evt)
        {
            Id = evt.Id;

            Created = evt.Created;
            Hostname = evt.Hostname;
            Address = evt.Address;
            Port = evt.Port;
            Username = evt.Username;
            Domain = evt.Domain;
            Login = evt.Login;
            Input = evt.Input;
            LogData = evt.LogData;

            _procData = new Dictionary<string, object>(evt.ProcData.Count);
            foreach (var kv in evt.ProcData)
            {
                _procData[kv.Key] = kv.Value;
            }
        }
        #endregion

        #region Methods
        public bool HasProcData(string key)
        {
            return _procData.ContainsKey(key);
        }

        public T GetProcData<T>(string key, T def = default(T))
        {
            if (!_procData.ContainsKey(key))
                return def;

            return (T) _procData[key];
        }

        public void SetProcData(string key, object val)
        {
            _procData[key] = val;
        }
        #endregion
    }


    class ProcPerformance
    {
        public int count;
        public double min;
        public double max;
        public double sum;

        public ProcPerformance()
        {
            count = 0;
            min = int.MaxValue;
            max = 0;
            sum = 0;
        }

        override public string ToString()
        {
            return string.Format("ProcPerformance({0:0.00}/{1}={2:0.00}ms,{3:0.00}ms,{4:0.00}ms)", sum, count, sum / count, min, max);
        }
    }

    class EventQueueThread
    {
        private int number;
        private Thread thread;
        private bool active;
        private string last;
        private DateTime startProc;
        private DateTime startChain;
        private IDictionary<string, ProcPerformance> perf;

        public int Number { get { return number; } }
        public bool Active { get { return active; } }
        public bool AbortAllowed { get; set; }
        public string Name { get { return last; } }
        public double ProcTime { get { return active ? DateTime.Now.Subtract(startProc).TotalMilliseconds : 0; } }
        public double ChainTime { get { return active ? DateTime.Now.Subtract(startChain).TotalMilliseconds : 0; } }

        public EventQueueThread(ParameterizedThreadStart start, int number)
        {
            this.number = number;
            active = false;
            last = null;
            perf = new Dictionary<string, ProcPerformance>();

            AbortAllowed = false;

            thread = new Thread(start);
            thread.IsBackground = true;
            thread.Start(this);
        }

        public void Abort()
        {
            if (thread.IsAlive && AbortAllowed)
            {
                Log.Info("EventQueueThread[" + number + "].Abort()");
                thread.Abort();
            }
        }

        public void Finish()
        {
            if (thread.IsAlive && AbortAllowed)
            {
                Log.Info("EventQueueThread[" + number + "].Abort()");
                thread.Abort();
            }

            Log.Info("EventQueueThread[" + number + "].Join()");
            thread.Join();
        }

        public void Reset()
        {
            AbortAllowed = false;

            active = false;
            last = null;
        }

        public void Process(string name)
        {
            DateTime curr = DateTime.Now;

            if (active && last != null)
            {
                ProcPerformance p;
                if (!perf.TryGetValue(last, out p))
                {
                    p = new ProcPerformance();
                    perf[last] = p;
                }

                double diff = curr.Subtract(startProc).TotalMilliseconds;
                p.count++;
                p.sum += diff;
                if (p.min > diff) p.min = diff;
                if (p.max < diff) p.max = diff;
            }

            if (name != null)
            {
                if (!active)
                {
                    active = true;
                    startChain = curr;
                }
                startProc = curr;
                last = name;
            }
            else
            {
                Reset();
            }
            //timer.Enabled = true;
        }

        public ProcPerformance Performance(string name)
        {
            ProcPerformance p;
            if (!perf.TryGetValue(name, out p))
            {
                return null;
            }

            return p;
        }
    }
    public class EventQueue
    {
        public enum Priority { Low, Medium, High };

        #region Properties
        #endregion

        #region Fields
        private volatile bool started;
        private CancellationTokenSource cancel;
        private BlockingCollection<Tuple<EventEntry, string>> queueLow;
        private BlockingCollection<Tuple<EventEntry, string>> queueMedium;
        private BlockingCollection<Tuple<EventEntry, string>> queueHigh;
        private BlockingCollection<Tuple<EventEntry, string>>[] queue;
        private Dictionary<string, BaseProcessor> processors;
        private EventQueueThread[] ethreads;
        private System.Timers.Timer abort;
        private int limit;
        private int maxtime;
        private int dropped;
        private int max_errs;
        private long lasttime;
        private int nconsumers;

        private object thisInst = new object();
        #endregion

        #region Constrictors
        public EventQueue(Dictionary<string, BaseProcessor> procs)
        {
            F2BSection config = F2B.Config.Instance;
            QueueElement queuecfg = config.Queue;

            limit = queuecfg.MaxSize.Value;
            maxtime = queuecfg.MaxTime.Value;
            nconsumers = queuecfg.Consumers.Value;
            dropped = 0;
            max_errs = 5;

            cancel = new CancellationTokenSource();
            queueLow = new BlockingCollection<Tuple<EventEntry, string>>();
            queueMedium = new BlockingCollection<Tuple<EventEntry, string>>();
            queueHigh = new BlockingCollection<Tuple<EventEntry, string>>();
            queue = new[] { queueHigh, queueMedium, queueLow };
            processors = procs;

            ethreads = new EventQueueThread[nconsumers];
            abort = null;
            if (maxtime > 0)
            {
                abort = new System.Timers.Timer(maxtime * 1000 / 10);
                abort.Elapsed += Abort;
            }
        }
        #endregion

        #region Methods
        public void Start() {
            Log.Info("Entry queue start: started=" + started);
            if (started)
            {
                return;
            }

            started = true; // this must be set before thread.Start

            Log.Info("Entry queue create " + nconsumers + " consumer threads");
            for (int i = 0; i < nconsumers; i++)
            {
                ethreads[i] = new EventQueueThread(Consume, i);
            }

            if (abort != null)
            {
                abort.Enabled = true;
            }
        }

        public void Stop()
        {
            Log.Info("Entry queue stop: started=" + started);
            if (!started)
            {
                return;
            }

            started = false; // this must be set before cancel.Cancel
            cancel.Cancel(false);

            Log.Info("Entry queue join " + nconsumers + " consumer threads");
            for (int i = 0; i < nconsumers; i++)
            {
                if (ethreads[i] == null) continue;
                ethreads[i].Finish();
            }

#if DEBUG
            IDictionary<string, ProcPerformance> summary = new Dictionary<string, ProcPerformance>();
            foreach (string procName in processors.Keys)
            {
                summary[procName] = new ProcPerformance();
            }

            for (int i = 0; i < nconsumers; i++)
            {
                if (ethreads[i] == null) continue;
                foreach (string procName in processors.Keys)
                {
                    ProcPerformance p = ethreads[i].Performance(procName);
                    if (p == null) continue;
                    summary[procName].count += p.count;
                    summary[procName].sum += p.sum;
                    if (summary[procName].min > p.min) summary[procName].min = p.min;
                    if (summary[procName].max < p.max) summary[procName].max = p.max;
                }
            }

            foreach (string procName in processors.Keys)
            {
                ProcPerformance p = summary[procName];
                Log.Info(string.Format("Performance[{0}]: avg({1:0.00}/{2}={3:0.00}ms), min({4:0.00}ms), max({5:0.00}ms)", procName, p.sum, p.count, p.sum / p.count, p.min, p.max));
            }
#endif

            for (int i = 0; i < nconsumers; i++)
            {
                if (ethreads[i] == null) continue;
                ethreads[i] = null;
            }

            if (abort != null)
            {
                abort.Enabled = false;
            }
        }

        private void Abort(object sender, ElapsedEventArgs e)
        {
            if (abort == null)
            {
                return;
            }

            if (!abort.Enabled)
            {
                // this should prevent race condition, because elapsed
                // event is queued for execution on a thread poole thread
                return;
            }

            int active = 0;
            int aborted = 0;
            for (int i = 0; i < nconsumers; i++)
            {
                EventQueueThread ethread = ethreads[i];
                if (ethread == null) continue;
                if (!ethread.Active) continue;
                active++;
                if (ethread.ChainTime < maxtime * 1000) continue;
                ethread.Abort();
                aborted++;
            }

            if (aborted > 0)
            {
                Log.Info("Aborted " + aborted + " threads, active threads "
                    + active + " (total threads " + nconsumers
                    + "), event queue size queue High(" + queueHigh.Count
                    + ")/Medium(" + queueMedium.Count + ")/Low("
                    + queueLow.Count + ")");
            }
        }

        public void Produce(EventEntry item, string processor = null, Priority priority = Priority.Low)
        {
            if (priority == Priority.Low && limit != 0 && queueLow.Count >= limit)
            {
                // log new dropped events every minute
                long currtime = DateTime.Now.Ticks;
                if (lasttime % (60 * TimeSpan.TicksPerSecond) != currtime % (60 * TimeSpan.TicksPerSecond))
                {
                    dropped++;
                    lasttime = currtime;
                    Log.Warn("Drop event because of full queue (limit: "
                        + limit + ", dropped: " + dropped + ")");
                }

                return;
            }
            switch (priority)
            {
                case Priority.Low:
                    queueLow.Add(new Tuple<EventEntry, string>(item, processor));
                    break;
                case Priority.Medium:
                    queueMedium.Add(new Tuple<EventEntry, string>(item, processor));
                    break;
                case Priority.High:
                    queueHigh.Add(new Tuple<EventEntry, string>(item, processor));
                    break;
                default:
                    Log.Error("Unsupported queue priority " + priority);
                    break;
            }
        }

        private void Consume(object data)
        {
            EventQueueThread ethread = (EventQueueThread)data;
            Log.Info("Log event consumption (thread " + ethread.Number + "): start");

            EventEntry evtlog;
            string procName;
            string logpfx;
            long tnevts = 0;
            long errcnt = 0;
            long errtime = DateTime.Now.Ticks;

            string firstProcName = null;
            F2BSection config = F2B.Config.Instance;

            if (config.Processors.Count > 0)
            {
                firstProcName = config.Processors[0].Name;
            }

            while (started)
            {
                evtlog = null;
                procName = null;
                tnevts++;
                logpfx = string.Format("Consuming({0}/{1}): ", ethread.Number, tnevts);

                try
                {
                    Tuple<EventEntry, string> entry;
#if DEBUG
                    if (Log.Level == EventLogEntryType.Information)
                    {
                        Log.Info(logpfx + "queue High(" + queueHigh.Count + ")/Medium(" + queueMedium.Count + ")/Low(" + queueLow.Count + ")");
                    }
                    int queueIndex =
#endif
                    BlockingCollection<Tuple<EventEntry, string>>.TakeFromAny(queue, out entry, cancel.Token);
#if DEBUG
                    if (Log.Level == EventLogEntryType.Information)
                    {
                        Log.Info(logpfx + "queue High(" + queueHigh.Count + ")/Medium(" + queueMedium.Count + ")/Low(" + queueLow.Count + "): queueIndex = " + queueIndex);
                    }
#endif
                    evtlog = entry.Item1;
                    procName = entry.Item2;
                }
                catch (OperationCanceledException)
                {
                    Log.Info(logpfx + "Log event consumption canceled (started=" + started + ")");
                    continue;
                }

#if DEBUG
                bool debug = evtlog == null;
                string debugFile = procName;

                if (!debug)
                {
                    // special event from 0.0.0.0 or :: with port 12345 is treated
                    // as requiest to dump F2B internal state that can be used for debug
                    if (evtlog.Port == 12345 && (evtlog.Address.Equals(IPAddress.Any.MapToIPv6()) || evtlog.Address.Equals(IPAddress.IPv6Any)))
                    {
                        debug = true;
                        debugFile = @"c:\F2B\dump.txt";
                        if (!string.IsNullOrEmpty(evtlog.Username))
                        {
                            debugFile = evtlog.Username;
                        }
                    }
                }

                if (debug)
                {
                    Log.Warn(logpfx + "Dump processors debug info");
                    Utils.DumpProcessInfo(EventLogEntryType.Warning);
                    StreamWriter output = null;
                    lock (thisInst)
                    {
                        try
                        {
                            output = new StreamWriter(new FileStream(debugFile, FileMode.Append));
                            output.WriteLine("======================================================================");
                            output.WriteLine("Timestamp: " + DateTime.Now + " (UTC " + DateTime.UtcNow.Ticks + ")");
                            foreach (BaseProcessor p in processors.Values)
                            {
                                output.WriteLine("========== " + p.GetType() + "[" + p.Name + "] processor ==========");
                                p.Debug(output);
                            }
                        }
                        catch (Exception ex)
                        {
                            Log.Error(logpfx + "Unable to dump debug info (" + debugFile + "): " + ex.ToString());
                        }
                        finally
                        {
                            if (output != null)
                            {
                                output.Close();
                            }
                        }
                    }

                    continue;
                }
#endif

                if (evtlog == null)
                {
                    // special event used for debugging
                    continue;
                }

                logpfx = string.Format("Consuming({0}/{1}) event[{2}@{3}]: ",
                    ethread.Number, tnevts, evtlog.Id, evtlog.Input.Name);
                Log.Info(logpfx + evtlog.Address + ", " + evtlog.Username);

                BaseProcessor proc = null;
                if (string.IsNullOrEmpty(procName))
                {
                    procName = firstProcName;
                }

                //ethread.Reset();
                while (true)
                {
                    ethread.Process(procName);

                    if (procName == null)
                    {
                        Log.Info(logpfx + "NULL processor terminated event processing");
                        break;
                    }

                    if (!processors.ContainsKey(procName))
                    {
                        Log.Info(logpfx + "processor \"" + procName + "\" not found");
                        break;
                    }

                    Log.Info(logpfx + "processor \"" + procName + "\" executed");
                    proc = processors[procName];

                    try
                    {
                        ethread.AbortAllowed = true;

                        if (nconsumers == 1 || typeof(IThreadSafeProcessor).IsAssignableFrom(proc.GetType()))
                        {
                            procName = proc.Execute(evtlog);
                        }
                        else
                        {
                            lock (proc)
                            {
                                procName = proc.Execute(evtlog);
                            }
                        }
                    }
                    catch (ThreadAbortException ex)
                    {
                        ethread.Reset();
                        Thread.ResetAbort();
                        Log.Warn(logpfx + "abort(" + proc.Name + ", "
                            + errtime + ", " + errcnt + "): " + ex.Message);
                        break;
                    }
                    catch (Exception ex)
                    {
                        // use processor error configuration
                        procName = proc.goto_error;

                        errcnt++;
                        if (errcnt >= max_errs)
                        {
                            // reset exception counter (to log another group of exceptions)
                            long currtime = DateTime.Now.Ticks;
                            if (errtime + 60 * TimeSpan.TicksPerSecond < currtime)
                            {
                                errcnt = 0;
                                errtime = currtime;
                            }
                        }

                        // log only limited number of execptions
                        if (errcnt < max_errs)
                        {
                            Log.Error(logpfx + "exception(" + proc.Name + ", "
                                + errtime + ", "+ errcnt + "): " + ex.ToString());
                        }
                    }
                    finally
                    {
                        ethread.AbortAllowed = false;
                    }

#if DEBUG
                    Log.Info(logpfx + "processor \"" + ethread.Name + "\" execution time: " + string.Format("{0:0.00}ms", ethread.ProcTime / 1000));
#endif
                }

#if DEBUG
                Log.Info(logpfx + "processor chain execution time: " + string.Format("{0:0.00}s", ethread.ChainTime / 1000));
#endif
                ethread.Reset();
            }

            Log.Info("Log event consumption (thread " + ethread.Number + "): finished");
        }
        #endregion
    }
}
