#region Imports
using F2B.inputs;
using F2B.processors;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
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
        long Timestamp { get; }
        string Hostname { get; }
        IPAddress Address { get; }
        int Port { get; }
        string Username { get; }
        string Domain { get; }
        LoginStatus Status { get; }
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
        public long Timestamp { get; set; }
        public string Hostname { get; set; }
        public IPAddress Address { get; set; }
        public int Port { get; set; }
        public string Username { get; set; }
        public string Domain { get; set; }
        public LoginStatus Status { get; set; }
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
        public EventEntry(long timestamp, string hostname,
            IPAddress address, int port, string username, string domain,
            LoginStatus status, BaseInput input, object ldata)
        {
            Id = Interlocked.Increment(ref _counter);

            Timestamp = timestamp;
            Hostname = hostname;
            Address = address;
            Port = port;
            Username = username;
            Domain = domain;
            Status = status;
            Input = input;
            LogData = ldata;

            _procData = new Dictionary<string, object>();
        }

        // copy constructor with individual ProcData
        public EventEntry(EventEntry evt)
        {
            Id = evt.Id;

            Timestamp = evt.Timestamp;
            Hostname = evt.Hostname;
            Address = evt.Address;
            Port = evt.Port;
            Username = evt.Username;
            Domain = evt.Domain;
            Status = evt.Status;
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


    public class EventQueue
    {
        #region Properties
        #endregion

        #region Fields
        private volatile bool started;
        private Thread thread;
        private CancellationTokenSource cancel;
        private BlockingCollection<Tuple<EventEntry, string>> queue;
        private Dictionary<string, BaseProcessor> processors;
        private int limit;
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
            nconsumers = queuecfg.Consumers.Value;
            dropped = 0;
            max_errs = 5;

            cancel = new CancellationTokenSource();
            queue = new BlockingCollection<Tuple<EventEntry, string>>();
            processors = procs;
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
                // this lambda function doesn't work, it is probably evaluated
                // during thread start and "i" can contain different value?!?
                //thread = new Thread(() => Consume(i));
                thread = new Thread(Consume);
                thread.IsBackground = true;
                thread.Start(new IntPtr(i));
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
        }

        public void Produce(EventEntry item, string processor = null,  bool ignoreQueueSizeLimit = false)
        {
            if (!ignoreQueueSizeLimit && queue.Count >= limit)
            {
                // log new dropped events every minute
                long currtime = DateTime.Now.Ticks;
                if (lasttime % (60 * 10 * 1000 * 1000) != currtime % (60 * 10 * 1000 * 1000))
                {
                    dropped++;
                    lasttime = currtime;
                    Log.Warn("Drop event because of full queue (limit: "
                        + limit + ", dropped: " + dropped + ")");
                }

                return;
            }
            queue.Add(new Tuple<EventEntry, string>(item, processor));
        }

        private void Consume(object tnumber)
        {
            Log.Info("Log event consumption (thread " + tnumber + "): start");

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
                logpfx = string.Format("Consuming({0}/{1}): ", tnumber, tnevts);

                try
                {
                    Tuple<EventEntry, string> entry = queue.Take(cancel.Token);
                    evtlog = entry.Item1;
                    procName = entry.Item2;
                }
                catch (OperationCanceledException)
                {
                    Log.Info(logpfx + "Log event consumption canceled (started=" + started + ")");
                    continue;
                }

                // Service.Consume(EventEntry, procName, thread);
                if (evtlog == null)
                {
#if DEBUG
                    Log.Info(logpfx + "Dump processors debug info");
                    string debugFile = @"c:\f2b.debug";
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
#endif

                    continue;
                }

                logpfx = string.Format("Consuming({0}/{1}) event[{2}@{3}]: ",
                    tnumber, tnevts, evtlog.Id, evtlog.Input.Name);
                Log.Info(logpfx + evtlog.Address + ", " + evtlog.Username);

                BaseProcessor proc = null;
                if (string.IsNullOrEmpty(procName))
                {
                    procName = firstProcName;
                }

                while (true)
                {
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
                    catch (Exception ex)
                    {
                        // use processor error configuration
                        procName = proc.goto_error;

                        errcnt++;
                        if (errcnt >= max_errs)
                        {
                            // reset exception counter (to log another group of exceptions)
                            long currtime = DateTime.Now.Ticks;
                            if (errtime + 60 * (10 * 1000 * 1000) < currtime)
                            {
                                errcnt = 0;
                                errtime = currtime;
                            }
                        }

                        // log only limited number of execptions
                        if (errcnt < max_errs)
                        {
                            Log.Error(logpfx + " exception(" + errtime
                                + ","+ errcnt + "): " + ex.ToString());
                        }
                    }
                }
            }

            Log.Info("Log event consumption (thread " + tnumber + "): finished");
        }
        #endregion
    }
}
