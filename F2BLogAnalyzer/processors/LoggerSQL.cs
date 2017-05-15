#region Imports
using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Data;
using System.Data.Odbc;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;

#endregion

namespace F2B.processors
{
    public class LoggerSQLProcessor : BaseProcessor
    {
        #region Fields
        private string odbc;
        private string table = null;
        private IList<Tuple<string, string>> columns;
        private string insert = null;
        private int timeout = 15;
        private OdbcConnection conn = null;
        private bool stop;
        private Object syncLock = new Object();
        private bool async = true;
        private int asyncMaxSize = 1000;
        private BlockingCollection<IList<Tuple<string, string>>> asyncQueue;
        private Thread asyncThread;
        private CancellationTokenSource asyncCanceled;
        #endregion

        #region Constructors
        public LoggerSQLProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            if (config.Options["odbc"] != null && !string.IsNullOrWhiteSpace(config.Options["odbc"].Value))
            {
                odbc = config.Options["odbc"].Value;
            }
            else
            {
                throw new InvalidDataException("required configuration option odbc missing or empty");
            }

            if (config.Options["insert"] != null && !string.IsNullOrWhiteSpace(config.Options["insert"].Value))
            {
                insert = config.Options["insert"].Value;
            }
            else if (config.Options["table"] != null && !string.IsNullOrWhiteSpace(config.Options["table"].Value))
            {
                table = config.Options["table"].Value;
            }
            else
            {
                throw new InvalidDataException("required configuration option table missing or empty");
            }

            columns = new List<Tuple<string, string>>();
            if (config.Options["columns"] != null && !string.IsNullOrWhiteSpace(config.Options["columns"].Value))
            {
                foreach (string column in config.Options["columns"].Value.Split(','))
                {
                    string template = "";

                    if (config.Options["column." + column] != null)
                    {
                        template = config.Options["column." + column].Value;
                    }
                    else
                    {
                        Log.Warn("missing required column template for column." + column);
                    }

                    columns.Add(new Tuple<string, string>(column, template));
                }

                if (insert == null)
                {
                    char[] vars = Enumerable.Repeat('?', columns.Count).ToArray();
                    insert = "INSERT INTO " + table + " (" + config.Options["columns"].Value
                        + ") VALUES (" + string.Join(",", vars) + ")";
                }
            }
            else
            {
                throw new InvalidDataException("required configuration option columns missing or empty");
            }

            if (config.Options["timeout"] != null)
            {
                timeout = int.Parse(config.Options["timeout"].Value);
            }

            if (config.Options["async"] != null)
            {
                async = bool.Parse(config.Options["async"].Value);
            }
            if (config.Options["async_max_queued"] != null)
            {
                asyncMaxSize = int.Parse(config.Options["async_max_queued"].Value);
            }
        }
        #endregion

        private void AsyncSQL()
        {
            while (!asyncQueue.IsCompleted)
            {
                try
                {
                    IList<Tuple<string, string>> colvals;
                    if (asyncQueue.TryTake(out colvals, -1, asyncCanceled.Token))
                    {
                        Save(colvals);
                    }
                }
                catch (OperationCanceledException ex)
                {
                    Log.Info("Canceled async take (queue size: " + asyncQueue.Count + "): " + ex.Message);
                    break;
                }
                catch (OdbcException ex)
                {
                    Log.Error("ODBC Exception in async thread: " + ex.Message);

                    if (Log.Level == EventLogEntryType.Information)
                    {
                        for (int i=0; i < ex.Errors.Count; i++)
                        {
                            OdbcError err = ex.Errors[i];
                            Log.Info("ODBC Exception details #" + i
                                + ": message='" + err.Message
                                + "', native='" + err.NativeError.ToString()
                                + "', source='" + err.Source
                                + "', SQL='" + err.SQLState);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log.Error("Exception(" + ex.GetType().Name + ") in async thread: " + ex.Message);
                }
            }
        }

        private bool Open(int retry = -1)
        {
            int cnt = 0;

            while (!stop && retry != 0)
            {
                if (cnt > 1)
                {
                    // don't retry connection immediately after last two failures
                    Thread.Sleep(Math.Min(cnt*1000, 10000));
                }

                try
                {
                    if (conn.State != ConnectionState.Open)
                    {
                        Log.Info("Opening database connection (retry: " + cnt + ")");
                        // Open can hangs for ~ 140s eventhought connection timeout
                        // is just 15s and Abort() even throws exception ... I'm not
                        // sure how to deal with this situation - just let the thread
                        // running without clean exit...
                        conn.Open();
                        //conn.OpenAsync(asyncCanceled.Token);
                     }

                     return true;
                }
                catch (OdbcException ex)
                {
                    Log.Error("ODBC Exception (unable to connect): " + ex.Message);

                    if (retry > 0) retry--;
                }

                cnt++;
            }

            return false;
        }

        private void Save(IList<Tuple<string, string>> colvals, int retry = -1)
        {
            bool opened = false;

            while (true)
            {
                if (conn.State != ConnectionState.Open)
                {
                    if (!Open(retry))
                    {
                        throw new Exception("unable to open database connection");
                    }

                    opened = true;
                }

                try {
                    using (OdbcCommand cmd = new OdbcCommand(insert, conn))
                    {
                        foreach (var item in colvals)
                        {
                            cmd.Parameters.Add(new OdbcParameter(item.Item1, item.Item2));
                        }

                        cmd.ExecuteNonQuery();
                    }

                    // we sucessfully stored data
                    break;
                }
                catch (ArgumentException ex)
                {
                    // invalid ODBC parameter - no reason to retry
                    throw new Exception("ODBC Parameter problem: " + ex.Message);
                }
                catch (InvalidOperationException ex)
                {
                    // may be connection was closed/bad?! if we did not made attempt
                    // to reconnect earlier than close connection and retry once more
                    if (opened)
                    {
                        throw new Exception("ODBC Exception (invalid operation): " + ex.Message);
                    }

                    Log.Warn("ODBC Exception (invalid operation): " + ex.Message + " (retry)");
                    conn.Close();
                }
            }
        }

        #region Override
        public override void Start()
        {
            stop = false;

            conn = new OdbcConnection(odbc);
            conn.ConnectionTimeout = timeout;

            if (async)
            {
                asyncQueue = new BlockingCollection<IList<Tuple<string, string>>>(asyncMaxSize);
                asyncCanceled = new CancellationTokenSource();
                asyncThread = new Thread(new ThreadStart(AsyncSQL));
                asyncThread.IsBackground = true; // NOTE: necessary for fast shutdown in case conn.Open hangs
                asyncThread.Start();
            }
        }

        public override void Stop()
        {
            stop = true;

            if (async)
            {
                Log.Info("Stop SQL async thread");
                asyncQueue.CompleteAdding();
                asyncCanceled.Cancel();
                asyncThread.Join(1000); // abort thread after 1s
                // skip Abort because it hangs and shutdown can take ~ 140s
                //if (asyncThread.IsAlive)
                //{
                //    Log.Info("Aborting SQL async thread");
                //    // this call hangs on unfinished conn.Open
                //    asyncThread.Abort();
                //}
            }

            lock (syncLock)
            {
                if (conn != null && conn.State != ConnectionState.Closed)
                {
                    conn.Close();
                }
            }
        }

        public override string Execute(EventEntry evtlog)
        {
            ProcessorEventStringTemplate tpl = new ProcessorEventStringTemplate(evtlog);

            IList<Tuple<string, string>> colvals = new List<Tuple<string, string>>(columns.Count);
            foreach (var item in columns)
            {
                colvals.Add(Tuple.Create(item.Item1, tpl.Apply(item.Item2)));
            }

            if (!async)
            {
                lock (syncLock)
                {
                    Save(colvals, 1);
                }
            }
            else
            {
                if (!asyncQueue.TryAdd(colvals))
                {
                    Log.Warn("unable to add new data to full queue (queue size: " + asyncQueue.Count + ")");
                    // we could store data into a SQL file that could be later inserted in DB
                }
            }

            return goto_next;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            output.WriteLine("config connection: " + odbc);
            output.WriteLine("config table: " + table);
            output.WriteLine("config insert: " + insert);
            foreach (var item in columns)
            {
                output.WriteLine("config column " + item.Item1 + ": " + item.Item2);
            }
            output.WriteLine("config async db connection: " + async);
            output.WriteLine("config async max queue size: " + asyncMaxSize);
        }
#endif
        #endregion
    }
}
