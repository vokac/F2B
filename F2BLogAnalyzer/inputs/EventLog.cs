#region Imports
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;

#endregion

namespace F2B.inputs
{
    public class EventLogInput : BaseInput
    {
        #region Fields
        private IDictionary<string, Tuple<int, int>> evtmap;
        private EventLogPropertySelector evtsel;
        private IList<Regex> evtregex;
        private EventLogWatcher watcher;
        private object eventLock = new object();
        #endregion

        #region Constructors
        public EventLogInput(InputElement input, SelectorElement selector, EventQueue equeue)
            : base(input, selector, equeue)
        {
            // Event log query with suppressed events logged by this service
            StringBuilder qstr = new StringBuilder();
            qstr.Append("<QueryList>");
            qstr.Append("<Query>");
            qstr.Append(selector.Query.Value);
            qstr.Append("<Suppress Path=\"Application\">*[System/Provider/@Name=\"F2B\"]</Suppress>");
            qstr.Append("</Query>");
            qstr.Append("</QueryList>");

            EventLogSession session = null;
            if (input.Server != string.Empty)
            {
                SecureString pw = new SecureString();
                Array.ForEach(input.Password.ToCharArray(), pw.AppendChar);
                session = new EventLogSession(input.Server, input.Domain,
                                              input.Username, pw,
                                              SessionAuthentication.Default);
                pw.Dispose();
            }

            EventLogQuery query = new EventLogQuery(null, PathType.LogName, qstr.ToString());
            if (session != null)
            {
                query.Session = session;
            }

            // create event watcher (must be enable later)
            watcher = new EventLogWatcher(query);
            watcher.EventRecordWritten +=
                new EventHandler<EventRecordWrittenEventArgs>(
                    (s, a) => EventRead(s, a));

            // event data parsers (e.g. XPath + regex to extract event data)
            // (it is important to preserve order - it is later used as array index)
            List<Tuple<string, EventDataElement>> tmp = new List<Tuple<string, EventDataElement>>();
            tmp.Add(new Tuple<string,EventDataElement>("address", selector.Address));
            tmp.Add(new Tuple<string,EventDataElement>("port", selector.Port));
            tmp.Add(new Tuple<string,EventDataElement>("username", selector.Username));
            tmp.Add(new Tuple<string,EventDataElement>("domain", selector.Domain));

            evtmap = new Dictionary<string, Tuple<int, int>>();
            evtregex = new List<Regex>();
            List<string> xPathRefs = new List<string>();

            for (int i = 0; i < tmp.Count; i++)
            {
                string evtdescr = tmp[i].Item1;
                EventDataElement evtdata = tmp[i].Item2;

                if (evtdata == null || string.IsNullOrEmpty(evtdata.XPath))
                {
                    if (evtdescr == "address")
                    {
                        throw new ArgumentException("No address in " + Name + " configuration");
                    }

                    evtmap[evtdescr] = new Tuple<int, int>(i, -1);

                    continue;
                }

                Regex regex = null;
                if (!string.IsNullOrWhiteSpace(evtdata.Value))
                {
                    string evtstr = evtdata.Value.Trim();
                    try
                    {
                        regex = new Regex(evtstr, RegexOptions.IgnoreCase | RegexOptions.Singleline);
                    }
                    catch (ArgumentException ex)
                    {
                        Log.Error("Invalid " + Name + " " + evtdescr + " regex: "
                            + evtstr + " (" + ex.Message + ")");
                        throw;
                    }
                }

                evtregex.Add(regex);
                if (xPathRefs.Contains(evtdata.XPath))
                {
                    int index = xPathRefs.IndexOf(evtdata.XPath);
                    evtmap[evtdescr] = new Tuple<int, int>(i, index);
                }
                else
                {
                    xPathRefs.Add(evtdata.XPath);
                    evtmap[evtdescr] = new Tuple<int, int>(i, xPathRefs.Count - 1);
                }
            }

            Debug.Assert(tmp.Count == evtmap.Count,
                "Invalid index map size (tmp[" + tmp.Count
                + "] != map[" + evtmap.Count + "]).");

            evtsel = new EventLogPropertySelector(xPathRefs);
        }
        #endregion

        #region Methods
        public override void Start()
        {
            Log.Info("Starting " + InputName + "/" + SelectorName);
            try
            {
                watcher.Enabled = true;
            }
            catch (EventLogException ex)
            {
                Log.Error("Invalid input[" + InputName + "]/selector[" + SelectorName
                    + "] event query: " + ex.Message);
                throw;
            }
            catch (UnauthorizedAccessException ex)
            {
                Log.Error("Invalid input[" + InputName + "]/selector[" + SelectorName
                    + "] event query (insufficient rights to subscribe eventlog): "
                    + ex.Message);
                throw;
            }
        }

        public override void Stop()
        {
            Log.Info("Stoping " + InputName + "/" + SelectorName);

            // Stop listening to events
            watcher.Enabled = false;
        }

        private string GetLogRecordData(IList<object> ldata, IList<Regex> lregex, string etype)
        {
            Debug.Assert(evtmap.ContainsKey(etype), "Trying to use missing data " + etype);

            Tuple<int, int> idxs = evtmap[etype];
            int idxregexp = idxs.Item1;
            int idxxpath = idxs.Item2;

            if (idxxpath < 0)
            {
                return null;
            }

            object edata = ldata[idxxpath];
            Regex eregex = lregex[idxregexp];

            return GetXPathData(edata, eregex, etype);
        }
            
        private string GetXPathData(object edata, Regex eregex, string etype)
        {
            if (edata == null)
            {
                return null;
            }

            if (edata.GetType().IsArray)
            {
                foreach (string item in (object[])edata)
                {
                    string ret = GetXPathData(item, eregex, etype);
                    if (ret != null)
                    {
                        return ret;
                    }
                }

                return null;
            }

            // with no regex we return all element data
            if (eregex == null)
            {
                return (string)edata;
            }

            // try to match regexp and parse required data
            Match m = eregex.Match((string)edata);
            if (!m.Success)
            {
                //Log.Info("Received EventLog message from " + InputName
                //    + "/" + SelectorName + ", regex \"" + eregex
                //    + "\" doesn't match data: " + edata);
                return null;
            }

            Group eregexGroup = m.Groups[etype];
            if (eregexGroup == null || !eregexGroup.Success || string.IsNullOrWhiteSpace(eregexGroup.Value))
            {
                //Log.Info("Received EventLog message from " + InputName
                //    + "/" + SelectorName + ", " + etype + " regex \"" + eregex
                //    + "\" select empty data: " + edata);
                return null;
            }

            return eregexGroup.Value;
        }

        /// <summary>
        /// Callback method that gets executed when an event is
        /// reported to the subscription.
        /// </summary>
        private void EventRead(object obj,
            EventRecordWrittenEventArgs arg)
        {
            EventLogWatcher watcher = obj as EventLogWatcher;
            EventLogRecord evtlog = (EventLogRecord)arg.EventRecord;
            EventLogException evtex = (EventLogException)arg.EventException;

            if (evtlog == null)
            {
                if (evtex == null)
                {
                    Log.Error("No event log info!?");
                }
                else
                {
                    Log.Error("No event log info, received exception: " + arg.EventException.Message);
                }

                return;
            }

            long recordId = 0;
            long timestamp = 0;
            string hostname = null;
            IList<object> evtdata = null;

            try
            {
                // without this synchronization we sometimes get corrupted evtlog
                // data with invalid handle (EventLogException)
                lock (eventLock)
                {
                    timestamp = evtlog.TimeCreated.Value.Ticks;
                    hostname = evtlog.MachineName;
                    recordId = evtlog.RecordId.GetValueOrDefault(0);
                    evtdata = evtlog.GetPropertyValues(evtsel);
                }
            }
            catch (EventLogException ex)
            {
                Log.Error("Unable to access log info: " + ex.Message);
                return;
            }
            catch (Exception ex)
            {
                Log.Error("Unable to access log info: " + ex.Message);
                return;
            }

            if (Log.Level == EventLogEntryType.Information)
            {
                // debug info
                Log.Info("EventLog[" + recordId + "@" + Name + "]: new log event received");

                // more debug info
                for (int i = 0; i < evtdata.Count; i++)
                {
                    if (evtdata[i] != null)
                    {
                        if (evtdata[i].GetType().IsArray)
                        {
                            foreach (string item in (object[])evtdata[i])
                            {
                                Log.Info("EventLog[" + recordId + "@" + Name + "][" + i + "](" + evtdata[i].GetType() + "):" + item.ToString());
                            }
                        }
                        else
                        {
                            Log.Info("EventLog[" + recordId + "@" + Name + "][" + i + "](" + evtdata[i].GetType() + "):" + evtdata[i].ToString());
                        }
                    }
                    else
                    {
                        Log.Info("EventLog[" + recordId + "@" + Name + "][" + i + "]: NULL!!!");
                    }
                }
            }

            string strAddress = GetLogRecordData(evtdata, evtregex, "address");
            string strPort = GetLogRecordData(evtdata, evtregex, "port");
            string strUsername = GetLogRecordData(evtdata, evtregex, "username");
            string strDomain = GetLogRecordData(evtdata, evtregex, "domain");

            if (strAddress == null)
            {
                Log.Info("EventLog[" + recordId + "@" + Name + "] unable to get address");
                return;
            }

            IPAddress address = null;
            try
            {
                address = IPAddress.Parse(strAddress.Trim()).MapToIPv6();
            }
            catch (FormatException ex)
            {
                Log.Info("EventLog[" + recordId + "@" + Name + "] invalid address"
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

            EventEntry evt = new EventEntry(timestamp, hostname,
                address, port, strUsername, strDomain, Status, this, arg);

            Log.Info("EventLog[" + recordId + "->" + evt.Id + "@"
                + Name + "] queued message " + strUsername + "@" + address
                + ":" + port + " from " + hostname + " status " + Status);

            equeue.Produce(evt, Processor);
        }
        #endregion
    }
}
