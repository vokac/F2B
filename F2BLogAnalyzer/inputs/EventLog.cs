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
        private class EventLogParserData
        {
            public string Id { get; }
            public string Type { get; }
            public string XPath { get; }
            public int Index { get; }
            public Regex Regex { get; }
            public EventLogParserData(string id, string type, string xpath, int index, string regexp)
            {
                Id = id;
                Type = type;
                XPath = xpath;
                Index = index;
                Regex = null;

                if (!string.IsNullOrWhiteSpace(regexp))
                {
                    Regex = new Regex(regexp, RegexOptions.Singleline);
                }
            }
        }

        #region Fields
        private EventLogPropertySelector evtsel;
        private IList<EventLogParserData> evtregexs;
        private IList<EventDataElement> evtdata_before;
        private IList<KeyValuePair<string, EventDataElement>> evtdata_match;
        private IList<EventDataElement> evtdata_after;
        private EventLogWatcher watcher;
        private object eventLock = new object();
        #endregion

        #region Constructors
        public EventLogInput(InputElement input, SelectorElement selector, EventQueue equeue)
            : base(input, selector, equeue)
        {
            Log.Info("input[" + InputName + "]/selector[" + SelectorName
                + "] creating EventLogInput");

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
            evtregexs = new List<EventLogParserData>();
            List<string> xPathRefs = new List<string>();

            foreach (RegexElement item in selector.Regexes)
            {
                if (string.IsNullOrEmpty(item.XPath))
                {
                    Log.Warn("Invalid input[" + InputName + "]/selector[" + SelectorName
                        + "] event regexp \"" + item.Id + "\" attribute xpath empty");

                    continue;
                }

                if (!xPathRefs.Contains(item.XPath))
                {
                    xPathRefs.Add(item.XPath);
                }

                try
                {
                    int index = xPathRefs.IndexOf(item.XPath);
                    EventLogParserData eli = new EventLogParserData(item.Id, item.Type, item.XPath, index, item.Value);
                    evtregexs.Add(eli);
                }
                catch (ArgumentException ex)
                {
                    Log.Error("Invalid input[" + InputName + "]/selector[" + SelectorName
                        + "] event regexp failed: " + ex.Message);

                    throw;
                }
            }

            evtsel = null;
            if (xPathRefs.Count > 0)
            {
                evtsel = new EventLogPropertySelector(xPathRefs);
            }

            // user defined event properties
            evtdata_before = new List<EventDataElement>();
            evtdata_match = new List<KeyValuePair<string, EventDataElement>>();
            evtdata_after = new List<EventDataElement>();
            foreach (EventDataElement item in selector.EventData)
            {
                if (item.Apply == "before")
                {
                    evtdata_before.Add(item);
                }
                else if (item.Apply == "after")
                {
                    evtdata_after.Add(item);
                }
                else if (item.Apply.StartsWith("match."))
                {
                    string key = item.Apply.Substring("match.".Length);
                    evtdata_match.Add(new KeyValuePair<string, EventDataElement>(key, item));
                }
                else
                {
                    Log.Warn("Invalid input[" + InputName + "]/selector[" + SelectorName
                        + "] event data \"" + item.Name + "\" attribute apply \""
                        + item.Apply + "\": ignoring this item");
                }
            }
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

        public static IEnumerable<Tuple<string, string>> GetXPathData(object data, Regex regex)
        {
            Log.Info("GetXPathData(" + data + ", " + regex + ")");

            if (data == null)
            {
                yield break;
            }

            // XPath matched array of XML elements
            if (data.GetType().IsArray)
            {
                foreach (string item in (object[])data)
                {
                    foreach (var ret in GetXPathData(item, regex))
                    {
                        yield return ret;
                    }
                }

                yield break;
            }

            // with no regex we return all element data
            if (regex == null)
            {
                Log.Info("A GetXPathData(" + data + ", " + regex + ")");
                yield return new Tuple<string, string>(null, (string)data);
            }
            else
            {
                Log.Info("B GetXPathData(" + data + ", " + regex + ")");
                // try to match regexp and parse required data
                Match m = regex.Match((string)data);
                if (!m.Success)
                {
                    //Log.Info("Received EventLog message from " + InputName
                    //    + "/" + SelectorName + ", regex \"" + eregex
                    //    + "\" doesn't match data: " + edata);
                    yield break;
                }

                foreach (int groupNumber in regex.GetGroupNumbers())
                {
                    Group regexGroup = m.Groups[groupNumber];

                    if (regexGroup == null)
                    {
                        continue;
                    }
                    if (!regexGroup.Success)
                    {
                        continue;
                    }
                    if (regex.GroupNameFromNumber(groupNumber) == groupNumber.ToString())
                    {
                        continue;
                    }

                    string groupName = regex.GroupNameFromNumber(groupNumber);
                    string groupValue = "";
                    if (regexGroup.Value != null)
                    {
                        groupValue = regexGroup.Value;
                    }

                    yield return new Tuple<string, string>(groupName, groupValue);
                }
            }
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

            int eventId;
            long recordId;
            long keywords;
            string machineName;
            DateTime created;
            string providerName;
            int processId;
            string logName;
            string logLevel;
            IList<object> evtdata = null;

            try
            {
                // without this synchronization we sometimes get corrupted evtlog
                // data with invalid handle (EventLogException)
                lock (eventLock)
                {
                    eventId = evtlog.Id;
                    recordId = evtlog.RecordId.GetValueOrDefault(0);
                    keywords = evtlog.Keywords.GetValueOrDefault(0);
                    machineName = evtlog.MachineName;
                    created = evtlog.TimeCreated.GetValueOrDefault(DateTime.Now);
                    providerName = evtlog.ProviderName;
                    processId = evtlog.ProcessId.GetValueOrDefault(0);
                    logName = evtlog.LogName;
                    logLevel = evtlog.LevelDisplayName;
                    // NOTE: may be just this line needs synchronization?
                    if (evtsel != null)
                    {
                        evtdata = evtlog.GetPropertyValues(evtsel);
                    }
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

            // just verbose debug info about received event
            if (Log.Level == EventLogEntryType.Information)
            {
                // debug info
                Log.Info("EventLog[" + recordId + "@" + Name + "]: new log event received");

                // more debug info
                for (int i = 0; evtdata != null && i < evtdata.Count; i++)
                {
                    EventLogParserData evtregex = evtregexs[i];
                    if (evtdata[i] != null)
                    {
                        if (evtdata[i].GetType().IsArray)
                        {
                            foreach (string item in (object[])evtdata[i])
                            {
                                Log.Info("EventLog[" + recordId + "@" + Name + "][" + evtregex.XPath + "](" + evtdata[i].GetType() + "):" + item.ToString());
                            }
                        }
                        else
                        {
                            Log.Info("EventLog[" + recordId + "@" + Name + "][" + evtregex.XPath + "](" + evtdata[i].GetType() + "):" + evtdata[i].ToString());
                        }
                    }
                    else
                    {
                        Log.Info("EventLog[" + recordId + "@" + Name + "][" + evtregex.XPath + "]: NULL!!!");
                    }
                }
            }

            EventEntry evt = new EventEntry(this, created, machineName, arg);

            foreach (EventDataElement item in evtdata_before)
            {
                if (item.Overwrite || !evt.HasProcData(item.Name))
                {
                    evt.SetProcData(item.Name, item.Value);
                }
            }

            // set basic event properties
            evt.SetProcData("Event.EventId", eventId.ToString());
            evt.SetProcData("Event.RecordId", recordId.ToString());
            evt.SetProcData("Event.Keywords", keywords.ToString());
            // machine name and time created already set in EventEntry constructor
            //evt.SetProcData("Event.MachineName", machineName);
            //evt.SetProcData("Event.TimeCreated", created.ToString());
            evt.SetProcData("Event.ProviderName", providerName);
            evt.SetProcData("Event.ProcessId", processId.ToString());
            evt.SetProcData("Event.LogName", logName);
            evt.SetProcData("Event.LogLevel", logLevel);

            IList<string> evtregexdata = new List<string>(); // ISet is not really better for small number of elements
            foreach (EventLogParserData evtregex in evtregexs)
            {
                foreach (Tuple<string, string> item in GetXPathData(evtdata[evtregex.Index], evtregex.Regex))
                {
                    string key = item.Item1 != null ? item.Item1 : evtregex.Id;
                    evt.SetProcData("Event." + key, item.Item2);
                    evtregexdata.Add(item.Item1 != null ? item.Item1 : evtregex.Id);
                }
            }

            foreach (KeyValuePair<string, EventDataElement> item in evtdata_match)
            {
                if (evtregexdata.Contains(item.Key))
                {
                    if (item.Value.Overwrite || !evt.HasProcData(item.Value.Name))
                    {
                        evt.SetProcData(item.Value.Name, item.Value.Value);
                    }
                }
            }

            foreach (EventDataElement item in evtdata_after)
            {
                if (item.Overwrite || !evt.HasProcData(item.Name))
                {
                    evt.SetProcData(item.Name, item.Value);
                }
            }
            // Event.EventData (NOTE: use EventData processor to parse event XML data)

            Log.Info("EventLog[" + recordId + "->" + evt.Id + "@"
                + Name + "] queued message from " + machineName);

#if DEBUG
            if (Log.Level == EventLogEntryType.Information)
            {
                Log.Info("EventLog[" + recordId + "->" + evt.Id + "@"
                    + Name + "] " + evt.ProcData.Count + " properties");
                foreach (var item in evt.ProcData)
                {
                    Log.Info("EventLog[" + recordId + "->" + evt.Id + "@"
                        + Name + "]: " + item.Key + " = " + item.Value);
                }
            }
#endif

            equeue.Produce(evt, Processor);
        }
        #endregion
    }
}
