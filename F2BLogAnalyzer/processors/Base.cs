#region Imports
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
#endregion

namespace F2B.processors
{
    // processor interface
    //interface IProcessor
    //{
    //    string name { get; }
    //    string cname { get; }
    //}

    // indicate that Execute method is implemented thread safe
    interface IThreadSafeProcessor
    {
    }

    public abstract class BaseProcessor
    {
        #region Properties
        public string Name { get; private set; }
        public string goto_next { get; private set; }
        public string goto_error { get; private set; }
        #endregion

        private Service Service;

        #region Constructors
        public BaseProcessor(ProcessorElement config, Service service)
        {
            Name = config.Name;
            goto_next = config.Goto.Next;
            goto_error = config.Goto.Error;
            Service = service;
        }
        #endregion

        #region Methods
        protected void Produce(EventEntry item, string processor = null)
        {
            Service.Produce(item, processor, true);
        }
        public abstract string Execute(EventEntry evtlog);
        public virtual void Start() { }
        public virtual void Stop() { }
#if DEBUG
        public virtual void Debug(StreamWriter output) { }
#endif
        #endregion
    }


    class ProcessorEventStringTemplate
    {
        private IDictionary<string, string> repl;

        public ProcessorEventStringTemplate(EventEntry evtlog)
        {
            repl = new Dictionary<string, string>(20 + evtlog.ProcData.Count);

            // Environment
            repl["Environment.Now"] = DateTime.Now.Ticks.ToString();
            repl["Environment.DateTime"] = DateTime.Now.ToString();
            repl["Environment.MachineName"] = System.Environment.MachineName;

            // F2B Event
            repl["Event.Id"] = evtlog.Id.ToString();
            repl["Event.Timestamp"] = evtlog.Created.Ticks.ToString();
            repl["Event.Hostname"] = (evtlog.Hostname != null ? evtlog.Hostname : "");
            repl["Event.Type"] = evtlog.Input.InputType;
            repl["Event.Input"] = evtlog.Input.InputName;
            repl["Event.Selector"] = evtlog.Input.SelectorName;
            repl["Event.Address"] = evtlog.Address.ToString();
            repl["Event.Port"] = evtlog.Port.ToString();
            repl["Event.Username"] = (evtlog.Username != null ? evtlog.Username : "");
            repl["Event.Domain"] = (evtlog.Domain != null ? evtlog.Domain : "");
            repl["Event.Status"] = evtlog.Status.ToString();
            // Event
            if (evtlog.LogData.GetType() == typeof(EventRecordWrittenEventArgs)
                || evtlog.LogData.GetType().IsSubclassOf(typeof(EventRecordWrittenEventArgs)))
            {
                EventRecordWrittenEventArgs evtarg = evtlog.LogData as EventRecordWrittenEventArgs;
                EventRecord evtrec = evtarg.EventRecord;
                repl["Event.EventId"] = evtrec.Id.ToString();
                repl["Event.RecordId"] = evtrec.RecordId.ToString();
                repl["Event.MachineName"] = evtrec.MachineName;
                repl["Event.TimeCreated"] = evtrec.TimeCreated.Value.ToString();
                repl["Event.ProviderName"] = evtrec.ProviderName;
                repl["Event.ProcessId"] = evtrec.ProcessId.ToString();
            }
            else
            {
                repl["Event.EventId"] = "0";
                repl["Event.RecordId"] = "0";
                repl["Event.MachineName"] = "";
                repl["Event.TimeCreated"] = "0";
                repl["Event.ProviderName"] = "";
                repl["Event.ProcessId"] = "";
            }

            // Processor
            foreach (var item in evtlog.ProcData)
            {
                if (item.Value == null) repl[item.Key] = "";
                else repl[item.Key] = item.Value.ToString();
            }
        }

        public string ExpandTemplateVariables(string str, string empty = null)
        {
            StringBuilder output = new StringBuilder();

            // parse template line by line (report syntax error
            // in case of unmatched variable parenthesis)
            int pos;
            int start, end, par;
            bool subvar;
            string key;
            foreach (string line in str.Replace(Environment.NewLine, "\n").Split('\n'))
            {
                pos = 0;
                while (true)
                {
                    // try to find beginning of variable definition "${"
                    start = pos;
                    while (start < line.Length - 1 && (line[start] != '$' || line[start + 1] != '{') && (start == 0 || (start > 0 && line[start - 1] != '\\'))) start++;
                    if (!(start < line.Length - 1))
                    {
                        output.Append(line.Substring(pos));
                        break;
                    }
                    output.Append(line.Substring(pos, start - pos));
                    pos = start;
                    start += 2;

                    // try to find end of variable definiton "}"
                    par = 0;
                    subvar = false;
                    end = start;
                    while (end < line.Length && (par > 0 || line[end] != '}'))
                    {
                        if (end < line.Length - 1 && line[end - 1] != '\\' && line[end] == '$' && line[end + 1] == '{')
                        {
                            par++;
                            subvar = true;
                        }
                        if (line[end] == '}')
                        {
                            par--;
                        }
                        end++;
                    }
                    if (!(end < line.Length))
                    {
                        Log.Warn("Unable to parse all variables in template line: " + line);
                        output.Append(line.Substring(pos));
                        break;
                    }
                    pos = end + 1;

                    // expand variable
                    if (subvar)
                    {
                        key = ExpandTemplateVariables(line.Substring(start, end - start), empty);
                    }
                    else
                    {
                        key = line.Substring(start, end - start);
                    }

                    // replace variable
                    if (repl.ContainsKey(key))
                    {
                        output.Append(repl[key]);
                    }
                    else
                    {
                        if (empty == null)
                        {
                            output.Append("${");
                            output.Append(key);
                            output.Append("}");
                        }
                        else
                        {
                            output.Append(empty);
                        }
                    }
                }

                output.Append(Environment.NewLine);
            }

            return output.ToString(0, output.Length - Environment.NewLine.Length);
        }
    }
}
