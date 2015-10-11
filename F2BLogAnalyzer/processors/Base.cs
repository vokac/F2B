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
        private IList<Tuple<string, string>> repl;
        private Regex removeVariable;

        public ProcessorEventStringTemplate(EventEntry evtlog)
        {
            repl = new List<Tuple<string, string>>(20 + evtlog.ProcData.Count);

            repl.Add(new Tuple<string, string>("${Environment.MachineName}", System.Environment.MachineName));

            repl.Add(new Tuple<string, string>("${Event.Id}", evtlog.Id.ToString()));
            if (evtlog.LogData.GetType().IsSubclassOf(typeof(EventRecordWrittenEventArgs)))
            {
                EventRecordWrittenEventArgs evtarg = evtlog.LogData as EventRecordWrittenEventArgs;
                repl.Add(new Tuple<string, string>("${Event.RecordId}", evtarg.EventRecord.Id.ToString()));
            }
            else
            {
                repl.Add(new Tuple<string, string>("${Event.RecordId}", "0"));
            }
            repl.Add(new Tuple<string, string>("${Event.Timestamp}", evtlog.Timestamp.ToString()));
            repl.Add(new Tuple<string, string>("${Event.Hostname}", (evtlog.Hostname != null ? evtlog.Hostname : "''")));
            repl.Add(new Tuple<string, string>("${Event.InputName}", evtlog.Input.InputName));
            repl.Add(new Tuple<string, string>("${Event.SelectorName}", evtlog.Input.SelectorName));
            repl.Add(new Tuple<string, string>("${Event.Address}", evtlog.Address.ToString()));
            repl.Add(new Tuple<string, string>("${Event.Port}", evtlog.Port.ToString()));
            repl.Add(new Tuple<string, string>("${Event.Username}", (evtlog.Username != null ? evtlog.Username : "''")));
            repl.Add(new Tuple<string, string>("${Event.Domain}", (evtlog.Domain != null ? evtlog.Domain : "''")));
            repl.Add(new Tuple<string, string>("${Event.Status}", evtlog.Status.ToString()));

            foreach (var item in evtlog.ProcData)
            {
                if (item.Value == null) repl.Add(new Tuple<string, string>("${" + item.Key + "}", ""));
                else repl.Add(new Tuple<string, string>("${" + item.Key + "}", item.Value.ToString()));
            }

            removeVariable = new Regex(@"\$\{.*?\}");
        }

        public string ExpandTemplateVariables(string str, string empty = null)
        {
            //Regex re = new Regex(@"\$(\w+)\$", RegexOptions.Compiled);
            //return re.Replace(str, match => repl[match.Groups[1].Value].ToString());
            StringBuilder output = new StringBuilder(str);

            foreach (Tuple<string, string> kv in repl)
            {
                output.Replace(kv.Item1, kv.Item2);
            }

            if (empty != null)
            {
                return removeVariable.Replace(output.ToString(), empty);
            }

            return output.ToString();
        }
    }
}
