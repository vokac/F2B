using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Text;

namespace F2B.processors
{
    public class CaseProcessor : BaseProcessor, IThreadSafeProcessor
    {
        #region Fields
        private Service service;
        private string template;
        #endregion

        #region Constructors
        public CaseProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            this.service = service;

            template = null;
            if (config.Options["template"] != null && !string.IsNullOrEmpty(config.Options["template"].Value))
            {
                template = config.Options["template"].Value;
            }

            if (template == null)
            {
                Log.Warn("empty template, next processor will be used for all events");
            }
        }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            if (template == null)
            {
                return goto_next;
            }

            Dictionary<string, string> repl = new Dictionary<string, string>(10 + evtlog.ProcData.Count);
            repl["$Event.Id$"] = evtlog.Id.ToString();
            if (evtlog.LogData.GetType().IsSubclassOf(typeof(EventRecordWrittenEventArgs)))
            {
                EventRecordWrittenEventArgs evtarg = evtlog.LogData as EventRecordWrittenEventArgs;
                repl["$Event.RecordId$"] = evtarg.EventRecord.Id.ToString();
            }
            else
            {
                repl["$Event.RecordId$"] = "0";
            }
            repl["$Event.Timestamp$"] = evtlog.Timestamp.ToString();
            repl["$Event.Hostname$"] = (evtlog.Hostname != null ? evtlog.Hostname : "''");
            repl["$Event.InputName$"] = evtlog.Input.InputName;
            repl["$Event.SelectorName$"] = evtlog.Input.SelectorName;
            repl["$Event.Address$"] = evtlog.Address.ToString();
            repl["$Event.Port$"] = evtlog.Port.ToString();
            repl["$Event.Username$"] = (evtlog.Username != null ? evtlog.Username : "''");
            repl["$Event.Domain$"] = (evtlog.Domain != null ? evtlog.Domain : "''");
            repl["$Event.Status$"] = evtlog.Status.ToString();
            foreach (var item in evtlog.ProcData)
            {
                if (item.Value == null) repl["$" + item.Key + "$"] = "";
                else repl["$" + item.Key + "$"] = item.Value.ToString();
            }

            string label = ExpandTemplateVariables(template, repl);
            if (service.HasProcessor(label))
            {
                return label;
            }
            else
            {
                Log.Info("processor " + label + " not defined, using goto error");
                return goto_error;
            }
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            output.WriteLine("config template: " + template);
        }
#endif
        #endregion

        #region Methods
        private string ExpandTemplateVariables(string str, IReadOnlyDictionary<string, string> repl)
        {
            //Regex re = new Regex(@"\$(\w+)\$", RegexOptions.Compiled);
            //return re.Replace(str, match => repl[match.Groups[1].Value].ToString());
            StringBuilder output = new StringBuilder(str);

            foreach (var kvp in repl)
            {
                output.Replace(kvp.Key, kvp.Value);
            }

            return output.ToString();
        }
        #endregion
    }
}
