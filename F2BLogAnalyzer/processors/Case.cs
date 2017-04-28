using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Text;

namespace F2B.processors
{
    public class CaseProcessor : BoolProcessor, IThreadSafeProcessor
    {
        #region Fields
        private string template;
        #endregion

        #region Constructors
        public CaseProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
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

            ProcessorEventStringTemplate tpl = new ProcessorEventStringTemplate(evtlog);

            string label = tpl.Apply(template);
            if (Service.HasProcessor(label))
            {
                return label;
            }
            else
            {
                Log.Info("processor " + label + " not defined, using goto error");
                return goto_failure;
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
    }
}
