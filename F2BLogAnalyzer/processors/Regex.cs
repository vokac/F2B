using System;
using System.IO;
using System.Text.RegularExpressions;

namespace F2B.processors
{
    public class RegexProcessor : BoolProcessor, IThreadSafeProcessor
    {
        #region Fields
        private Regex regex;
        private string value;
        #endregion

        #region Constructors
        public RegexProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            if (config.Options["regex"] != null && config.Options["regex"].Value != null)
            {
                regex = new Regex(config.Options["regex"].Value);
            }
            else
            {
                throw new InvalidDataException("required configuration option regex is null");
            }

            value = "";
            if (config.Options["value"] != null && !string.IsNullOrEmpty(config.Options["value"].Value))
            {
                value = config.Options["value"].Value;
            }
            if (value == "")
            {
                Log.Warn("required configuration option value is empty");
            }
        }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            if (value == null)
            {
                return goto_next;
            }

            ProcessorEventStringTemplate tpl = new ProcessorEventStringTemplate(evtlog);

            string data = tpl.Apply(value);
            if (!regex.IsMatch(data))
            {
                return goto_failure;
            }

            return goto_success;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            output.WriteLine("config regex: " + regex);
            output.WriteLine("config value: " + value);
        }
#endif
        #endregion
    }
}
