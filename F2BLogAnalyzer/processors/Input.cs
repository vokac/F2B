#region Imports
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

#endregion

namespace F2B.processors
{
    public class InputProcessor : BoolProcessor, IThreadSafeProcessor
    {
        #region Fields
        private Regex itype;
        private Regex input;
        private Regex selector;
        #endregion

        #region Constructors
        public InputProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            itype = null;
            if (config.Options["type"] != null && !string.IsNullOrEmpty(config.Options["type"].Value))
            {
                itype = new Regex(config.Options["type"].Value);
            }

            input = null;
            if (config.Options["input"] != null && !string.IsNullOrEmpty(config.Options["input"].Value))
            {
                input = new Regex(config.Options["input"].Value);
            }

            selector = null;
            if (config.Options["selector"] != null && !string.IsNullOrEmpty(config.Options["selector"].Value))
            {
                selector = new Regex(config.Options["selector"].Value);
            }

            if (input == null && itype == null && selector == null)
            {
                Log.Warn("input type, input name and selector name regexp is empty (all events will pass this configuration)");
            }
        }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            if (itype != null)
            {
                Log.Error("regex: " + itype.ToString() + ", data: " + evtlog.Input.InputType);
                if (!itype.IsMatch(evtlog.Input.InputType))
                {
                    return goto_failure;
                }
            }

            if (input != null)
            {
                Log.Error("regex: " + input.ToString() + ", data: " + evtlog.Input.InputName);
                if (!input.IsMatch(evtlog.Input.InputName))
                {
                    return goto_failure;
                }
            }

            if (selector != null)
            {
                Log.Error("regex: " + selector.ToString() + ", data: " + evtlog.Input.SelectorName);
                if (!selector.IsMatch(evtlog.Input.SelectorName))
                {
                    return goto_failure;
                }
            }

            return goto_success;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            if (itype == null)
            {
                output.WriteLine("config type:");
            }
            else
            {
                output.WriteLine("config type: " + itype.ToString());
            }

            if (input == null)
            {
                output.WriteLine("config input:");
            }
            else
            {
                output.WriteLine("config input: " + input.ToString());
            }

            if (selector == null)
            {
                output.WriteLine("config selector:");
            }
            else
            {
                output.WriteLine("config selector: " + selector.ToString());
            }
        }
#endif
        #endregion
    }
}
