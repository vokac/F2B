#region Imports
using System;
using System.Collections.Generic;
using System.IO;

#endregion

namespace F2B.processors
{
    public class FilterProcessor : BoolProcessor, IThreadSafeProcessor
    {
        #region Fields
        private HashSet<string> filters;
        #endregion

        #region Constructors
        public FilterProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            if (filters == null)
            {
                filters = new HashSet<string>();
            }
            else
            {
                filters.Clear();
            }

            foreach (FilterRefElement filter in config.Filters)
            {
                filters.Add(filter.Name);
            }
        }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            if (filters.Count > 0)
            {
                if (!filters.Contains(evtlog.Input.SelectorName))
                    return goto_failure;
            }

            return goto_success;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            foreach (string filter in filters)
            {
                output.WriteLine("config filter: " + filter);
            }
        }
#endif
        #endregion
    }
}
