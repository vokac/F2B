#region Imports
using System.Collections.Generic;
using System.IO;
#endregion

namespace F2B.processors
{
    public class ParallelProcessor : BaseProcessor, IThreadSafeProcessor
    {
        #region Fields
        private List<string> processors;
        #endregion

        #region Constructors
        public ParallelProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            processors = new List<string>();

            if (config.Options["processors"] != null)
            {
                foreach (string processor in config.Options["processors"].Value.Split(','))
                {
                    if (string.IsNullOrEmpty(processor))
                        continue;

                    processors.Add(processor);
                }
            }
        }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            foreach (string processor in processors)
            {
                Produce(new EventEntry(evtlog), processor);
            }

            return null;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            foreach (string processor in processors)
            {
                output.WriteLine("config processors: " + processor);
            }
        }
#endif
        #endregion
    }
}
