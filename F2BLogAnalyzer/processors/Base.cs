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
}
