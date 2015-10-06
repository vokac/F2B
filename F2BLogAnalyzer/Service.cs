#region Imports
using F2B.inputs;
using F2B.processors;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Reflection;
using System.ServiceProcess;
using System.Threading;
#endregion

namespace F2B
{
    public partial class Service : ServiceBase
    {
        public static string NAME = "F2BLA";
        public static string DISPLAY = "Fail2ban Log Analyzer for Windows";
        public static string DESCR = "Provides one component of fail2ban services for Windows that can reconfigure firewall to reject clients that exceed failed login threshold.";

        private volatile bool shutdown = false;
        private Thread st = null;
        private EventWaitHandle ewh;
        private Dictionary<string, BaseInput> inputs;
        private Dictionary<string, BaseProcessor> processors;
        private EventQueue equeue;

        public Service()
        {
            this.ServiceName = NAME;

            ewh = new EventWaitHandle(false, EventResetMode.ManualReset);
        }

        private Dictionary<string, BaseInput> InitializeInputs(EventQueue queue)
        {
            F2BSection config = F2B.Config.Instance;
            InputCollection inputs = config.Inputs;
            SelectorCollection selectors = config.Selectors;
            ProcessorCollection processors = config.Processors;

            string firstProcName = null;
            if (processors.Count > 0)
            {
                firstProcName = processors[0].Name;
            }

            Dictionary<string, BaseInput> ret = new Dictionary<string, BaseInput>();

            // create log data sources and selectors
            foreach (InputElement input in inputs)
            {
                Log.Info("input[" + input.Name + "]");
                if (string.IsNullOrEmpty(input.Name))
                {
                    Log.Warn("input[" + input.Name + "] undefined input name");
                    continue;
                }

                foreach (SelectorElement selector in selectors)
                {
                    if (!string.IsNullOrEmpty(selector.InputName) && selector.InputName != input.Name)
                    {
                        continue;
                    }
                    if (!string.IsNullOrEmpty(selector.InputType) && selector.InputType != input.Type)
                    {
                        continue;
                    }

                    // create input
                    string clazzName = "F2B.inputs." + input.Type + "Input";
                    Type clazzType = Type.GetType(clazzName);

                    if (clazzType == null)
                    {
                        Log.Error("input[" + input.Name + "]/selector[" + selector.Name
                            + "]: unable to resolve class \"" + clazzName + "\"");
                    }
                    else
                    {
                        Log.Info("input[" + input.Name + "]/selector[" + selector.Name
                            + "]: creating new " + clazzName + " input");
                    }

                    ConstructorInfo ctor = clazzType.GetConstructor(
                        new[] { typeof(InputElement), typeof(SelectorElement), typeof(EventQueue) });
                    BaseInput logInput = (BaseInput)ctor.Invoke(new object[] { input, selector, queue });
                    ret[input.Name + "/" + selector.Name] = logInput;
                }
            }

            return ret;
        }

        private Dictionary<string, BaseProcessor> InitializeProcessors()
        {
            F2BSection config = F2B.Config.Instance;
            ProcessorCollection processors = config.Processors;

            Dictionary<string, BaseProcessor> ret = new Dictionary<string, BaseProcessor>();

            // create processors
            for (int i = 0; i < processors.Count; i++)
            {
                ProcessorElement processor = processors[(int)i];

                // test invalid configuration
                if (processor.Name == null || processor.Name == "")
                {
                    throw new Exception("Undefined processor #" + (processors.Count + 1) + " name");
                }
                if (ret.ContainsKey(processor.Name))
                {
                    throw new Exception("Duplicate processor name: " + processor.Name);
                }

                // add reference to next processor name
                if (i < processors.Count - 1)
                {
                    string nextName = processors[(int)(i + 1)].Name;
                    if (processor.Goto.Next == string.Empty)
                    {
                        processor.Goto.Next = nextName;
                    }
                    if (processor.Goto.Error == string.Empty)
                    {
                        if (processor.Goto.OnErrorNext)
                        {
                            processor.Goto.Error = nextName;
                        }
                        else
                        {
                            processor.Goto.Error = null;
                        }
                    }
                    if (processor.Goto.Success == string.Empty)
                    {
                        processor.Goto.Success = nextName;
                    }
                    if (processor.Goto.Failure == string.Empty)
                    {
                        processor.Goto.Failure = nextName;
                    }
                }

                // create processor
                string clazzName = "F2B.processors." + processor.Type + "Processor";
                Type clazzType = Type.GetType(clazzName); // + "`1[F2B.ProcessorElement]");

                if (clazzType == null)
                {
                    Log.Error("processor[" + processor.Name + "@" + processor.Type
                        + "]: unable to resolve class \"" + clazzName + "\"");
                }
                else if (clazzType.IsSubclassOf(typeof(BoolProcessor)))
                {
                    Log.Info("processor[" + processor.Name + "@" + processor.Type
                        + "]: next->" + processor.Goto.Next
                        + ", error->" + processor.Goto.Error
                        + ", success->" + processor.Goto.Success
                        + ", failure->" + processor.Goto.Failure);
                }
                else
                {
                    Log.Info("processor[" + processor.Name + "@" + processor.Type
                        + "]: next->" + processor.Goto.Next
                        + ", error->" + processor.Goto.Error);
                }

                //ConstructorInfo ctor = clazzType.GetConstructor(new[] { typeof(ProcessorElement), typeof(Action<EventEntry, string, bool>) });
                //ret[processor.Name] = (BaseProcessor)ctor.Invoke(new object[] { processor, Delegate.CreateDelegate(GetType(), this, "Produce") });
                ConstructorInfo ctor = clazzType.GetConstructor(new[] { typeof(ProcessorElement), GetType() });
                ret[processor.Name] = (BaseProcessor)ctor.Invoke(new object[] { processor, this });
            }

            return ret;
        }

        public void Produce(EventEntry item, string processor, bool ignoreQueueSizeLimit = false)
        {
            if (equeue == null)
            {
                Log.Error("Unable to produce events before queue initialization!?!?");
                return;
            }

            if (string.IsNullOrEmpty(processor))
            {
                Log.Error("Unable to queue events with empty processor name");
                return;
            }

            Log.Info("Service[" + item.Id + "@" + item.Input.Name + "] (re)queued message"
                + " with first processor name " + processor);
            equeue.Produce(item, processor, ignoreQueueSizeLimit);
        }

        private void ServiceThread()
        {
            Log.Info("ServiceThread starting");

            // create and start log processors
            processors = InitializeProcessors();
            foreach (BaseProcessor processor in processors.Values)
            {
                processor.Start();
            }

            // create and start log queue
            equeue = new EventQueue(processors);
            equeue.Start();
            
            // create and start log inputs
            inputs = InitializeInputs(equeue);
            foreach (BaseInput input in inputs.Values)
            {
                try
                {
                    input.Start();
                }
                catch (Exception ex)
                {
                    Log.Error("Unable to start " + input.Name + ": " + ex.Message);
                    //Log.Info(ex.ToString());
                }
            }

            while (!shutdown)
            {
                ewh.WaitOne();
                ewh.Reset();
                Log.Info("ServiceThread loop cont(" + !shutdown + ")");
            }

            Log.Info("ServiceThread finished");
        }

        protected override void OnStart(string[] args)
        {
            st = new Thread(new ThreadStart(ServiceThread));
            st.Start();
        }

        protected override void OnStop()
        {
            shutdown = true;

            // stop log inputs
            if (inputs != null)
            {
                foreach (BaseInput input in inputs.Values)
                {
                    try
                    {
                        input.Stop();
                    }
                    catch (Exception ex)
                    {
                        Log.Error("Unable to stop input " + input.Name + ": " + ex.Message);
                        //Log.Info(ex.ToString());
                    }
                }
            }

            // drain event log queue
            if (equeue != null)
            {
                equeue.Stop();
            }

            // stop event processors
            if (processors != null)
            {
                foreach (BaseProcessor processor in processors.Values)
                {
                    try
                    {
                        processor.Stop();
                    }
                    catch (Exception ex)
                    {
                        Log.Error("Unable to stop processor " + processor.Name + ": " + ex.Message);
                        //Log.Info(ex.ToString());
                    }
                }
            }

            // send signal to service main thread
            ewh.Set();

            Log.Info("Waiting for service thread to finish");
            st.Join();
            Log.Info("Service thread to finished");
        }

#if DEBUG
        public void Dump()
        {
            equeue.Produce(null);
        }
#endif
    }
}
