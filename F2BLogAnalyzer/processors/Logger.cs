#region Imports
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Text;

#endregion

namespace F2B.processors
{
    public class LoggerProcessor : BaseProcessor
    {
        #region Fields
        private long nexceptions;
        private long size_curr;
        private StreamWriter sw;

        private string filename;
        private long size;
        private int rotate;
        private string template;
        private bool synchronized;
        #endregion

        #region Constructors
        public LoggerProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            // set default values
            nexceptions = 0;
            size_curr = -1;
            sw = null;

            filename = null;
            size = -1;
            rotate = -1;
            template = "$Event.Id$\t$Event.Timestamp$\t$Event.Hostname$\t$Event.InputName$\t$Event.SelectorName$\t$Event.Status$\t$Event.RecordId$\t$Event.Address$\t$Event.Port$\t$Event.Username$\t$Event.Domain$\n";
            synchronized = true;

            if (config.Options["file"] != null)
            {
                filename = config.Options["file"].Value;
            }
            if (config.Options["size"] != null)
            {
                size = long.Parse(config.Options["size"].Value);
            }
            if (config.Options["rotate"] != null)
            {
                rotate = int.Parse(config.Options["rotate"].Value);
            }
            if (config.Options["template"] != null)
            {
                template = config.Options["template"].Value;
            }
            if (config.Options["synchronized"] != null)
            {
                synchronized = bool.Parse(config.Options["synchronized"].Value);
            }
        }
        #endregion

        #region Override
        public override void Stop()
        {
             //base.Stop();
            if (sw != null)
            {
                sw.Close();
                sw = null;
            }
        }


        public override string Execute(EventEntry evtlog)
        {
            try
            {
                if (size > 0)
                {
                    // get current log file size
                    if (size_curr < 0)
                    {
                        if (File.Exists(filename))
                        {
                            FileInfo f = new FileInfo(filename);
                            size_curr = f.Length;
                        }
                        else
                        {
                            size_curr = 0;
                        }
                    }

                    if (size_curr > size)
                    {
                        if (sw != null)
                        {
                            sw.Close();
                            sw = null;
                        }

                        if (rotate > 0)
                        {
                            if (File.Exists(filename + "." + rotate))
                            {
                                File.Delete(filename + "." + rotate);
                            }
                            for (int i = rotate; i > 1; i++)
                            {
                                if (File.Exists(filename + "." + (i - 1)))
                                {
                                    File.Move(filename + "." + (i - 1), filename + "." + i);
                                }
                            }
                            if (File.Exists(filename))
                            {
                                File.Move(filename, filename + ".1");
                            }
                        }
                        else
                        {
                            if (File.Exists(filename))
                            {
                                File.Move(filename, filename + ".bak");
                            }
                        }
                    }
                }

                if (sw == null)
                {
                    sw = File.AppendText(filename);
                    nexceptions = 0;
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

                string data = ExpandTemplateVariables(template, repl);
                sw.Write(data);
                
                if (synchronized)
                {
                    sw.Flush();
                }

                size_curr += data.Length;
            }
            catch (Exception ex)
            {
                if (nexceptions == 0)
                {
                    Log.Error("LoggerProcessor::Execute exception: " + ex.ToString());
                }

                nexceptions++;
            }

            return goto_next;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            output.WriteLine("config file: " + filename);
            output.WriteLine("config size: " + size);
            output.WriteLine("config rotate: " + rotate);
            output.WriteLine("status size_curr: " + size_curr);
            output.WriteLine("status nexceptions: " + nexceptions);
            output.WriteLine("status sw: " + sw);
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
