#region Imports
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

#endregion

namespace F2B.processors
{
    public class RangeFileProcessor : BoolProcessor, IThreadSafeProcessor
    {
        #region Fields
        private string filename;
        private Dictionary<IPAddress, int> ranges;
        private FileSystemWatcher watcher;
        #endregion

        #region Constructors
        public RangeFileProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            if (config.Options["filename"] != null)
            {
                filename = config.Options["filename"].Value;
            }

            if (string.IsNullOrEmpty(filename))
            {
                throw new Exception("Undefined configuration file for \""
                    + Name + "\" processor");
            }

            string dirname = Path.GetDirectoryName(filename);
            if (dirname == string.Empty)
            {
                dirname = Directory.GetCurrentDirectory();
            }

            if (!Directory.Exists(dirname))
            {
                throw new Exception("Processor \"" + Name
                    + "\" configuration file \"" + filename
                    + "\" contains invalid path \"" + dirname + "\"");
            }

            // Create a new FileSystemWatcher and set its properties.
            watcher = new FileSystemWatcher();
            watcher.Path = dirname;
            watcher.Filter = Path.GetFileName(filename);
            watcher.NotifyFilter = NotifyFilters.LastWrite;
            watcher.Changed += new FileSystemEventHandler((s, e) => FileWatcherChanged(s, e));
        }
        #endregion

        #region Methods
        private void UpdateConfiguration()
        {
            try
            {
                if (!File.Exists(filename))
                {
                    if (ranges == null)
                    {
                        Log.Error("Config \"" + filename + "\" doesn't exist");
                    }
                    else
                    {
                        Log.Warn("Config file \"" + filename
                        + "\" doesn't exist, skipping update");
                    }
                    return;
                }

                // parse IP address ranges from text file
                Dictionary<IPAddress, int> rangesNew = new Dictionary<IPAddress, int>();
                using (StreamReader reader = new StreamReader(filename))
                {
                    int pos = 0;
                    string line;

                    while ((line = reader.ReadLine()) != null)
                    {
                        pos++;

                        if (line.StartsWith("#"))
                            continue;

                        if (line.Trim() == string.Empty)
                            continue;

                        try
                        {
                            Tuple<IPAddress, int> network = Utils.ParseNetwork(line.Trim());
                            IPAddress net = Utils.GetNetwork(network.Item1, network.Item2);
                            if (rangesNew.ContainsKey(net) && rangesNew[net] >= network.Item2)
                                continue;

                            rangesNew[net] = network.Item2;
                        }
                        catch (FormatException ex)
                        {
                            Log.Error("Unable to parse range in \"" + filename
                                + "\" (line #" + pos + "): " + line.Trim()
                                + " (" + ex.Message + ")");
                            continue;
                        }
                    }
                }

                // Optimization: remove overlapping IP subranges

                // update configuration
                ranges = rangesNew;
            }
            catch (Exception ex)
            {
                Log.Error("Unable to process \"" + filename + "\": " + ex.Message);
            }

            if (ranges != null && ranges.Count == 0)
            {
                Log.Info("No valid address range in \"" + filename
                    + "\"? That's suspicious...");
            }
        }

        private void FileWatcherChanged(object source, FileSystemEventArgs e)
        {
            WatcherChangeTypes wct = e.ChangeType;
            Log.Info("FileWatcherChanged for \"" + filename
                + "\": " + wct.ToString() + ", " + e.FullPath);

            UpdateConfiguration();
        }
        #endregion

        #region Override
        public override void Start()
        {
            UpdateConfiguration();
            watcher.EnableRaisingEvents = true;
        }

        public override void Stop()
        {
            watcher.EnableRaisingEvents = false;
        }

        public override string Execute(EventEntry evtlog)
        {
            if (ranges == null)
            {
                return goto_failure;
            }

            bool contain = false;

            foreach (KeyValuePair<IPAddress, int> range in ranges)
            {
                IPAddress network = Utils.GetNetwork(evtlog.Address, range.Value);

                Log.Info("Range::Execute: " + evtlog.Address + "/"
                    + range.Value + " -> " + network
                    + (range.Key.Equals(network) ? "" : " not")
                    + " in " + range.Key + "/" + range.Value);

                if (range.Key.Equals(network))
                {
                    contain = true;
                    break;
                }
            }

            if (!contain)
                return goto_failure;
            else
                return goto_success;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            if (ranges != null)
            {
                foreach (KeyValuePair<IPAddress, int> range in ranges)
                {
                    output.WriteLine("config range: {0}/{1}", range.Key, range.Value);
                }
            }
            else
            {
                output.WriteLine("config range: null");
            }
        }
#endif
        #endregion
    }
}
