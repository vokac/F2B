using NetFwTypeLib; // Add reference %SystemRoot%\System32\FirewallAPI.dll
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Timers;

namespace F2B.processors
{
    public sealed class FwManager
    {
        // singleton
        private static volatile FwManager instance;
        private static object syncRoot = new Object();
        // firewall
        private static Type typeFWPolicy2 = Type.GetTypeFromCLSID(new Guid("{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}"));
        private static Type typeFWRule = Type.GetTypeFromCLSID(new Guid("{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}"));

        System.Timers.Timer tCleanupExpired = null;
        private object dataLock = new Object();

        // data structures that keeps info about applyed firewall rules,
        // to be able to discard filters with duplicate conditions and
        // remove filter rules after expiration time
        IDictionary<string, int> fcnt; // name -> count
        IDictionary<string, byte[]> data; // name -> ruleHash
        IDictionary<byte[], long> expire; // ruleHash -> expiration
        SortedDictionary<long, string> cleanup; // expiration -> name

        private FwManager()
        {
            tCleanupExpired = new System.Timers.Timer(10000);
            tCleanupExpired.Elapsed += CleanupExpired;

            Refresh();
        }


        ~FwManager()
        {
            if (tCleanupExpired != null)
            {
                if (tCleanupExpired.Enabled)
                {
                    tCleanupExpired.Enabled = false;
                }
                tCleanupExpired.Dispose();
            }
        }


        public static FwManager Instance
        {
            get
            {
                if (instance == null)
                {
                    lock (syncRoot)
                    {
                        if (instance == null)
                            instance = new FwManager();
                    }
                }

                return instance;
            }
        }


        public double Interval
        {
            get
            {
                if (tCleanupExpired == null)
                    return 0;

                return tCleanupExpired.Interval;
            }
            set
            {
                if (value < 0)
                    return;

                //if (value > tCleanupExpired.Interval)
                //    return;

                if (value == 0)
                {
                    Log.Info("Disabling cleanup timer (no cleanup interval)");
                    tCleanupExpired.Enabled = false;
                }
                else
                {
                    tCleanupExpired.Interval = value;

                    if (!tCleanupExpired.Enabled && data.Count > 0)
                    {
                        Log.Info("Enabling cleanup timer (interval " + tCleanupExpired.Interval + " ms)");
                        tCleanupExpired.Enabled = true;
                    }
                    else
                    {
                        Log.Info("Changing cleanup timer interval to " + tCleanupExpired.Interval + " ms");
                    }
                }
            }
        }


        public int MaxSize { get; set; } = 0;

        
        private IDictionary<string, int> List()
        {
            IDictionary<string, int> ret = new Dictionary<string, int>();
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(typeFWPolicy2);

            foreach (INetFwRule rule in fwPolicy2.Rules)
            {
                if (rule.Name.IndexOf("F2B B64 ") < 0)
                    continue;

                if (!ret.ContainsKey(rule.Name))
                {
                    ret[rule.Name] = 0;
                }

                ret[rule.Name] += 1;
            }

            return ret;
        }


        private void Remove(string filterName, int filterCnt = 0)
        {
            if (filterCnt == 0 && !fcnt.TryGetValue(filterName, out filterCnt))
            {
                Log.Info("Remove: Missing filter count for " + filterName);
                return;
            }

            Tuple<long, byte[]> fwName = null;
            int pos = filterName.IndexOf("F2B B64 ");
            if (pos >= 0)
            {
                try
                {
                    fwName = FwData.DecodeName(filterName.Substring(pos));
                }
                catch (ArgumentException)
                {
                }
            }

            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(typeFWPolicy2);

            for (int i = 0; i < filterCnt; i++)
            {
                try
                {
                    fwPolicy2.Rules.Remove(filterName);

                    if (fwName == null)
                    {
                        Log.Info("Remove: Removed filter rule \""
                            + filterName + "\" (pass = " + i + ")");
                    }
                    else
                    {
                        Log.Info("Remove: Removed filter rule \""
                            + filterName + "\" (expiration=" + fwName.Item1 + ", md5="
                            + BitConverter.ToString(fwName.Item2).Replace("-", ":")
                            + ", pass=" + i + ")");
                    }
                }
                catch (Exception ex)
                {
                    if (fwName == null)
                    {
                        Log.Warn("Remove: Unable to remove filter rule \""
                            + filterName + "\" ( pass = " + i + "): " + ex.Message);
                    }
                    else
                    {
                        Log.Warn("Remove: Unable to remove filter rule \""
                            + filterName + "\" (expiration=" + fwName.Item1 + ", md5="
                            + BitConverter.ToString(fwName.Item2).Replace("-", ":")
                            + ", pass=" + i + "): " + ex.Message);
                    }
                    //fail++;
                    break;
                }
            }
        }


        public void Refresh()
        {
            Log.Info("Refresh list of F2B filter rules using Firewall COM object");

            lock (dataLock)
            {
                data = new Dictionary<string, byte[]>();
                expire = new Dictionary<byte[], long>(new ByteArrayComparer());
                cleanup = new SortedDictionary<long, string>();

                long currtime = DateTime.UtcNow.Ticks;

                try
                {
                    fcnt = List();
                }
                catch (Exception ex)
                {
                    Log.Error("Refresh: Unable to list F2B firewall filters: " + ex.Message);
                    return;
                }

                // get current F2B firewall rules from WFP configuration
                foreach (var item in fcnt)
                {
                    string filterName = item.Key;
                    int filterCnt = item.Value;

                    Tuple<long, byte[]> fwName = null;
                    int pos = filterName.IndexOf("F2B B64 ");
                    if (pos >= 0)
                    {
                        try
                        {
                            fwName = FwData.DecodeName(filterName.Substring(pos));
                        }
                        catch (ArgumentException)
                        {
                        }
                    }
                    if (fwName == null)
                    {
                        Log.Info("Refresh: Unable to parse F2B data from filter rule name: " + filterName);
                        continue;
                    }

                    long expiration = fwName.Item1;
                    byte[] hash = fwName.Item2;

                    // cleanup expired rules
                    if (expiration < currtime)
                    {
                        Log.Info("Refresh: Remove expired filter rule \"" + filterName + "\"");
                        Remove(filterName);
                        continue;
                    }

                    // cleanup rules with same hash
                    long expirationOld;
                    if (expire.TryGetValue(hash, out expirationOld))
                    {
                        string filterNameOld = cleanup[expirationOld];
                        string filterNameRemove = (expiration < expirationOld ? filterName : filterNameOld);

                        Log.Info("Refresh: Remove older filter rule \"" + filterName + "\"");
                        Remove(filterNameRemove);

                        if (expiration < expirationOld)
                        {
                            Log.Info("Refresh: Skipping older (removed) filter rule");
                            continue;
                        }
                        else
                        {
                            data.Remove(filterNameOld);
                            expire.Remove(hash); // not necessary
                            cleanup.Remove(expirationOld);
                        }
                    }

                    // we need unique expiration time to keep all required
                    // data in simple key/value hashmap structure (and we
                    // really don't care about different expiration time in ns)
                    while (cleanup.ContainsKey(expiration))
                    {
                        expiration++;
                    }

                    Log.Info("Refresh: Add filter rule e/f/h: " + expiration + "/" + filterName + "/" + BitConverter.ToString(hash).Replace("-", ":"));
                    data[filterName] = hash;
                    expire[hash] = expiration;
                    cleanup[expiration] = filterName;
                }

                if (data.Count > 0)
                {
                    if (tCleanupExpired.Enabled)
                    {
                        Log.Info("Found " + data.Count + " F2B existing filter rules, cleanup timer already running (interval " + tCleanupExpired.Interval + " ms)");
                    }
                    else
                    {
                        Log.Info("Found " + data.Count + " F2B existing filter rules, enabling cleanup timer (interval " + tCleanupExpired.Interval + " ms)");
                        tCleanupExpired.Enabled = true;
                    }
                }
                else
                {
                    if (tCleanupExpired.Enabled)
                    {
                        Log.Info("No F2B filter rules currently defined in WFP, disabling cleanup timer");
                        tCleanupExpired.Enabled = true;
                    }
                    else
                    {
                        Log.Info("No F2B filter rules currently defined in WFP, cleanup timer already disabled");
                    }
                }
            }
        }


        private void CleanupExpired(object sender, ElapsedEventArgs e)
        {
            if (tCleanupExpired != null && !tCleanupExpired.Enabled)
            {
                // this should prevent race condition, because elapsed
                // event is queued for execution on a thread poole thread
                return;
            }

            int sizeBefore, sizeAfter;
            long currtime = DateTime.UtcNow.Ticks;
            IList<KeyValuePair<long, string>> remove = new List<KeyValuePair<long, string>>();

            Log.Info("CleanupExpired: Started");

            lock (dataLock)
            {
                sizeBefore = data.Count;

                foreach (var item in cleanup)
                {
                    // this assume sorted container!
                    if (item.Key > currtime)
                        break;

                    remove.Add(item);
                }

                foreach (var item in remove)
                {
                    long expiration = item.Key;
                    string filterName = item.Value;
                    byte[] hash = data[filterName];

                    cleanup.Remove(expiration);
                    expire.Remove(hash);
                    data.Remove(filterName);
                }

                sizeAfter = data.Count;
            }

            Log.Info("CleanupExpired: Removed " + remove.Count + " F2B filter rules (data size " + sizeBefore + " -> " + sizeAfter + ")");

            int fail = 0;
            foreach (var item in remove)
            {
                string filterName = item.Value;
                try
                {
                    Log.Info("CleanupExpired: Remove filter rule \"" + filterName + "\"");
                    Remove(filterName);
                }
                catch (Exception ex)
                {
                    Log.Warn("CleanupExpired: Unable to remove filter rule \"" + filterName + "\": " + ex.Message);
                    fail++;
                }
            }

            lock (dataLock)
            {
                if (data.Count == 0)
                {
                    Log.Info("CleanupExpired: List of F2B filters is empty, disabling cleanup timer");
                    tCleanupExpired.Enabled = false;
                }
            }

            Log.Info("CleanupExpired: Finished" + (fail > 0 ? " (failed to remove " + fail + " filter rules)" : ""));
        }


        private void Add(string name, long expiration, string address, bool permit = false)
        {
            // human readable expiration time
            string expstr = Convert.ToString(expiration);
            try
            {
                DateTime tmpExp = new DateTime(expiration, DateTimeKind.Utc);
                expstr = tmpExp.ToLocalTime().ToString();
            }
            catch (Exception)
            {
            }

            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(typeFWPolicy2);
            INetFwRule newRule = (INetFwRule)Activator.CreateInstance(typeFWRule);

            newRule.Name = name;
            newRule.Description = "Fail2ban " + (permit ? "allow" : "block") + " client address " + address + " till " + expstr;
            newRule.RemoteAddresses = address;
            newRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
            newRule.Enabled = true;
            newRule.Grouping = "@firewallapi.dll,-23255";
            newRule.Profiles = fwPolicy2.CurrentProfileTypes;
            if (permit)
            {
                newRule.Action = NET_FW_ACTION_.NET_FW_ACTION_ALLOW;
            }
            else
            {
                newRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
            }

            fwPolicy2.Rules.Add(newRule);
        }


        public void Add(long expiration, IPAddress addr, int prefix, bool permit = false)
        {
            long currtime = DateTime.UtcNow.Ticks;

            // Adding filter with expiration time in past
            // doesn't really make any sense
            if (currtime >= expiration)
            {
                string tmp = Convert.ToString(expiration);
                try
                {
                    DateTime tmpExp = new DateTime(expiration, DateTimeKind.Utc);
                    tmp = tmpExp.ToLocalTime().ToString();
                }
                catch (Exception)
                {
                }
                Log.Info("Skipping expired firewall rule (expired on " + tmp + ")");
                return;
            }

            F2B.FwData fwdata = new F2B.FwData(expiration, addr, prefix);
            byte[] hash = fwdata.Hash;

            lock (dataLock)
            {
                // we need unique expiration time to keep all required
                // data in simple key/value hashmap structure (and we
                // really don't care about different expiration time in ns)
                while (cleanup.ContainsKey(expiration))
                {
                    expiration++;
                }

                // filter out requests with expiration within 10% time
                // range and treat them as duplicate requests
                string filterName = null;
                long expirationOld;
                if (expire.TryGetValue(hash, out expirationOld))
                {
                    if (currtime > Math.Max(expirationOld, expiration))
                    {
                        Log.Info("Skipping request with expiration in past");
                    }
                    else if (expiration < expirationOld)
                    {
                        Log.Info("Skipping request with new expiration " + expiration + " < existing exipration " + expirationOld);
                    }
                    else if (expiration - expirationOld < (expiration - currtime) / 10)
                    {
                        Log.Info("Skipping request with expiration of new records within 10% of expiration of existing rule (c/o/e=" + currtime + "/" + expirationOld + "/" + expiration + ")");
                    }
                    else
                    {
                        string filterNameOld = cleanup[expirationOld];
                        // maximum filter name size is 60 characters
                        //string tmpFilterName = "Fail2ban block address " + addr + "/" + prefix
                        //    + " till " + expstr + "|" + F2B.FwData.EncodeName(expiration, hash);
                        string tmpFilterName = F2B.FwData.EncodeName(expiration, hash);

                        Log.Info("Replace old filter \"" + filterNameOld + "\" with increased expiration time (c/o/e=" + currtime + "/" + expirationOld + "/" + expiration + ")");
                        try
                        {
                            Log.Info("Add: Add filter rule \"" + tmpFilterName + "\"");
                            Add(tmpFilterName, expiration, addr + "/" + prefix);
                            filterName = tmpFilterName;

                            Log.Info("Add: Remove expired filter rule \"" + filterNameOld + "\"");
                            Remove(filterNameOld);
                        }
                        catch (Exception ex)
                        {
                            Log.Warn("Unable to replace filter rule \"" + filterNameOld + "\" with \"" + tmpFilterName + "\": " + ex.Message);
                            //fail++;
                        }

                        if (filterName != null) // no exception during rule addition
                        {
                            data.Remove(filterNameOld);
                            expire.Remove(hash); // not necessary
                            cleanup.Remove(expirationOld);
                        }
                    }
                }
                else
                {
                    if (MaxSize == 0 || MaxSize > data.Count)
                    {
                        // maximum filter name size is 60 characters
                        //string tmpFilterName = "Fail2ban block address " + addr + "/" + prefix
                        //    + " till " + expstr + "|" + F2B.FwData.EncodeName(expiration, hash);
                        string tmpFilterName = F2B.FwData.EncodeName(expiration, hash);

                        try
                        {
                            Log.Info("Add: Add filter rule \"" + tmpFilterName + "\"");
                            Add(tmpFilterName, expiration, addr + "/" + prefix);
                            filterName = tmpFilterName;
                        }
                        catch (Exception ex)
                        {
                            Log.Warn("Unable to add filter \"" + tmpFilterName + "\": " + ex.Message);
                            //fail++;
                        }
                    }
                    else
                    {
                        Log.Warn("Reached limit for number of active F2B filter rules, skipping new additions");
                    }
                }

                if (filterName != null)
                {
                    fcnt[filterName] = 1; // ???
                    data[filterName] = hash;
                    expire[hash] = expiration;
                    cleanup[expiration] = filterName;

                    if (!tCleanupExpired.Enabled)
                    {
                        Log.Info("Enabling cleanup timer (interval " + tCleanupExpired.Interval + " ms)");
                        tCleanupExpired.Enabled = true;
                    }
                }
            } // dataLock
        }


#if DEBUG
        public void Debug(StreamWriter output)
        {
            lock (dataLock)
            {
                foreach (var item in data)
                {
                    output.WriteLine("  data: {0} {1}", item.Key, BitConverter.ToString(item.Value).Replace("-", ":"));
                }
                foreach (var item in expire)
                {
                    string tmp = Convert.ToString(item.Value);
                    try
                    {
                        DateTime tmpExp = new DateTime(item.Value, DateTimeKind.Utc);
                        tmp = tmpExp.ToLocalTime().ToString();
                    }
                    catch (Exception)
                    {
                    }
                    output.WriteLine("  expire: {0} {1} ({2})", BitConverter.ToString(item.Key).Replace("-", ":"), item.Value, tmp);
                }
                foreach (var item in cleanup)
                {
                    output.WriteLine("  cleanup: {0} {1}", item.Key, item.Value);
                }
                foreach (var item in cleanup)
                {
                    long expiration = item.Key;
                    string filterName = item.Value;
                    byte[] hash = data[filterName];

                    output.WriteLine("  e/f/h: {0}/{1}/{2}", expiration, filterName, BitConverter.ToString(hash).Replace("-", ":"));
                }
            }
        }
#endif
    }



    public class Fail2banFwProcessor : Fail2banActionProcessor, IThreadSafeProcessor
    {
        #region Fields
        private int cleanup;
        private int max_filter_rules;
        #endregion

        #region Constructors
        public Fail2banFwProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            cleanup = bantime / 10;
            if (config.Options["cleanup"] != null)
            {
                int tmp = int.Parse(config.Options["cleanup"].Value);
                if (tmp > 0)
                {
                    cleanup = tmp;
                }
                else
                {
                    Log.Error("Ignoring invalid cleanup interval " + tmp);
                }
            }

            max_filter_rules = 0;
            if (config.Options["max_filter_rules"] != null)
            {
                max_filter_rules = int.Parse(config.Options["max_filter_rules"].Value);
            }

            if (F2B.processors.FwManager.Instance.Interval > 1000 * cleanup)
            {
                F2B.processors.FwManager.Instance.Interval = 1000 * cleanup;
            }
            F2B.processors.FwManager.Instance.MaxSize = max_filter_rules;
        }
        #endregion

        #region Override
        protected override void ExecuteFail2banAction(EventEntry evtlog, IPAddress addr, int prefix, long expiration)
        {
            F2B.processors.FwManager.Instance.Add(expiration, addr, prefix);
        }


#if DEBUG
        public override void Debug(StreamWriter output)
        {
            output.WriteLine("config cleanup: " + cleanup);
            output.WriteLine("config max_filter_rules: " + max_filter_rules);
            base.Debug(output);
            output.WriteLine("FwManager:");
            F2B.processors.FwManager.Instance.Debug(output);
        }
#endif
        #endregion
    }
}
