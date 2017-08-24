using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Timers;

namespace F2B
{
    public partial class FwData
    {
        public F2B.FirewallConditions Conditions()
        {
            F2B.FirewallConditions conds = new F2B.FirewallConditions();

            byte[] data = stream.ToArray();

            int pos = DataSize[F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION];
            while (pos < data.Length)
            {
                int size = 0;
                DataSize.TryGetValue((F2B_FWDATA_TYPE0_ENUM)data[pos], out size);

                // this is not necessary because we validate input data
                //if (size == 0)
                //{
                //    // undefined size or unknown type
                //    throw new InvalidDataException("Unknown FwData type or size: " + data[pos]);
                //}
                //
                //if (!(data.Length >= pos + size))
                //{
                //    // Truncated data?!
                //    throw new InvalidDataException("Truncated FwData data with type: " + data[pos]);
                //}

                // Create new firewall rule
                switch ((F2B_FWDATA_TYPE0_ENUM)data[pos])
                {
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION:
                        throw new InvalidDataException("More expiration records in FwData");
                    //expiration = IPAddress.NetworkToHostOrder(BitConverter.ToInt64(data, pos + 1));
                    //break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4:
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4_AND_PREFIX:
                        byte[] baddr4 = new byte[4];
                        Array.Copy(data, pos + 1, baddr4, 0, 4);
                        if ((F2B_FWDATA_TYPE0_ENUM)data[pos] == F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4)
                            conds.Add(new IPAddress(baddr4));
                        else
                            conds.Add(new IPAddress(baddr4), data[pos + 1 + 4]);
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4_RANGE:
                        byte[] baddrLow4 = new byte[4];
                        byte[] baddrHigh4 = new byte[4];
                        Array.Copy(data, pos + 1, baddrLow4, 0, 4);
                        Array.Copy(data, pos + 1 + 4, baddrHigh4, 0, 4);
                        conds.Add(new IPAddress(baddrLow4), new IPAddress(baddrHigh4));
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6:
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6_AND_PREFIX:
                        byte[] baddr6 = new byte[16];
                        Array.Copy(data, pos + 1, baddr6, 0, 16);
                        if ((F2B_FWDATA_TYPE0_ENUM)data[pos] == F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6)
                            conds.Add(new IPAddress(baddr6));
                        else
                            conds.Add(new IPAddress(baddr6), data[pos + 1 + 16]);
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6_RANGE:
                        byte[] baddrLow6 = new byte[16];
                        byte[] baddrHigh6 = new byte[16];
                        Array.Copy(data, pos + 1, baddrLow6, 0, 16);
                        Array.Copy(data, pos + 1 + 4, baddrHigh6, 0, 16);
                        conds.Add(new IPAddress(baddrLow6), new IPAddress(baddrHigh6));
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_PORT:
                        conds.Add(IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, pos + 1)));
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_PORT_RANGE:
                        conds.Add(IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, pos + 1)),
                            IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, pos + 1 + 2)));
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_PROTOCOL:
                        conds.Add((ProtocolType)data[pos + 1]);
                        break;
                    default:
                        throw new InvalidDataException("Unknown FwData type: " + data[pos]);
                        //break;
                }

                pos += size;
            }

            return conds;
        }
    }



    public sealed class FwManager
    {
        private static volatile FwManager instance;
        private static object syncRoot = new Object();

        System.Timers.Timer tCleanupExpired = null;
        private object dataLock = new Object();

        // data structures that keeps info about applyed firewall rules,
        // to be able to discard filters with duplicate conditions and
        // remove filter rules after expiration time
        IDictionary<UInt64, byte[]> data; // filterId -> ruleHash
        IDictionary<byte[], long> expire; // ruleHash -> expiration
        SortedDictionary<long, UInt64> cleanup; // expiration -> filterId

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


        public void Refresh()
        {
            Log.Info("Refresh list of F2B filter rules from WFP data structures");

            lock (dataLock)
            {
                data = new Dictionary<UInt64, byte[]>();
                expire = new Dictionary<byte[], long>(new ByteArrayComparer());
                cleanup = new SortedDictionary<long, UInt64>();

                IDictionary<ulong, string> filters;
                long currtime = DateTime.UtcNow.Ticks;

                try
                {
                    filters = F2B.Firewall.Instance.List();
                }
                catch (FirewallException ex)
                {
                    Log.Error("Unable to list F2B firewall filters: " + ex.Message);
                    return;
                }

                // get current F2B firewall rules from WFP configuration
                foreach (var item in filters)
                {
                    Tuple<long, byte[]> fwName = null;
                    try
                    {
                        fwName = FwData.DecodeName(item.Value);
                    }
                    catch (ArgumentException)
                    {
                        Log.Info("Refresh: Unable to parse F2B data from filter rule name: " + item.Value);
                        continue;
                    }

                    UInt64 filterId = item.Key;
                    long expiration = fwName.Item1;
                    byte[] hash = fwName.Item2;

                    // cleanup expired rules
                    if (expiration < currtime)
                    {
                        try
                        {
                            F2B.Firewall.Instance.Remove(filterId);
                            Log.Info("Refresh: Removed expired filter rule #" + filterId);
                        }
                        catch (Exception ex)
                        {
                            Log.Warn("Refresh: Unable to remove expired filter rule #" + filterId + ": " + ex.Message);
                            //fail++;
                        }
                        continue;
                    }

                    // cleanup rules with same hash
                    long expirationOld;
                    if (expire.TryGetValue(hash, out expirationOld))
                    {
                        UInt64 filterIdOld = cleanup[expirationOld];
                        UInt64 filterIdRemove = (expiration < expirationOld ? filterId : filterIdOld);
                        try
                        {
                            F2B.Firewall.Instance.Remove(filterIdRemove);
                            Log.Info("Refresh: Removed older filter rule #" + filterId);
                        }
                        catch (Exception ex)
                        {
                            Log.Warn("Refresh: Unable to remove older rule #" + filterIdRemove + ": " + ex.Message);
                            //fail++;
                        }

                        if (expiration < expirationOld)
                        {
                            Log.Info("Refresh: Skipping older (removed) filter rule");
                            continue;
                        }
                        else
                        {
                            data.Remove(filterIdOld);
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

                    Log.Info("Refresh: Add filter rule e/f/h: " + expiration + "/" + filterId + "/" + BitConverter.ToString(hash).Replace("-", ":"));
                    data[filterId] = hash;
                    expire[hash] = expiration;
                    cleanup[expiration] = filterId;
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
            IList<KeyValuePair<long, UInt64>> remove = new List<KeyValuePair<long, UInt64>>();

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
                    UInt64 filterId = item.Value;
                    byte[] hash = data[filterId];

                    cleanup.Remove(expiration);
                    expire.Remove(hash);
                    data.Remove(filterId);
                }

                sizeAfter = data.Count;
            }

            Log.Info("CleanupExpired: Removed " + remove.Count + " F2B filter rules (data size " + sizeBefore + " -> " + sizeAfter + ")");

            int fail = 0;
            foreach (var item in remove)
            {
                UInt64 filterId = item.Value;
                try
                {
                    F2B.Firewall.Instance.Remove(filterId);
                    Log.Info("CleanupExpired: Removed filter rule #" + filterId);
                }
                catch (FirewallException ex)
                {
                    Log.Warn("CleanupExpired: Unable to remove filter rule #" + filterId + ": " + ex.Message);
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


        private void Add(string filter, long expiration, byte[] hash, FirewallConditions conds, UInt64 weight, bool permit, bool persistent, Func<string, FirewallConditions, UInt64, bool, bool, ulong> AddFilter)
        {
            long currtime = DateTime.UtcNow.Ticks;
            string filterName = FwData.EncodeName(expiration, hash);

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
                UInt64 filterId = 0;
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
                        UInt64 filterIdOld = cleanup[expirationOld];

                        Log.Info("Replace old filter #" + filterIdOld + " with increased expiration time (c/o/e=" + currtime + "/" + expirationOld + "/" + expiration + ")");
                        try
                        {
                            filterId = AddFilter(filterName, conds, weight, permit, persistent);
                            Log.Info("Added filter rule #" + filterId + ": " + filter);
                            F2B.Firewall.Instance.Remove(filterIdOld);
                            Log.Info("Removed filter rule #" + filterIdOld);
                        }
                        catch (FirewallException ex)
                        {
                            Log.Warn("Unable to replace filter rule #" + filterId + ": " + ex.Message);
                            //fail++;
                        }

                        if (filterId != 0) // no exception during rule addition
                        {
                            data.Remove(filterIdOld);
                            expire.Remove(hash); // not necessary
                            cleanup.Remove(expirationOld);
                        }
                    }
                }
                else
                {
                    if (MaxSize == 0 || MaxSize > data.Count)
                    {
                        try
                        {
                            filterId = AddFilter(filterName, conds, weight, permit, persistent);
                            Log.Info("Added new filter #" + filterId + ": " + filter);
                        }
                        catch (FirewallException ex)
                        {
                            Log.Warn("Unable to add filter " + filter + ": " + ex.Message);
                            //fail++;
                        }
                    }
                    else
                    {
                        Log.Warn("Reached limit for number of active F2B filter rules, skipping new additions");
                    }
                }

                if (filterId != 0)
                {
                    data[filterId] = hash;
                    expire[hash] = expiration;
                    cleanup[expiration] = filterId;

                    if (!tCleanupExpired.Enabled)
                    {
                        Log.Info("Enabling cleanup timer (interval " + tCleanupExpired.Interval + " ms)");
                        tCleanupExpired.Enabled = true;
                    }
                }
            } // dataLock
        }


        public void Add(FwData fwdata, UInt64 weight = 0, bool permit = false, bool persistent = false)
        {
            long expiration = fwdata.Expire;
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

            byte[] hash = fwdata.Hash;
            FirewallConditions conds = fwdata.Conditions();

            // IPv4 filter layer
            if (conds.HasIPv4() || (!conds.HasIPv4() && !conds.HasIPv6()))
            {
                byte[] hash4 = new byte[hash.Length];
                hash.CopyTo(hash4, 0);
                hash4[hash4.Length - 1] &= 0xfe;
                Add(fwdata.ToString(), expiration, hash4, conds, weight, permit, persistent, F2B.Firewall.Instance.AddIPv4);
            }

            // IPv6 filter layer
            if (conds.HasIPv6() || (!conds.HasIPv4() && !conds.HasIPv6()))
            {
                byte[] hash6 = new byte[hash.Length];
                hash.CopyTo(hash6, 0);
                hash6[hash6.Length - 1] |= 0x01;
                Add(fwdata.ToString(), expiration, hash6, conds, weight, permit, persistent, F2B.Firewall.Instance.AddIPv6);
            }
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
                    UInt64 filterId = item.Value;
                    byte[] hash = data[filterId];

                    output.WriteLine("  e/f/h: {0}/{1}/{2}", expiration, filterId, BitConverter.ToString(hash).Replace("-", ":"));
                }
            }
        }
#endif
    }
}
