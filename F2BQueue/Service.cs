using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Messaging;
using System.Net;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Timers;

namespace F2B
{
    public class Service : ServiceBase
    {
        public static string NAME = "F2BQ";
        public static string DISPLAY = "Fail2ban Queue for Windows";
        public static string DESCR = "Provides message queue component of fail2ban services for Windows that can reconfigure firewall to reject clients that exceed failed login threshold.";

        private string computerName;
        private string producerQueue;
        private string registrationQueue;
        private int unsubscribeInterval;
        private int cleanupExpiredInterval;
        private int maxQueueSize;
        private string stateFile;

        private Thread tRegistration = null;
        private Thread tProduction = null;
        private System.Timers.Timer tUnsubscribe = null;
        private System.Timers.Timer tCleanupExpired = null;
        private EventWaitHandle ewh;

        private volatile bool shutdown = false;
        private TimeSpan receiveTimeout;
        private TimeSpan timeToBeReceived;
        private int maxAggregatedSize = 100 * 1024;
        private bool compressAggregatedData = false;

        // qdata[expiration] = (data, hash)
        // qhash[hash] = expiration
        private SortedDictionary<long, Tuple<byte[], byte[]>> qdata;
        private IDictionary<byte[], long> qhash;
        private IDictionary<MessageQueue, long> subscribers;

        private Object thisQDataLock = new Object();
        private Object thisSubscribersLock = new Object();

        public Service(string computerName, string producerQueue, string registrationQueue, int unsubscribeInterval, int cleanupExpiredInterval, int maxQueueSize, string stateFile)
        {
            this.ServiceName = NAME;

            this.computerName = computerName;
            this.producerQueue = producerQueue;
            this.registrationQueue = registrationQueue;
            this.unsubscribeInterval = unsubscribeInterval;
            this.cleanupExpiredInterval = cleanupExpiredInterval;
            this.maxQueueSize = maxQueueSize;
            this.stateFile = stateFile;

            receiveTimeout = TimeSpan.FromMilliseconds(250);
            timeToBeReceived = TimeSpan.FromSeconds(unsubscribeInterval);

            if (string.IsNullOrEmpty(computerName))
            {
                throw new ArgumentException("Machine name with message queues must be defined");
            }

            if (string.IsNullOrEmpty(producerQueue) || string.IsNullOrEmpty(registrationQueue))
            {
                throw new ArgumentException("Producer and registration queue must be specified");
            }

            qdata = new SortedDictionary<long, Tuple<byte[], byte[]>>();
            qhash = new Dictionary<byte[], long>(new ByteArrayComparer());
            subscribers = new Dictionary<MessageQueue, long>();

            if (unsubscribeInterval > 0)
            {
                tUnsubscribe = new System.Timers.Timer(unsubscribeInterval * 1000);
                tUnsubscribe.Elapsed += Unsubscribe;
            }

            if (cleanupExpiredInterval > 0)
            {
                tCleanupExpired = new System.Timers.Timer(cleanupExpiredInterval * 1000);
                tCleanupExpired.Elapsed += CleanupExpired;
            }

            ewh = new EventWaitHandle(false, EventResetMode.ManualReset);
        }


        ~Service()
        {
            if (tCleanupExpired != null)
            {
                if (tCleanupExpired.Enabled)
                {
                    tCleanupExpired.Enabled = false;
                }
                tCleanupExpired.Dispose();
            }

            if (tUnsubscribe != null)
            {
                if (tUnsubscribe.Enabled)
                {
                    tUnsubscribe.Enabled = false;
                }
                tUnsubscribe.Dispose();
            }
        }


        protected override void OnStart(string[] args)
        {
            if (stateFile != null)
            {
                Log.Info("Read state file: " + stateFile);
                ReadState(stateFile);
            }

            Log.Info("Start registration thread");
            tRegistration = new Thread(new ThreadStart(RegistrationThread));
            tRegistration.Start();

            Log.Info("Start production thread");
            tProduction = new Thread(new ThreadStart(ProductionThread));
            tProduction.Start();

            if (tUnsubscribe != null)
            {
                Log.Info("Start unsubscribe timer");
                tUnsubscribe.Enabled = true;
            }

            if (tCleanupExpired != null)
            {
                Log.Info("Start cleanup expired timer");
                tCleanupExpired.Enabled = true;
            }
        }


        protected override void OnStop()
        {
            // send signal to service main thread
            shutdown = true;
            ewh.Set();

            Log.Info("Waiting for registration thread to finish");
            tRegistration.Join();

            Log.Info("Waiting for production thread to finish");
            tProduction.Join();

            if (tUnsubscribe != null)
            {
                Log.Info("Disable unsubscribe timer");
                tUnsubscribe.Enabled = false;
            }

            if (tCleanupExpired != null)
            {
                Log.Info("Disable cleanup expired timer");
                tCleanupExpired.Enabled = false;
            }

            if (stateFile != null)
            {
                Log.Info("Write state file: " + stateFile);
                WriteState(stateFile);
            }

            Log.Info("Service threads finished");
        }


        private void Unsubscribe(object sender, ElapsedEventArgs e)
        {
            if (tUnsubscribe != null && !tUnsubscribe.Enabled)
            {
                // this should prevent race condition, because elapsed
                // event is queued for execution on a thread poole thread
                return;
            }

            long currTime = DateTime.UtcNow.Ticks;

            // cleanup empty / expired fail objects from "data" dictionary
            lock (thisSubscribersLock)
            {
                foreach (var s in subscribers.Where(kv => kv.Value + unsubscribeInterval * 100L * 1000L * 1000L < currTime).ToList())
                {
                    MessageQueue msmq = s.Key;

                    Log.Info("Unsubscribe: Removing subscriber with expired registration: "
                        + msmq.QueueName + " (" + msmq.Label + ")");

                    subscribers.Remove(msmq);
                    msmq.Close();
                    MessageQueue.Delete(msmq.QueueName);
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
            long currTime = DateTime.UtcNow.Ticks;

            Log.Info("CleanupExpired: Started");

            // cleanup empty / expired fail objects from "data" dictionary
            lock (thisQDataLock)
            {
                sizeBefore = qdata.Count;

                foreach (var s in qdata.Where(kv => kv.Key + cleanupExpiredInterval * 100L * 1000L * 1000L < currTime).ToList())
                {
                    byte[] hash = s.Value.Item2;
                    qhash.Remove(hash);
                    qdata.Remove(s.Key);
                }

                sizeAfter = qdata.Count;
            }

            Log.Info("CleanupExpired: Finished (records " + sizeBefore + " -> " + sizeAfter + ")");
        }


        private void SendData(MessageQueue msmq, string label, MemoryStream mstream, bool compress)
        {
            //
            Message msg = new Message();
            msg.Priority = MessagePriority.Normal;
            msg.UseJournalQueue = true;
            msg.Label = label;
            msg.TimeToBeReceived = timeToBeReceived;

            byte[] data = mstream.ToArray();
            if (compress)
            {
                msg.BodyStream.WriteByte((byte)'F');
                msg.BodyStream.WriteByte((byte)'2');
                msg.BodyStream.WriteByte((byte)'B');
                msg.BodyStream.WriteByte((byte)F2B_DATA_TYPE_ENUM.F2B_GZIP);

                int msgLenNO = IPAddress.HostToNetworkOrder(data.Length);
                msg.BodyStream.Write(BitConverter.GetBytes(msgLenNO), 0, 4);
            }
            msg.BodyStream.Write(data, 0, data.Length);

            // end of message
            msg.BodyStream.WriteByte((byte)'F');
            msg.BodyStream.WriteByte((byte)'2');
            msg.BodyStream.WriteByte((byte)'B');
            msg.BodyStream.WriteByte((byte)F2B_DATA_TYPE_ENUM.F2B_EOF);

            msmq.Send(msg);
        }


        private void SendAllData(MessageQueue subscriber)
        {
            Log.Info("SendAllData: Sending all data to new client " + subscriber.Path);

            int part = 0;
            byte[] msgHeader = new byte[] { (byte)'F', (byte)'2', (byte)'B', (byte)F2B_DATA_TYPE_ENUM.F2B_FWDATA_TYPE0 };
            long currTime = DateTime.UtcNow.Ticks;

            // push all state data to new subscriber
            lock (thisQDataLock)
            {
                Stream dataStream = null;
                MemoryStream mstream = null;

                foreach (var item in qdata)
                {
                    // skip expired data
                    if (item.Key < currTime)
                        continue;

                    byte[] data = item.Value.Item1;

                    if (dataStream != null)
                    {
                        if (dataStream.Length + data.Length > maxAggregatedSize)
                        {
                            SendData(subscriber, "F2BQueue aggregated data part " + part, mstream, compressAggregatedData);

                            dataStream.Dispose();
                            dataStream = null;
                        }
                    }

                    if (dataStream == null)
                    {
                        mstream = new MemoryStream();
                        if (compressAggregatedData)
                        {
                            dataStream = new GZipStream(mstream, CompressionMode.Compress);
                        }
                        else
                        {
                            dataStream = mstream;
                        }

                        part++;
                    }

                    int msgLenNO = IPAddress.HostToNetworkOrder(data.Length);
                    dataStream.Write(msgHeader, 0, msgHeader.Length);
                    dataStream.Write(BitConverter.GetBytes(msgLenNO), 0, 4);
                    dataStream.Write(data, 0, data.Length);
                }

                if (dataStream != null)
                {
                    SendData(subscriber, "F2BQueue aggregated data part " + part + " (last)", mstream, compressAggregatedData);

                    dataStream.Dispose();
                    dataStream = null;
                }
            }
        }


        private void RegistrationThread()
        {
            Log.Info("RegistrationThread starting");

            int retryInterval = 250;
            LimitedLog ll = new LimitedLog(5, 1000);
            MessageQueue msmq = null;
            string queueName = computerName + "\\private$\\" + registrationQueue;

            while (!shutdown)
            {
                if (msmq == null)
                {
                    msmq = new MessageQueue(queueName);
                    //msmq.Formatter = new XmlMessageFormatter(new Type[] { typeof(string) });
                }

                try
                {
                    // NOTE: we process only first F2B record from received message
                    // and ignore the rest (including F2B_EOF)
                    Message msg = msmq.Receive(receiveTimeout);
                    BinaryReader stream = new BinaryReader(msg.BodyStream);

                    byte[] header = stream.ReadBytes(4);
                    if (header[0] != 'F' || header[1] != '2' || header[2] != 'B')
                    {
                        Log.Info("RegistrationThread: Invalid message header");
                        continue;
                    }

                    if (header[3] != (byte) F2B_DATA_TYPE_ENUM.F2B_FWQUEUE_SUBSCRIBE0 && header[3] != (byte)F2B_DATA_TYPE_ENUM.F2B_FWQUEUE_UNSUBSCRIBE0)
                    {
                        Log.Info("RegistrationThread: Invalid message type");
                        continue;
                    }

                    bool reg = header[3] == (byte)F2B_DATA_TYPE_ENUM.F2B_FWQUEUE_SUBSCRIBE0;
                    int size = IPAddress.NetworkToHostOrder(stream.ReadInt32()); // message size
                    BinaryReader data = new BinaryReader(new MemoryStream(stream.ReadBytes(size)));

                    int dnsSize = IPAddress.NetworkToHostOrder(data.ReadInt32());
                    string dns = Encoding.Default.GetString(data.ReadBytes(dnsSize));
                    int uuidSize = IPAddress.NetworkToHostOrder(data.ReadInt32());
                    Guid guid = new Guid(data.ReadBytes(uuidSize));

                    string subscriberQueueName = ".\\Private$\\F2BFW_Subscriber_" + dns + "_" + guid.ToString();

                    Log.Info("RegistrationThread: " + (reg ? "Register" : "Unregister")
                        + " client " + subscriberQueueName + " (" + msg.Label + ")");

                    bool sendAllData = false;
                    MessageQueue subscriber = null;
                    lock (thisSubscribersLock)
                    {
                        // check if we already registered queue with given name
                        foreach (var item in subscribers)
                        {
                            if (item.Key.Path == subscriberQueueName)
                            {
                                subscriber = item.Key;
                                break;
                            }
                        }

                        if (reg) // subscription request / refresh
                        {
                            // create new message queue for subscriber if it doesn't exists
                            if (!MessageQueue.Exists(subscriberQueueName))
                            {
                                MessageQueue newMsMq = MessageQueue.Create(subscriberQueueName);
                                // set the label name and close the message queue
                                newMsMq.Label = msg.Label;
                                //newMsMq.AccessMode = QueueAccessMode.SendAndReceive;
                                //newMsMq.Authenticate = true;
                                //newMsMq.EncryptionRequired = EncryptionRequired.Body;
                                //newMsMq.MaximumJournalSize = 10 * 1024;
                                //newMsMq.MaximumQueueSize = ???;
                                // TODO: privileges
                                newMsMq.Close();
                            }

                            if (subscriber == null)
                            {
                                subscriber = new MessageQueue(subscriberQueueName);
                                subscribers.Add(subscriber, DateTime.UtcNow.Ticks);
                                sendAllData = true;
                            }
                            else
                            {
                                subscribers[subscriber] = DateTime.UtcNow.Ticks;
                            }

                        }
                        else // unsubscribe request
                        {
                            if (subscriber != null)
                            {
                                subscriber.Close();
                                subscribers.Remove(subscriber);
                            }

                            if (MessageQueue.Exists(subscriberQueueName))
                            {
                                MessageQueue.Delete(subscriberQueueName);
                            }
                        }
                    }

                    if (sendAllData)
                    {
                        SendAllData(subscriber);
                    }

                    ll.Reset();
                }
                catch (MessageQueueException ex)
                {
                    // Handle no message arriving in the queue. 
                    if (ex.MessageQueueErrorCode == MessageQueueErrorCode.IOTimeout)
                    {
                        //ll.Msg("RegistrationThread: No message arrived in queue.");
                    }
                    else if (ex.MessageQueueErrorCode == MessageQueueErrorCode.QueueDeleted)
                    {
                        Log.Info("RegistrationThread: Message queue was deleted ... recreate");
                        msmq.Close();
                        msmq = null;
                    }
                    else if (ex.MessageQueueErrorCode == MessageQueueErrorCode.QueueNotFound)
                    {
                        try
                        {
                            if (!MessageQueue.Exists(queueName))
                            {
                                MessageQueue msmqNew = MessageQueue.Create(queueName);
                                msmqNew.Label = "Fail2ban F2BQueue registration message queue";
                                msmqNew.Close();
                                Log.Info("RegistrationThread: Registration queue " + queueName + " created");
                            }
                            else
                            {
                                ll.Msg("RegistrationThread: Registration queue "
                                            + queueName + " inacceslible: " + ex.Message);
                                // Let's way a bit...
                                ewh.WaitOne(retryInterval * (ll.Last < 10 ? ll.Last : 10));
                                ewh.Reset();
                            }
                        }
                        catch (MessageQueueException ex1)
                        {
                            ll.Msg("RegistrationThread: Unable to create registration queue "
                                        + queueName + ": " + ex1.Message);
                            // Let's way a bit...
                            ewh.WaitOne(retryInterval * (ll.Last < 10 ? ll.Last : 10));
                            ewh.Reset();
                        }
                    }
                    else
                    {
                        ll.Msg("RegistrationThread: Unexpected MSMQ exception (code "
                            + ex.MessageQueueErrorCode + "): " + ex.Message);
                        // Let's way a bit...
                        ewh.WaitOne(retryInterval * (ll.Last < 10 ? ll.Last : 10));
                        ewh.Reset();
                    }
                }
                catch (EndOfStreamException)
                {
                    Log.Info("RegistrationThread: Input data truncated");
                }

                Log.Info("RegistrationThread loop cont(" + !shutdown + ")");
            }

            Log.Info("RegistrationThread finished");
        }


        private void ProductionThread()
        {
            Log.Info("ProductionThread starting");

            int retryInterval = 250;
            LimitedLog ll = new LimitedLog(5, 1000);
            MessageQueue msmq = null;
            string queueName = computerName + "\\Private$\\" + producerQueue;

            while (!shutdown)
            {
                if (msmq == null)
                {
                    msmq = new MessageQueue(queueName);
                    //msmq.Formatter = new XmlMessageFormatter(new Type[] { typeof(string) });
                }

                try
                {
                    Message msg = msmq.Receive(receiveTimeout);
                    BinaryReader istream = new BinaryReader(msg.BodyStream);

                    byte[] header = istream.ReadBytes(4);
                    if (header[0] != 'F' || header[1] != '2' || header[2] != 'B')
                    {
                        Log.Info("ProductionThread: Invalid message header");
                        continue;
                    }

                    int recordSize = IPAddress.NetworkToHostOrder(istream.ReadInt32());

                    if (header[3] == (byte) F2B_DATA_TYPE_ENUM.F2B_FWDATA_TYPE0)
                    {
                        // put message in all subscriber queues
                        byte[] data = istream.ReadBytes(recordSize);
                        long expiration = FwData.Expiration(data);
                        byte[] hash = FwData.GetHash(data);

                        if (expiration < DateTime.UtcNow.Ticks)
                        {
                            Log.Info("ProductionThread: Invalid message expiration (expired)");
                            continue;
                        }

                        lock (thisQDataLock)
                        {
                            // we need unique expiration time to keep all required
                            // data in simple key/value hashmap structure (and we
                            // really don't care about different expiration time in ns)
                            while (qdata.ContainsKey(expiration))
                            {
                                expiration++;
                            }

                            long expirationOld = 0;
                            if (qhash.TryGetValue(hash, out expirationOld))
                            {
                                if (expirationOld > expiration)
                                {
                                    // same data with longer expiration time already exists
                                    continue;
                                }
                            }

                            if (expirationOld != 0 || maxQueueSize == 0 || maxQueueSize > qdata.Count)
                            {
                                qdata[expiration] = new Tuple<byte[], byte[]>(data, hash);
                                qhash[hash] = expiration;

                                if (expirationOld != 0)
                                {
                                    // remove data with older expiration time
                                    qdata.Remove(expirationOld);
                                }
                            }
                            else
                            {
                                Log.Warn("Reached maximum number of F2B filter rules, skiping filter addition");
                            }
                        }

                        Log.Info("ProductionThread: Resubmit received message to " + subscribers.Count + " subscribers (expiration=" + expiration + ")");

                        foreach (MessageQueue subscriber in subscribers.Keys)
                        {
                            // create the message and set the base properties
                            Message msgs = new Message();
                            msgs.Priority = MessagePriority.Normal;
                            msgs.UseJournalQueue = true;
                            msgs.Label = msg.Label;
                            msgs.TimeToBeReceived = timeToBeReceived;

                            BinaryWriter ostream = new BinaryWriter(msgs.BodyStream);
                            ostream.Write(header);
                            ostream.Write(IPAddress.HostToNetworkOrder(data.Length));
                            ostream.Write(data);

                            subscriber.Send(msgs);
                        }
                    }
                    else
                    {
                        Log.Error("ProductionThread: Unknown message type " + header[3]);
                    }

                    ll.Reset();
                }
                catch (MessageQueueException ex)
                {
                    // Handle no message arriving in the queue. 
                    if (ex.MessageQueueErrorCode == MessageQueueErrorCode.IOTimeout)
                    {
                        //ll.Msg("ProductionThread: No message arrived in queue.");
                    }
                    else if (ex.MessageQueueErrorCode == MessageQueueErrorCode.QueueDeleted)
                    {
                        Log.Info("ProductionThread: Message queue was deleted ... recreate");
                        msmq.Close();
                        msmq = null;
                    }
                    else if (ex.MessageQueueErrorCode == MessageQueueErrorCode.QueueNotFound)
                    {
                        try
                        {
                            if (!MessageQueue.Exists(queueName))
                            {
                                MessageQueue msmqNew = MessageQueue.Create(queueName);
                                msmqNew.Label = "Fail2ban F2BQueue FWDATA production message queue";
                                msmqNew.Close();
                                Log.Info("ProductionThread: Production queue " + queueName + " created");
                            }
                            else
                            {
                                ll.Msg("ProductionThread: Production queue "
                                            + queueName + " inacceslible: " + ex.Message);
                                // Let's way a bit...
                                ewh.WaitOne(retryInterval * (ll.Last < 10 ? ll.Last : 10));
                                ewh.Reset();
                            }
                        }
                        catch (MessageQueueException ex1)
                        {
                            ll.Msg("ProductionThread: Unable to create production queue "
                                        + queueName + ": " + ex1.Message);
                            // Let's way a bit...
                            ewh.WaitOne(retryInterval * (ll.Last < 10 ? ll.Last : 10));
                            ewh.Reset();
                        }
                    }
                    else
                    {
                        ll.Msg("ProductionThread: Unexpected MSMQ exception (code "
                            + ex.MessageQueueErrorCode + "): " + ex.Message);
                        // Let's way a bit...
                        ewh.WaitOne(retryInterval * (ll.Last < 10 ? ll.Last : 10));
                        ewh.Reset();
                    }
                }
                catch (EndOfStreamException)
                {
                    Log.Info("ProductionThread: Input data truncated");
                }

                Log.Info("ProductionThread loop cont(" + !shutdown + ")");
            }

            Log.Info("ProductionThread finished");
        }


        public void ReadState(string stateFile)
        {
            Log.Info("ReadState from " + stateFile);

            long currTime = DateTime.UtcNow.Ticks;

            lock (thisQDataLock)
            {
                using (Stream fileStream = new FileStream(stateFile, FileMode.Open, FileAccess.Read))
                {
                    BinaryReader stream = new BinaryReader(new GZipStream(fileStream, CompressionMode.Decompress));
                    //Stream stream = new GZipStream(fileStream, CompressionMode.Decompress);

                    while (stream.PeekChar() > 0)
                    {
                        //byte[] header = new byte[4];
                        //stream.Read(header, 0, 4);
                        byte[] header = stream.ReadBytes(4);
                        int size = IPAddress.NetworkToHostOrder(stream.ReadInt32());
                        if (header[0] != 'F' || header[1] != '2' && header[2] != 'B')
                        {
                            Log.Error("Invalid message header");
                            // exception?!
                        }

                        byte[] data = stream.ReadBytes(size);
                        if (header[3] != (byte)F2B_DATA_TYPE_ENUM.F2B_FWDATA_TYPE0)
                        {
                            Log.Error("Invalid data type: " + header[3]);
                            continue;
                        }

                        long expiration = FwData.Expiration(data);
                        byte[] hash = FwData.GetHash(data);

                        if (expiration < currTime)
                        {
                            Log.Info("Invalid message expiration (expired)");
                            continue;
                        }

                        // we need unique expiration time to keep all required
                        // data in simple key/value hashmap structure (and we
                        // really don't care about different expiration time in ns)
                        while (qdata.ContainsKey(expiration))
                        {
                            expiration++;
                        }

                        long expirationOld = 0;
                        if (qhash.TryGetValue(hash, out expirationOld))
                        {
                            if (expirationOld > expiration)
                            {
                                // same data with longer expiration time already exists
                                continue;
                            }
                        }

                        if (expirationOld != 0 || maxQueueSize == 0 || maxQueueSize > qdata.Count)
                        {
                            qdata[expiration] = new Tuple<byte[], byte[]>(data, hash);
                            qhash[hash] = expiration;

                            if (expirationOld != 0)
                            {
                                // remove data with older expiration time
                                qdata.Remove(expirationOld);
                            }
                        }
                        else
                        {
                            Log.Warn("Reached maximum number of F2B filter rules, skiping filter addition");
                        }
                    }
                }
            }
        }


        public void WriteState(string stateFile)
        {
            Log.Info("WriteState to " + stateFile);

            byte[] msgHeader = new byte[] { (byte)'F', (byte)'2', (byte)'B', (byte)F2B_DATA_TYPE_ENUM.F2B_FWDATA_TYPE0 };
            long currTime = DateTime.UtcNow.Ticks;

            lock (thisQDataLock)
            {
                using (Stream fileStream = new FileStream(stateFile, FileMode.Create, FileAccess.Write))
                {
                    Stream stream = new GZipStream(fileStream, CompressionMode.Compress);

                    //fileStream.WriteByte((byte)'F');
                    //fileStream.WriteByte((byte)'2');
                    //fileStream.WriteByte((byte)'B');
                    //fileStream.WriteByte((byte)F2B_DATA_TYPE_ENUM.F2B_GZIP);
                    //fileStream.Write(BitConverter.GetBytes(0), 0, 4);

                    // records with highest expiration are written at the beginning
                    // (in case we use smaler maxQueueSize in next run)
                    foreach (var item in qdata.Reverse())
                    {
                        // skip expired data
                        if (item.Key < currTime)
                            continue;

                        byte[] data = item.Value.Item1;

                        int msgLenNO = IPAddress.HostToNetworkOrder(data.Length);
                        stream.Write(msgHeader, 0, msgHeader.Length);
                        stream.Write(BitConverter.GetBytes(msgLenNO), 0, 4);
                        stream.Write(data, 0, data.Length);
                    }

                    // end of message
                    //fileStream.WriteByte((byte)'F');
                    //fileStream.WriteByte((byte)'2');
                    //fileStream.WriteByte((byte)'B');
                    //fileStream.WriteByte((byte)F2B_DATA_TYPE_ENUM.F2B_EOF);
                }
            }
        }


#if DEBUG
        public void Dump()
        {
            Log.Info("Dump service debug info");
            string debugFile = @"c:\f2b\dump.txt";
            StreamWriter output = null;
            try
            {
                output = new StreamWriter(new FileStream(debugFile, FileMode.Append));
                output.WriteLine("======================================================================");
                output.WriteLine("Timestamp: " + DateTime.Now + " (UTC " + DateTime.UtcNow.Ticks + ")");
                output.WriteLine("Subscribers:");
                lock (thisSubscribersLock)
                {
                    foreach (var item in subscribers)
                    {
                        MessageQueue mq = item.Key;
                        output.WriteLine(mq.Path);
                    }
                }
                output.WriteLine("QData:");
                lock (thisQDataLock)
                {
                    foreach (var item in qdata)
                    {
                        output.WriteLine("  expiration key: " + item.Key);

                        FwData fwdata = new FwData(item.Value.Item1);
                        fwdata.Debug(output);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error("Unable to dump debug info (" + debugFile + "): " + ex.ToString());
            }
            finally
            {
                if (output != null)
                {
                    output.Close();
                }
            }
        }
#endif
    }
}
