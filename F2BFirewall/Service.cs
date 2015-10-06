using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Messaging;
using System.Net;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Threading;
using System.Timers;

namespace F2B
{
    public class Service : ServiceBase
    {
        #region Fields
        public static string NAME = "F2BFW";
        public static string DISPLAY = "Fail2ban Firewall Service";
        public static string DESCR = "Fail2ban firewall service reads message queue filled by Fail2ban and adds ban rules in Windows firewall.";
        #endregion

        private string computerName;
        private string producerQueue;
        private string registrationQueue;
        private int registrationInterval;
        private int cleanupExpiredInterval;
        private int maxFilterRules;

        private Thread tConsumption = null;
        private System.Timers.Timer tRegistration = null;
        private EventWaitHandle ewh;

        private volatile bool shutdown = false;
        private TimeSpan receiveTimeout;
        private TimeSpan timeToBeReceived;
        private bool registered = false;
        private Guid registrationUuid;

        public Service(string computerName, string producerQueue, string registrationQueue, int registrationInterval, int cleanupExpiredInterval, int maxFilterRules)
        {
            this.ServiceName = NAME;

            this.computerName = computerName;
            this.producerQueue = producerQueue;
            this.registrationQueue = registrationQueue;
            this.registrationInterval = registrationInterval;
            this.cleanupExpiredInterval = cleanupExpiredInterval;
            this.maxFilterRules = maxFilterRules;

            receiveTimeout = TimeSpan.FromMilliseconds(250);
            timeToBeReceived = TimeSpan.FromSeconds(registrationInterval);

            if (string.IsNullOrEmpty(computerName))
            {
                throw new ArgumentException("Machine name with message queues must be defined");
            }

            if (string.IsNullOrEmpty(producerQueue) && string.IsNullOrEmpty(registrationQueue))
            {
                throw new ArgumentException("Producer or registration queue must be specified");
            }

            if (!string.IsNullOrEmpty(producerQueue) && !string.IsNullOrEmpty(registrationQueue))
            {
                throw new ArgumentException("Only one queue can be specified (producer of registration)");
            }

            registrationUuid = Guid.NewGuid();
            if (!string.IsNullOrEmpty(registrationQueue) && registrationInterval > 0)
            {
                tRegistration = new System.Timers.Timer(registrationInterval * 1000);
                tRegistration.Elapsed += Registration;
            }

            if (string.IsNullOrEmpty(producerQueue))
            {
                this.producerQueue = "F2BFW_Subscriber_" + Dns.GetHostName() + "_" + registrationUuid.ToString();
            }

            F2B.FwManager.Instance.Interval = 1000 * cleanupExpiredInterval;
            F2B.FwManager.Instance.MaxSize = maxFilterRules;

            ewh = new EventWaitHandle(false, EventResetMode.ManualReset);
        }


        ~Service()
        {
            if (tRegistration != null)
            {
                if (tRegistration.Enabled)
                {
                    tRegistration.Enabled = false;
                }
                tRegistration.Dispose();
            }
        }


        protected override void OnStart(string[] args)
        {
            if (tRegistration != null)
            {
                Log.Info("Start registration timer");
                tRegistration.Enabled = true;
                Log.Info("Register immediately");
                RegUnreg(true);
            }

            Log.Info("Start consumptions thread");
            tConsumption = new Thread(new ThreadStart(ConsumptionThread));
            tConsumption.Start();
        }


        protected override void OnStop()
        {
            // send signal to service main thread
            shutdown = true;
            ewh.Set();

            Log.Info("Waiting for consumption thread to finish");
            tConsumption.Join();

            if (tRegistration != null)
            {
                if (registered)
                {
                    Log.Info("Disable registration timer");
                    tRegistration.Enabled = false;
                }
                Log.Info("Unsubscribe from producer");
                RegUnreg(false);
            }

            Log.Info("Service threads finished");
        }


        private void RegUnreg(bool register)
        {
            // create a message queue object
            string queueName = computerName + "\\Private$\\" + registrationQueue;
            MessageQueue msmq = new MessageQueue(queueName);

            Log.Info((register ? "Register" : "Unregister") + " in MSMQ " + queueName);

            // create the message and set the base properties
            Message msg = new Message();
            //Msg.ResponseQueue = new MessageQueue(ResponseMessageQueuePath);
            msg.Priority = MessagePriority.High;
            msg.UseJournalQueue = true;
            msg.Label = "Fail2ban F2BQueue registration for " + Dns.GetHostName() + " (PID " + Process.GetCurrentProcess().Id + ")";
            msg.TimeToBeReceived = timeToBeReceived;
            // we want a acknowledgement if received or not in the response queue
            //Msg.AcknowledgeType = AcknowledgeTypes.FullReceive;
            //Msg.AdministrationQueue = new MessageQueue(ResponseMessageQueuePath);

            BinaryWriter stream = new BinaryWriter(msg.BodyStream);
            stream.Write((byte)'F');
            stream.Write((byte)'2');
            stream.Write((byte)'B');
            if (register)
            {
                stream.Write((byte)F2B_DATA_TYPE_ENUM.F2B_FWQUEUE_SUBSCRIBE0);
            }
            else
            {
                stream.Write((byte)F2B_DATA_TYPE_ENUM.F2B_FWQUEUE_UNSUBSCRIBE0);
            }

            byte[] uuid = registrationUuid.ToByteArray();
            string dns = Dns.GetHostName();

            stream.Write(IPAddress.HostToNetworkOrder(dns.Length + uuid.Length + 2 * sizeof(int)));
            stream.Write(IPAddress.HostToNetworkOrder(dns.Length));
            stream.Write(dns.ToCharArray());
            stream.Write(IPAddress.HostToNetworkOrder(uuid.Length));
            stream.Write(uuid);

            // end of message
            stream.Write((byte)'F');
            stream.Write((byte)'2');
            stream.Write((byte)'B');
            stream.Write((byte)F2B_DATA_TYPE_ENUM.F2B_EOF);

            try
            {
                // send the message
                msmq.Send(msg);
                registered = register;
                Log.Info((register ? "Register" : "Unregister")
                    + " in MSMQ send to " + queueName + " (" + msg.Label + "): "
                    + producerQueue);
            }
            catch (MessageQueueException ex)
            {
                Log.Error("Unable to " + (register ? "register" : "unregister")
                    + " using queue " + queueName + ": " + ex.Message);
            }
            catch (Exception ex)
            {
                Log.Error(ex.ToString());
            }
            finally
            {
                // close the mesage queue
                msmq.Close();
            }
        }


        private void Registration(object sender, ElapsedEventArgs e)
        {
            if (tRegistration != null && !tRegistration.Enabled)
            {
                // this should prevent race condition, because elapsed
                // event is queued for execution on a thread poole thread
                return;
            }

            Log.Info("Registration timer triggered new subscription to F2BQueue producer queue");
            RegUnreg(true);
        }


        private void ConsumptionThread()
        {
            Log.Info("ConsumptionThread starting");

            int retryInterval = 250;
            LimitedLog ll = new LimitedLog(5, 1000);
            MessageQueue msmq = null;
            string queueName = computerName + "\\private$\\" + producerQueue;

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

                    processFwStream(msg.BodyStream);

                    ll.Reset();
                }
                catch (MessageQueueException ex)
                {
                    // Handle no message arriving in the queue. 
                    if (ex.MessageQueueErrorCode == MessageQueueErrorCode.IOTimeout)
                    {
                        ll.Msg("ConsumptionThread: No message arrived in queue.");
                    }
                    else if (ex.MessageQueueErrorCode == MessageQueueErrorCode.QueueDeleted)
                    {
                        Log.Info("ConsumptionThread: Message queue was deleted ... recreate");
                        msmq.Close();
                        msmq = null;
                    }
                    else if (ex.MessageQueueErrorCode == MessageQueueErrorCode.QueueNotFound)
                    {
                        ll.Msg("ConsumptionThread: Producer queue " + queueName + " not found: " + ex.Message);
                        // Let's way a bit...
                        ewh.WaitOne(retryInterval * (ll.Last < 10 ? ll.Last : 10));
                        ewh.Reset();
                    }
                    else
                    {
                        ll.Msg("ConsumptionThread: Unexpected MSMQ exception (code "
                            + ex.MessageQueueErrorCode + "): " + ex.Message);
                        // Let's way a bit...
                        ewh.WaitOne(retryInterval * (ll.Last < 10 ? ll.Last : 10));
                        ewh.Reset();
                    }
                }
                catch (EndOfStreamException)
                {
                    Log.Info("ConsumptionThread: Input data truncated");
                }
                catch (Exception ex)
                {
                    Log.Warn("ConsumptionThread: Unexpected exception: " + ex.Message);
                }

                //Log.Info("ConsumptionThread: loop cont(" + !shutdown + ")");
            }

            Log.Info("ConsumptionThread finished");
        }


        private void processFwStream(Stream stream)
        {
            BinaryReader binStream = new BinaryReader(stream);

            byte[] header = binStream.ReadBytes(4);
            if (header[0] != 'F' || header[1] != '2' || header[2] != 'B')
            {
                Log.Warn("ConsumptionThread: Invalid message header");
                return;
            }
            else if (header[3] == (byte)F2B_DATA_TYPE_ENUM.F2B_EOF)
            {
                Log.Info("ConsumptionThread: End of FwData");
                return;
            }
            else if (header[3] == (byte)F2B_DATA_TYPE_ENUM.F2B_GZIP)
            {
                Log.Info("ConsumptionThread: Processing message compressed FwData");

                int size = IPAddress.NetworkToHostOrder(binStream.ReadInt32()); // record size
                long pos = stream.Position;

                GZipStream innerStream = new GZipStream(stream, CompressionMode.Decompress);
                processFwStream(innerStream);
                innerStream.Dispose();

                if (stream.Position != pos + size)
                {
                    stream.Seek(pos + size, SeekOrigin.Current);
                }
            }
            if (header[3] == (byte)F2B_DATA_TYPE_ENUM.F2B_FWDATA_TYPE0)
            {
                Log.Info("ConsumptionThread: Processing message FwData");

                int size = IPAddress.NetworkToHostOrder(binStream.ReadInt32()); // record size
                byte[] buf = binStream.ReadBytes(size);
                FwData fwdata = new FwData(buf);
                F2B.FwManager.Instance.Add(fwdata);
            }
            else
            {
                Log.Warn("ConsumptionThread: Unknown message type: " + header[3]);

                int size = IPAddress.NetworkToHostOrder(binStream.ReadInt32()); // record size
                long pos = stream.Position;
                stream.Seek(pos + size, SeekOrigin.Current);
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
                output.WriteLine("FwManager:");
                FwManager.Instance.Debug(output);
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
