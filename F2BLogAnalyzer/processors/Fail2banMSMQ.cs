#region Imports
using System;
using System.Collections.Generic;
using System.IO;
using System.Messaging;
using System.Net;
using System.Runtime.Caching;
#endregion

namespace F2B.processors
{
    enum F2B_DATA_TYPE_ENUM : byte
    {
        F2B_EOF,
        F2B_GZIP,
        F2B_FWDATA_TYPE0,
        F2B_FWQUEUE_SUBSCRIBE0,
        F2B_FWQUEUE_UNSUBSCRIBE0,
    };

    enum F2B_FWDATA_TYPE0_ENUM : byte
    {
        F2B_FWDATA_EXPIRATION,
        F2B_FWDATA_IPv4, F2B_FWDATA_IPv4_AND_PREFIX, F2B_FWDATA_IPv4_RANGE,
        F2B_FWDATA_IPv6, F2B_FWDATA_IPv6_AND_PREFIX, F2B_FWDATA_IPv6_RANGE,
        F2B_FWDATA_PORT, F2B_FWDATA_PORT_RANGE, F2B_FWDATA_PROTOCOL,
    };

    public class Fail2banMSMQProcessor : BaseProcessor, IThreadSafeProcessor
    {
        #region Fields
        private string queue_name;
        private int max_ignore;
        private int bantime;
        private int time_to_be_received;

        private MemoryCache recent;
        #endregion

        #region Constructors
        public Fail2banMSMQProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            if (config.Options["queue_name"] != null)
            {
                queue_name = config.Options["queue_name"].Value;
            }

            max_ignore = 60;
            if (config.Options["max_ignore"] != null)
            {
                max_ignore = int.Parse(config.Options["max_ignore"].Value);
            }

            bantime = 60;
            if (config.Options["bantime"] != null)
            {
                bantime = int.Parse(config.Options["bantime"].Value);
            }

            time_to_be_received = 300;
            if (config.Options["time_to_be_received"] != null)
            {
                bantime = int.Parse(config.Options["time_to_be_received"].Value);
            }

            //recent = new MemoryCache("F2B." + Name + ".recent");
            recent = new MemoryCache(GetType() + ".recent");
        }
        #endregion

        #region Override
        public override string Execute(EventEntry evtlog)
        {
            if (!evtlog.HasProcData("Fail2ban.address"))
            {
                throw new ArgumentException("Missing Fail2ban.address, invalid/misspelled configuration?!");
            }
            if (!evtlog.HasProcData("Fail2ban.prefix"))
            {
                throw new ArgumentException("Missing Fail2ban.prefix, invalid/misspelled configuration?!");
            }

            IPAddress addr = evtlog.GetProcData<IPAddress>("Fail2ban.address");
            int prefix = evtlog.GetProcData<int>("Fail2ban.prefix");
            int btime = evtlog.GetProcData("Fail2ban.bantime", bantime);

            // check in memory cache with recently send F2B messages
            string recentKey = null;
            long now = DateTimeOffset.Now.Ticks;
            if (max_ignore > 0)
            {
                recentKey = Name + "[" + addr + "/" + prefix + "]";
                object cacheEntry = recent[recentKey];

                if (cacheEntry != null)
                {
                    Tuple<long, int> item = (Tuple<long, int>)cacheEntry;
                    long ticksDiff = Math.Abs(item.Item1 - now);

                    if (ticksDiff < TimeSpan.FromSeconds(btime).Ticks / 100)
                    {
                        Log.Info("Skipping F2B firewall for recent address ("
                            + TimeSpan.FromTicks(ticksDiff).TotalSeconds + "s ago)");

                        return goto_next;
                    }
                }
            }

            if (!MessageQueue.Exists(queue_name))
            {
                MessageQueue newMsMq = MessageQueue.Create(queue_name);
                // set the label name and close the message queue
                newMsMq.Label = "Fail2ban log analyzer FWDATA production message queue";
                //newMsMq.AccessMode = QueueAccessMode.SendAndReceive;
                //newMsMq.Authenticate = true;
                //newMsMq.EncryptionRequired = EncryptionRequired.Body;
                //newMsMq.MaximumJournalSize = 10 * 1024;
                //newMsMq.MaximumQueueSize = ???;
                newMsMq.Close();
            }
            else
            {
                //  MessageQueue.Delete(queueName);
            }

            // create a message queue object
            MessageQueue msMq = new MessageQueue(queue_name);

            // create the message and set the base properties
            Message msg = new Message();
            //Msg.ResponseQueue = new MessageQueue(ResponseMessageQueuePath);
            msg.Priority = MessagePriority.Normal;
            msg.UseJournalQueue = true;
            msg.Label = "F2BFW";
            msg.TimeToBeReceived = TimeSpan.FromSeconds(time_to_be_received);
            // we want a acknowledgement if received or not in the response queue
            //Msg.AcknowledgeType = AcknowledgeTypes.FullReceive;
            //Msg.AdministrationQueue = new MessageQueue(ResponseMessageQueuePath);

            msg.BodyStream.WriteByte((byte)'F');
            msg.BodyStream.WriteByte((byte)'2');
            msg.BodyStream.WriteByte((byte)'B');
            msg.BodyStream.WriteByte((byte)F2B_DATA_TYPE_ENUM.F2B_FWDATA_TYPE0);

            long expiration = DateTime.UtcNow.Ticks + btime * 100L * 1000L * 1000L;

            //BinaryWriter stream = new BinaryWriter(msg.BodyStream);
            //MemoryStream memStream = new MemoryStream();
            //BinaryWriter dataStream = new BinaryWriter(memStream);
            //dataStream.Write((byte)F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION);
            //dataStream.Write(IPAddress.HostToNetworkOrder(expiration));
            //if (addr.IsIPv4MappedToIPv6)
            //{
            //    dataStream.Write((byte)F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4_AND_PREFIX);
            //    dataStream.Write(addr.MapToIPv4().GetAddressBytes());
            //    dataStream.Write((byte)(prefix - 96));
            //}
            //else
            //{
            //    dataStream.Write((byte)F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6_AND_PREFIX);
            //    dataStream.Write(addr.GetAddressBytes());
            //    dataStream.Write((byte)prefix);
            //}

            //stream.Write(IPAddress.HostToNetworkOrder((int)memStream.Length));
            //stream.Write(memStream.ToArray());

            F2B.FwData fwData = new F2B.FwData(expiration, addr, prefix);
            byte[] data = fwData.ToArray();
            int dataLengthNO = IPAddress.HostToNetworkOrder(data.Length);
            byte[] dataLenght = BitConverter.GetBytes(dataLengthNO);

            msg.BodyStream.Write(dataLenght, 0, dataLenght.Length);
            msg.BodyStream.Write(data, 0, data.Length);

            msg.BodyStream.WriteByte((byte)'F');
            msg.BodyStream.WriteByte((byte)'2');
            msg.BodyStream.WriteByte((byte)'B');
            msg.BodyStream.WriteByte((byte)F2B_DATA_TYPE_ENUM.F2B_EOF);

            try
            {
                // send the message
                msMq.Send(msg);
            }
            catch (MessageQueueException ee)
            {
                Log.Error(ee.ToString());
            }
            catch (Exception eee)
            {
                Log.Error(eee.ToString());
            }
            finally
            {
                // close the mesage queue
                msMq.Close();
            }

            // add this message to in memory cache of recently send F2B messages
            if (max_ignore > 0)
            {
                long bantimeTicks = TimeSpan.FromSeconds(btime).Ticks / 100;
                long expirationTicks = Math.Min(bantimeTicks, TimeSpan.FromSeconds(max_ignore).Ticks);
                TimeSpan expirationOffset = TimeSpan.FromTicks(expirationTicks);
                DateTimeOffset absoluteExpiration = DateTimeOffset.Now + expirationOffset;
                recent.Add(recentKey, new Tuple<long, int>(now, btime), absoluteExpiration);
            }

            return goto_next;
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            base.Debug(output);

            output.WriteLine("config msmq: " + queue_name);
            output.WriteLine("config max_ignore: " + max_ignore);
            output.WriteLine("config bantime: " + bantime);
            output.WriteLine("config time_to_be_received: " + time_to_be_received);
            output.WriteLine("status cache size: " + recent.GetCount());
        }
#endif
        #endregion
    }
}
