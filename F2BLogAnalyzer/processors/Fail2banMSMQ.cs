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
    public class Fail2banMSMQProcessor : Fail2banActionProcessor, IThreadSafeProcessor
    {
        #region Fields
        private string queue_name;
        private int time_to_be_received;
        #endregion

        #region Constructors
        public Fail2banMSMQProcessor(ProcessorElement config, Service service)
            : base(config, service)
        {
            if (config.Options["queue_name"] != null)
            {
                queue_name = config.Options["queue_name"].Value;
            }

            time_to_be_received = 300;
            if (config.Options["time_to_be_received"] != null)
            {
                time_to_be_received = int.Parse(config.Options["time_to_be_received"].Value);
            }
        }
        #endregion

        #region Override
        protected override void ExecuteFail2banAction(EventEntry evtlog, IPAddress addr, int prefix, long expiration)
        {
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
        }

#if DEBUG
        public override void Debug(StreamWriter output)
        {
            output.WriteLine("config msmq: " + queue_name);
            output.WriteLine("config time_to_be_received: " + time_to_be_received);
            base.Debug(output);
        }
#endif
        #endregion
    }
}
