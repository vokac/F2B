using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Timers;

namespace F2B
{
    public enum F2B_DATA_TYPE_ENUM : byte
    {
        F2B_EOF,
        F2B_GZIP,
        F2B_FWDATA_TYPE0,
        F2B_FWQUEUE_SUBSCRIBE0,
        F2B_FWQUEUE_UNSUBSCRIBE0,
    };

    public enum F2B_FWDATA_TYPE0_ENUM : byte
    {
        F2B_FWDATA_EXPIRATION,
        F2B_FWDATA_IPv4, F2B_FWDATA_IPv4_AND_PREFIX, F2B_FWDATA_IPv4_RANGE,
        F2B_FWDATA_IPv6, F2B_FWDATA_IPv6_AND_PREFIX, F2B_FWDATA_IPv6_RANGE,
        F2B_FWDATA_PORT, F2B_FWDATA_PORT_RANGE, F2B_FWDATA_PROTOCOL,
    };


    public class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public bool Equals(byte[] left, byte[] right)
        {
            if (left == null || right == null)
            {
                return left == right;
            }
            return left.SequenceEqual(right);
        }
        public int GetHashCode(byte[] key)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }
            return key.Sum(b => b);
        }
    }


    public partial class FwData
    {
        private static readonly Dictionary<F2B_FWDATA_TYPE0_ENUM, int> DataSize = new Dictionary<F2B_FWDATA_TYPE0_ENUM, int>
        {
            { F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION, 1 + 8 },
            { F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4, 1 + 4 },
            { F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4_AND_PREFIX, 1 + 4 + 1 },
            { F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4_RANGE, 1 + 4 + 4 },
            { F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6, 1 + 16 },
            { F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6_AND_PREFIX, 1 + 16 + 1 },
            { F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6_RANGE, 1 + 16 + 16 },
            { F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_PORT, 1 + 2 },
            { F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_PORT_RANGE, 1 + 2 + 2 },
            { F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_PROTOCOL, 1 + 1 },
        };

        public long Expire { get; set; }

        private MemoryStream stream;
        private BinaryReader reader;
        private BinaryWriter writer;

        private byte[] cachedHash = null;

        public static long Expiration(byte[] data)
        {
            if (data.Length < DataSize[F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION])
            {
                throw new InvalidDataException("Truncated FwData data (can't get expiration time)");
            }

            if ((F2B_FWDATA_TYPE0_ENUM)data[0] != F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION)
            {
                throw new InvalidDataException("No expiration record at the beginning of FwData data");
            }

            return IPAddress.NetworkToHostOrder(BitConverter.ToInt64(data, 1));
        }

        public static byte[] GetHash(byte[] data)
        {
            if (data.Length < DataSize[F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION])
            {
                throw new InvalidDataException("Truncated FwData data (can't get expiration time)");
            }

            if ((F2B_FWDATA_TYPE0_ENUM)data[0] != F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION)
            {
                throw new InvalidDataException("No expiration record at the beginning of FwData data");
            }

            int expSize = DataSize[F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION];

            MD5 md5 = MD5.Create();
            return md5.ComputeHash(data, expSize, data.Length - expSize);
        }

        public static string EncodeName(long expiration, byte[] hash)
        {
            byte[] tmp = new byte[4 + 8 + hash.Length];
            byte[] exp = BitConverter.GetBytes(expiration);

            // header + version
            tmp[0] = (byte)'F';
            tmp[1] = (byte)'2';
            tmp[2] = (byte)'B';
            tmp[3] = 1; // version

            // encoded data
            Array.Copy(exp, 0, tmp, 4, exp.Length);
            Array.Copy(hash, 0, tmp, 4 + 8, hash.Length);

            return "F2B B64 " + Convert.ToBase64String(tmp);
        }

        public static Tuple<long, byte[]> DecodeName(string name)
        {
            if (!name.StartsWith("F2B B64 "))
            {
                throw new ArgumentException("Unable to parse FwData name (missing/invalid header): " + name);
            }

            try
            {
                byte[] tmp = Convert.FromBase64String(name.Substring(8));

                if (tmp.Length < 4)
                {
                    throw new ArgumentException("Unable to parse FwData name (data too short - header): " + name);
                }

                if (tmp[0] != 'F' || tmp[1] != '2' || tmp[2] != 'B')
                {
                    throw new ArgumentException("Unable to parse FwData name (invalid encoded header): " + name);
                }

                byte version = tmp[3];
                if (version == 1)
                {
                    if (tmp.Length < 4 + 8)
                    {
                        throw new ArgumentException("Unable to parse FwData name (data too short - expiration): " + name);
                    }
                    if (tmp.Length < 4 + 9)
                    {
                        throw new ArgumentException("Unable to parse FwData name (data too short - hash): " + name);
                    }

                    long expiration = BitConverter.ToInt64(tmp, 4);
                    byte[] hash = new byte[tmp.Length - 4 - 8];
                    Array.Copy(tmp, 4 + 8, hash, 0, hash.Length);

                    return new Tuple<long, byte[]>(expiration, hash);
                }
                else
                {
                    throw new ArgumentException("Unable to parse FwData name (unknown version " + tmp[0] + "): " + name);
                }
            }
            catch (FormatException ex)
            {
                throw new ArgumentException("Unable to parse FwData name from (" + ex.Message + "): " + name);
            }
        }


        public FwData(long expiration)
        {
            this.cachedHash = null;
            this.Expire = expiration;
            this.stream = new MemoryStream();
            this.reader = new BinaryReader(this.stream);
            this.writer = new BinaryWriter(this.stream);

            writer.Write((byte)F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION);
            writer.Write(IPAddress.HostToNetworkOrder(expiration));
        }

        public FwData(long expiration, IPAddress addr) : this(expiration)
        {
            Add(addr);
        }

        public FwData(long expiration, IPAddress addr, int prefix) : this(expiration)
        {
            Add(addr, prefix);
        }

        public FwData(long expiration, IPAddress addrLow, IPAddress addrHigh) : this(expiration)
        {
            Add(addrLow, addrHigh);
        }

        public FwData(long expiration, List<Tuple<F2B_FWDATA_TYPE0_ENUM, byte[]>> rules) : this(expiration)
        {
            if (rules == null)
                return;

            int cnt = 0;

            foreach (var item in rules)
            {
                cnt++;

                if (DataSize[item.Item1] != 1 + item.Item2.Length)
                {
                    throw new ArgumentException("Invalid rule #" + cnt
                        + " data size (" + (1 + item.Item2.Length) + " x "
                        + DataSize[item.Item1] + ") for data type " + item.Item1);
                }

                writer.Write((byte)item.Item1);
                writer.Write(item.Item2);
            }
        }

        public FwData(byte[] data)
        {
            this.cachedHash = null;
            this.Expire = Expiration(data);
            this.stream = new MemoryStream(data);
            this.reader = new BinaryReader(this.stream);
            this.writer = new BinaryWriter(this.stream);

            // validate input data
            int pos = DataSize[F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION];
            while (pos < data.Length)
            {
                int size = 0;
                DataSize.TryGetValue((F2B_FWDATA_TYPE0_ENUM)data[pos], out size);

                if (size == 0)
                {
                    // undefined size or unknown type
                    throw new InvalidDataException("Unknown FwData type or size: " + data[pos]);
                }

                if (!(data.Length >= pos + size))
                {
                    // Truncated data?!
                    throw new InvalidDataException("Truncated FwData data with type: " + data[pos]);
                }

                pos += size;
            }
        }

        public void Add(byte[] data)
        {
            if (data.Length == 0)
            {
                // skip empty data
                return;
            }

            int size = 0;
            F2B_FWDATA_TYPE0_ENUM type = (F2B_FWDATA_TYPE0_ENUM)data[0];
            if (!DataSize.TryGetValue(type, out size))
            {
                throw new ArgumentException("Unable to add rule with unknown type size: " + type);
            }

            cachedHash = null;

            writer.Write(data);
        }

        public void Add(F2B_FWDATA_TYPE0_ENUM type, byte[] data)
        {
            int size = 0;
            if (!DataSize.TryGetValue(type, out size))
            {
                throw new ArgumentException("Unable to add rule with unknown type size: " + type);
            }

            cachedHash = null;

            writer.Write((byte)type);
            writer.Write(data);
        }

        public void Add(IPAddress addr)
        {
            cachedHash = null;

            if (addr.IsIPv4MappedToIPv6)
            {
                addr = addr.MapToIPv4();
            }

            if (addr.AddressFamily == AddressFamily.InterNetwork)
            {
                writer.Write((byte)F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4);
            }
            else
            {
                writer.Write((byte)F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6);
            }
            writer.Write(addr.GetAddressBytes());
        }

        public void Add(IPAddress addr, int prefix)
        {
            cachedHash = null;

            if (addr.IsIPv4MappedToIPv6)
            {
                addr = addr.MapToIPv4();
                if (prefix >= 96)
                {
                    prefix -= 96;
                }
            }

            if (addr.AddressFamily == AddressFamily.InterNetwork)
            {
                writer.Write((byte)F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4_AND_PREFIX);
            }
            else
            {
                writer.Write((byte)F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6_AND_PREFIX);
            }
            writer.Write(addr.GetAddressBytes());
            writer.Write((byte)prefix);
        }

        public void Add(IPAddress addrLow, IPAddress addrHigh)
        {
            cachedHash = null;

            if (addrLow.IsIPv4MappedToIPv6)
            {
                addrLow = addrLow.MapToIPv4();
            }
            if (addrHigh.IsIPv4MappedToIPv6)
            {
                addrHigh = addrHigh.MapToIPv4();
            }

            if (addrLow.AddressFamily != addrHigh.AddressFamily)
            {
                throw new ArgumentException("Unable to add rule with mixed IPv4 and IPv6 range");
            }

            if (addrLow.AddressFamily == AddressFamily.InterNetwork)
            {
                writer.Write((byte)F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4_RANGE);
            }
            else
            {
                writer.Write((byte)F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6_RANGE);
            }
            writer.Write(addrLow.GetAddressBytes());
            writer.Write(addrHigh.GetAddressBytes());
        }

        public void Add(short port)
        {
            cachedHash = null;

            writer.Write((byte)F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_PORT);
            writer.Write(IPAddress.HostToNetworkOrder(port));
        }

        public void Add(short portLow, short portHigh)
        {
            cachedHash = null;

            writer.Write((byte)F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_PORT_RANGE);
            writer.Write(IPAddress.HostToNetworkOrder(portLow));
            writer.Write(IPAddress.HostToNetworkOrder(portHigh));
        }

        public void Add(ProtocolType protocol)
        {
            cachedHash = null;

            writer.Write((byte)F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_PROTOCOL);
            writer.Write((byte)protocol);
        }

        public byte[] ToArray()
        {
            return stream.ToArray();
        }

        public byte[] Hash
        {
            get
            {
                if (cachedHash == null)
                {
                    byte[] data = this.ToArray();
                    cachedHash = GetHash(data);
                }

                return cachedHash;
            }
        }

        public string Name()
        {
            byte[] data = this.ToArray();

            return EncodeName(Expire, GetHash(data));
        }

        public override string ToString()
        {
            StringBuilder ret = new StringBuilder();

            ret.Append("FwData[expiration=" + Expire + ",md5=" + BitConverter.ToString(this.Hash).Replace("-", ":") + "](");

            byte[] data = stream.ToArray();

            int pos = DataSize[F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION];
            while (pos < data.Length)
            {
                int size = 0;
                DataSize.TryGetValue((F2B_FWDATA_TYPE0_ENUM)data[pos], out size);

                // this is not necessary because we validate input data
                if (size == 0)
                {
                    // undefined size or unknown type
                    throw new InvalidDataException("Unknown FwData type or size: " + data[pos]);
                }

                if (!(data.Length >= pos + size))
                {
                    // Truncated data?!
                    throw new InvalidDataException("Truncated FwData data with type: " + data[pos]);
                }

                if (pos > DataSize[F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION])
                {
                    ret.Append(",");
                }

                // Create new firewall rule
                switch ((F2B_FWDATA_TYPE0_ENUM)data[pos])
                {
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION:
                        ret.Append("expiration=" + IPAddress.NetworkToHostOrder(BitConverter.ToInt64(data, pos + 1)));
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4:
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4_AND_PREFIX:
                        byte[] baddr4 = new byte[4];
                        Array.Copy(data, pos + 1, baddr4, 0, 4);
                        if ((F2B_FWDATA_TYPE0_ENUM)data[pos] == F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4)
                            ret.Append("address=" + new IPAddress(baddr4));
                        else
                            ret.Append("address=" + new IPAddress(baddr4) + "/" + data[pos + 1 + 4]);
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4_RANGE:
                        byte[] baddrLow4 = new byte[4];
                        byte[] baddrHigh4 = new byte[4];
                        Array.Copy(data, pos + 1, baddrLow4, 0, 4);
                        Array.Copy(data, pos + 1 + 4, baddrHigh4, 0, 4);
                        ret.Append("address=" + new IPAddress(baddrLow4) + "-" + new IPAddress(baddrHigh4));
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6:
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6_AND_PREFIX:
                        byte[] baddr6 = new byte[16];
                        Array.Copy(data, pos + 1, baddr6, 0, 16);
                        if ((F2B_FWDATA_TYPE0_ENUM)data[pos] == F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6)
                            ret.Append("address=" + new IPAddress(baddr6));
                        else
                            ret.Append("address=" + new IPAddress(baddr6) + "/" + data[pos + 1 + 4]);
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6_RANGE:
                        byte[] baddrLow6 = new byte[16];
                        byte[] baddrHigh6 = new byte[16];
                        Array.Copy(data, pos + 1, baddrLow6, 0, 16);
                        Array.Copy(data, pos + 1 + 4, baddrHigh6, 0, 16);
                        ret.Append("address=" + new IPAddress(baddrLow6) + "-" + new IPAddress(baddrHigh6));
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_PORT:
                        ret.Append("port=" + IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, pos + 1)));
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_PORT_RANGE:
                        ret.Append("port="
                            + IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, pos + 1))
                            + "-"
                            + IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, pos + 1 + 2)));
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_PROTOCOL:
                        ret.Append("protocol=" + (ProtocolType)data[pos + 1]);
                        break;
                    default:
                        ret.Append("unknown=" + data[pos]);
                        break;
                }

                pos += size;
            }

            ret.Append(")");

            return ret.ToString();
        }

#if DEBUG
        public void Debug(StreamWriter output)
        {
            string tmp = Convert.ToString(this.Expire);
            try
            {
                DateTime tmpExp = new DateTime(this.Expire, DateTimeKind.Utc);
                tmp = tmpExp.ToLocalTime().ToString();
            }
            catch (Exception)
            {
            }

            output.WriteLine("  FwData[expiration=" + Expire + " (" + tmp + "), md5=" + BitConverter.ToString(this.Hash).Replace("-", ":") + "]");

            byte[] data = stream.ToArray();

            int pos = DataSize[F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION];
            while (pos < data.Length)
            {
                int size = 0;
                DataSize.TryGetValue((F2B_FWDATA_TYPE0_ENUM)data[pos], out size);

                // this is not necessary because we validate input data
                if (size == 0)
                {
                    // undefined size or unknown type
                    throw new InvalidDataException("Unknown FwData type or size: " + data[pos]);
                }

                if (!(data.Length >= pos + size))
                {
                    // Truncated data?!
                    throw new InvalidDataException("Truncated FwData data with type: " + data[pos]);
                }

                // Create new firewall rule
                switch ((F2B_FWDATA_TYPE0_ENUM)data[pos])
                {
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_EXPIRATION:
                        output.WriteLine("    expiration: " + IPAddress.NetworkToHostOrder(BitConverter.ToInt64(data, pos + 1)));
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4:
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4_AND_PREFIX:
                        byte[] baddr4 = new byte[4];
                        Array.Copy(data, pos + 1, baddr4, 0, 4);
                        if ((F2B_FWDATA_TYPE0_ENUM)data[pos] == F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4)
                            output.WriteLine("    address: " + new IPAddress(baddr4));
                        else
                            output.WriteLine("    address: " + new IPAddress(baddr4) + "/" + data[pos + 1 + 4]);
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv4_RANGE:
                        byte[] baddrLow4 = new byte[4];
                        byte[] baddrHigh4 = new byte[4];
                        Array.Copy(data, pos + 1, baddrLow4, 0, 4);
                        Array.Copy(data, pos + 1 + 4, baddrHigh4, 0, 4);
                        output.WriteLine("    address: " + new IPAddress(baddrLow4) + "-" + new IPAddress(baddrHigh4));
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6:
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6_AND_PREFIX:
                        byte[] baddr6 = new byte[16];
                        Array.Copy(data, pos + 1, baddr6, 0, 16);
                        if ((F2B_FWDATA_TYPE0_ENUM)data[pos] == F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6)
                            output.WriteLine("    address: " + new IPAddress(baddr6));
                        else
                            output.WriteLine("    address: " + new IPAddress(baddr6) + "/" + data[pos + 1 + 4]);
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_IPv6_RANGE:
                        byte[] baddrLow6 = new byte[16];
                        byte[] baddrHigh6 = new byte[16];
                        Array.Copy(data, pos + 1, baddrLow6, 0, 16);
                        Array.Copy(data, pos + 1 + 4, baddrHigh6, 0, 16);
                        output.WriteLine("    address: " + new IPAddress(baddrLow6) + "-" + new IPAddress(baddrHigh6));
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_PORT:
                        output.WriteLine("    port: " + IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, pos + 1)));
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_PORT_RANGE:
                        output.WriteLine("    port: "
                            + IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, pos + 1))
                            + "-"
                            + IPAddress.NetworkToHostOrder(BitConverter.ToInt16(data, pos + 1 + 2)));
                        break;
                    case F2B_FWDATA_TYPE0_ENUM.F2B_FWDATA_PROTOCOL:
                        output.WriteLine("    protocol: " + (ProtocolType)data[pos + 1]);
                        break;
                    default:
                        output.WriteLine("    error: Unknown FwData type: " + data[pos]);
                        break;
                }

                pos += size;
            }
        }
#endif
    }
}
