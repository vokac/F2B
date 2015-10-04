using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace F2B
{
    public class Utils
    {
        public static Tuple<IPAddress, int> ParseNetwork(string network)
        {
            IPAddress addr;
            int prefix;

            int pos = network.LastIndexOf('/');
            if (pos == -1)
            {
                addr = IPAddress.Parse(network).MapToIPv6();
                prefix = 128;
            }
            else
            {
                addr = IPAddress.Parse(network.Substring(0, pos));
                prefix = int.Parse(network.Substring(pos + 1));
                if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    prefix += 96;
                }
                addr = addr.MapToIPv6();
            }

            return new Tuple<IPAddress, int>(addr, prefix);
        }

        public static IPAddress GetNetwork(IPAddress addr, int prefix)
        {
            byte[] addrBytes = addr.GetAddressBytes();

            if (addrBytes.Length != 16)
                throw new ArgumentException("Only IPv6 (or IPv6 mapped IPv4 addresses) supported.");

            for (int i = (prefix + 7) / 8; i < 16; i++)
            {
                addrBytes[i] = 0;
            }

            if (prefix % 8 != 0)
            {
                addrBytes[prefix / 8] &= (byte)(0xff << (8 - (prefix % 8)));
            }

            return new IPAddress(addrBytes);
        }

    }
}
