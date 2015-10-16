using System;
using System.Net;
using System.Net.Sockets;

namespace F2B
{
    public class Fixes
    {
        // Implementation of IPAddress.MapToIPv4 is buggy even in .Net 4.5.2
        // (this issue was probably fixed by an update, but it is safer not
        // to relay that target machine has latest updated .Net installation)
        public static IPAddress MapToIPv4(IPAddress addr)
        {
            if (addr.AddressFamily == AddressFamily.InterNetwork)
            {
                return addr;
            }

            byte[] bytes = addr.GetAddressBytes();
            long address = ((uint)bytes[12]) << 0 | ((uint)bytes[13]) << 8 | ((uint)bytes[14]) << 16 | ((uint)bytes[15]) << 24;

            return new IPAddress(address);
        }
    }
}
