using System.Net;

namespace ARPSpoofing
{
    public class IPObject
    {
        public byte[] IPBytes { get; private set; }

        public IPAddress IPAddress
        {
            get
            {
                return new IPAddress(IPBytes);
            }
        }

        public IPObject(IPAddress ip)
        {
            IPBytes = ip.GetAddressBytes();
        }

        public void AddOne()
        {
            int i = 3;
            while (i >= 0)
            {
                if (IPBytes[i] == 255)
                {
                    IPBytes[i] = 0;
                    i--;
                }
                else
                {
                    IPBytes[i]++;
                    break;
                }
            }
        }

        public override bool Equals(object obj)
        {
            var ret = true;
            var ip = obj as IPObject;
            for (int i = 0; i < IPBytes.Length; ++i)
            {
                if (ip.IPBytes[i] != IPBytes[i])
                    ret =  false;
            }

            return ret;

        }
        public bool SmallerThan(IPObject ip)
        {
            return IP2ulong() <= ip.IP2ulong();
        }

        /// <summary>
        /// ip地址转long
        /// </summary>
        /// <param name="ipAddress"></param>
        /// <returns></returns>
        private ulong IP2ulong()
        {
            ulong ret = 0;

            foreach (byte b in IPBytes)
            {
                ret <<= 8;
                ret |= b;
            }

            return ret;
        }
    }
}
