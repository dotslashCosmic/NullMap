// Author: dotslashCosmic
using System;
using System.Collections.Generic;
using System.Net.Security;
using PacketDotNet;
using SharpPcap;
/*TODO
evasion: fragmenting packets, using decoy packets, and spoofing IP addresses.
detect version/os detection scanning activities by analyzing the packet headers and payload,
port scanning activities by monitoring incoming packets and identifying the scan patterns,
then give warning to user of 'scan in progress'.
toggle for creating a fake network environment in its entirety- like a cloned virtual network in a container
*/
class AntiNmapSpoofer
{
    private static ICaptureDevice device;
    private static Dictionary<int, bool> portStates = new Dictionary<int, bool>();
    private static Dictionary<int, (string Resolve, int Delay)> tracerouteHops;
    private static string spoofedOS = "Linux";
    private static string spoofedServiceInfo = "Apache 2.4";
    private static string spoofedTraceroute = "Hop 1";

    public static void Main(string[] args)
    {
        SetupDevice();
        StartCapture();
        
        Console.WriteLine("Anti-Nmap Spoofer Configuration");
        Console.WriteLine("1. Toggle Ports");
        Console.WriteLine("2. Spoof OS Detection");
        Console.WriteLine("3. Spoof Service Info");
        Console.WriteLine("4. Spoof Traceroute");
        Console.WriteLine("5. Start Spoofing");
        Console.WriteLine("6. Exit");

        while (true)
        {
            Console.Write("Select option: ");
            var input = Console.ReadLine();

            switch (input)
            {
                case "1":
                    TogglePorts();
                    break;
                case "2":
                    SpoofOsDetection();
                    break;
                case "3":
                    SpoofServiceInfo();
                    break;
                case "4":
                    SpoofTraceroute();
                    break;
                case "5":
                    RunSpoofing();
                    break;
                case "6":
                    return;
            }
        }
    }

    private static void SetupDevice()
    {
        var devices = CaptureDeviceList.Instance;
        if (devices.Count < 1)
        {
            Console.WriteLine("No devices found on this machine.");
            return;
        }

        device = devices[0]; // Select the first device
        device.OnPacketArrival += new PacketArrivalEventHandler(OnPacketArrival);
        device.Open(DeviceMode.Promiscuous, 1000);
    }

    private static void StartCapture()
    {
        Console.WriteLine("Starting packet capture...");
        device.StartCapture();
    }

    private static void OnPacketArrival(object sender, CaptureEventArgs e)
    {
        var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
        var tcpPacket = packet.Extract<TcpPacket>();

        if (tcpPacket != null)
        {
            Console.WriteLine($"Captured TCP packet: {tcpPacket.SourcePort} -> {tcpPacket.DestinationPort}");
            HandleTcpPacket(tcpPacket, packet);
        }
    }

    private static void HandleTcpPacket(TcpPacket tcpPacket, Packet packet)
    {
        if (tcpPacket.Syn && !tcpPacket.Ack)
        {
            if (portStates.ContainsKey(tcpPacket.DestinationPort) && portStates[tcpPacket.DestinationPort])
            {
                SendSpoofedSynAck(tcpPacket, packet); // Spoof open port
            }
            else
            {
                SendSpoofedRst(tcpPacket, packet); // Spoof closed port
            }
        }
    }

    private static void SendSpoofedSynAck(TcpPacket tcpPacket, Packet packet)
    {
        var ipPacket = packet.Extract<IpPacket>();
        var ethernetPacket = (EthernetPacket)packet;

        var srcIp = ipPacket.DestinationAddress;
        var dstIp = ipPacket.SourceAddress;
        var srcPort = tcpPacket.DestinationPort;
        var dstPort = tcpPacket.SourcePort;

        var spoofedTcpPacket = new TcpPacket(srcPort, dstPort)
        {
            Syn = true,
            Ack = true,
            SequenceNumber = tcpPacket.AcknowledgmentNumber,
            AcknowledgmentNumber = tcpPacket.SequenceNumber + 1,
            WindowSize = tcpPacket.WindowSize
        };

        var spoofedIpPacket = new IPv4Packet(srcIp, dstIp)
        {
            PayloadPacket = spoofedTcpPacket
        };

        var spoofedEthernetPacket = new EthernetPacket(ethernetPacket.DestinationHwAddress, ethernetPacket.SourceHwAddress, EthernetPacketType.IpV4)
        {
            PayloadPacket = spoofedIpPacket
        };

        device.SendPacket(spoofedEthernetPacket);
    }

    private static void SendSpoofedRst(TcpPacket tcpPacket, Packet packet)
    {
        var ipPacket = packet.Extract<IpPacket>();
        var ethernetPacket = (EthernetPacket)packet;

        var srcIp = ipPacket.DestinationAddress;
        var dstIp = ipPacket.SourceAddress;
        var srcPort = tcpPacket.DestinationPort;
        var dstPort = tcpPacket.SourcePort;

        var spoofedTcpPacket = new TcpPacket(srcPort, dstPort)
        {
            Rst = true,
            Ack = true,
            SequenceNumber = tcpPacket.AcknowledgmentNumber,
            AcknowledgmentNumber = tcpPacket.SequenceNumber + 1
        };

        var spoofedIpPacket = new IPv4Packet(srcIp, dstIp)
        {
            PayloadPacket = spoofedTcpPacket
        };

        var spoofedEthernetPacket = new EthernetPacket(ethernetPacket.DestinationHwAddress, ethernetPacket.SourceHwAddress, EthernetPacketType.IpV4)
        {
            PayloadPacket = spoofedIpPacket
        };

        device.SendPacket(spoofedEthernetPacket);
    }

    private static void TogglePorts()
    {
        Console.WriteLine("Enter port number to toggle:");
        string portInput = Console.ReadLine();
        int portNumber;
        if (int.TryParse(portInput, out portNumber))
        {
            if (portStates.ContainsKey(portNumber))
            {
                portStates[portNumber] = !portStates[portNumber];
            }
            else
            {
                portStates.Add(portNumber, true);
            }
        }
    }

    private static void SpoofOsDetection()
    {
        Console.WriteLine("Select an OS to spoof:");
        Console.WriteLine("1. Windows");
        Console.WriteLine("2. Linux");
        Console.WriteLine("3. Mac OS");
        Console.WriteLine("4. Other (custom)");
        Console.Write("Enter your choice: ");
        string osChoice = Console.ReadLine();

        string[] versions;
        string osName;

        switch (osChoice)
        {
            case "1":
                osName = "Windows";
                versions = new string[] { "95", "98", "XP", "Vista", "7", "8", "10", "11" };
                break;
            case "2":
                osName = "Linux";
                versions = new string[] { "Ubuntu", "Debian", "Fedora", "CentOS", "Red Hat Enterprise Linux" };
                break;
            case "3":
                osName = "Mac OS";
                versions = new string[] { "10.0", "10.1", "10.2", "10.3", "10.4", "10.5", "10.6", "10.7", "10.8", "10.9", "10.10", "10.11", "10.12", "10.13", "10.14", "10.15" };
                break;
            case "4":
                SpoofCustomOs();
                return;
            default:
                Console.WriteLine("Invalid choice. Defaulting to Linux.");
                osName = "Linux";
                versions = new string[] { "Ubuntu" };
                break;
        }

        SpoofOs(osName, versions);
    }

    private static void SpoofOs(string osName, string[] versions)
    {
        Console.WriteLine($"Select a {osName} version to spoof:");
        for (int i = 0; i < versions.Length; i++)
        {
            Console.WriteLine($"{i + 1}. {versions[i]}");
        }

        Console.Write("Enter your choice: ");
        string choice = Console.ReadLine();

        if (int.TryParse(choice, out int index) && index > 0 && index <= versions.Length)
        {
            spoofedOS = $"{osName} {versions[index - 1]}";
        }
        else
        {
            Console.WriteLine("Invalid choice. Defaulting to the first version.");
            spoofedOS = $"{osName} {versions[0]}";
        }
    }

    private static void SpoofCustomOs()
    {
        Console.Write("Enter a custom OS name: ");
        string osName = Console.ReadLine();
        Console.Write("Enter a custom OS version: ");
        string osVersion = Console.ReadLine();
        spoofedOS = $"{osName} {osVersion}";
    }

    private static void SpoofServiceInfo()
    {
        Console.WriteLine("Select a service to spoof:");
        Console.WriteLine("1. Apache");
        Console.WriteLine("2. IIS");
        Console.WriteLine("3. Nginx");
        Console.WriteLine("4. Lighttpd");
        Console.WriteLine("5. Other (custom)");
        Console.Write("Enter your choice: ");
        string serviceChoice = Console.ReadLine();

        string[] versions;
        string serviceName;
        List<int> typicalPorts = new List<int>();

        Console.Write("Show CVE vulnerable versions? (y/n): ");
        string showCve = Console.ReadLine().ToLower();

        switch (serviceChoice)
        {
            case "1":
                serviceName = "Apache";
                typicalPorts.AddRange(new int[] { 80, 8080 });
                if (showCve == "y")
                {
                    versions = new string[] { "1.3.34", "2.2.34", "2.4.38", "2.4.46" };
                    Console.WriteLine("Note: These versions have known CVEs:");
                    Console.WriteLine("  1.3.34: CVE-2017-15715");
                    Console.WriteLine("  2.2.34: CVE-2019-10092");
                    Console.WriteLine("  2.4.38: CVE-2020-11984");
                    Console.WriteLine("  2.4.46: CVE-2021-44790");
                }
                else
                {
                    versions = new string[] { "2.2", "2.4", "2.4.51" };
                }
                break;
            case "2":
                serviceName = "IIS";
                typicalPorts.Add(80);
                if (showCve == "y")
                {
                    versions = new string[] { "6.0", "7.0", "7.5", "8.0", "8.5" };
                    Console.WriteLine("Note: These versions have known CVEs:");
                    Console.WriteLine("  6.0: MS15-034");
                    Console.WriteLine("  7.0: CVE-2015-1635");
                    Console.WriteLine("  7.5: CVE-2017-7269");
                    Console.WriteLine("  8.0: CVE-2019-1367");
                    Console.WriteLine("  8.5: CVE-2020-0688");
                }
                else
                {
                    versions = new string[] { "10.0", "10.5" };
                }
                break;
            case "3":
                serviceName = "Nginx";
                typicalPorts.AddRange(new int[] { 80, 443 });
                if (showCve == "y")
                {
                    versions = new string[] { "0.8.20", "1.10.3", "1.12.2", "1.14.0", "1.16.1" };
                    Console.WriteLine("Note: These versions have known CVEs:");
                    Console.WriteLine("  0.8.20: CVE-2013-2028");
                    Console.WriteLine("  1.10.3: CVE-2017-7529");
                    Console.WriteLine("  1.12.2: CVE-2018-16843");
                    Console.WriteLine("  1.14.0: CVE-2019-11043");
                    Console.WriteLine("  1.16.1: CVE-2020-6828");
                }
                else
                {
                    versions = new string[] { "1.10", "1.12", "1.14", "1.16", "1.20" };
                }
                break;
            case "4":
                serviceName = "Lighttpd";
                typicalPorts.Add(80);
                if (showCve == "y")
                {
                    versions = new string[] { "1.4.35", "1.4.40", "1.4.45", "1.4.50" };
                    Console.WriteLine("Note: These versions have known CVEs:");
                    Console.WriteLine("  1.4.35: CVE-2015-3200");
                    Console.WriteLine("  1.4.40: CVE-2016-1000211");
                    Console.WriteLine("  1.4.45: CVE-2017-18934");
                    Console.WriteLine("  1.4.50: CVE-2018-19052");
                }
                else
                {
                    versions = new string[] { "1.4", "1.4.63" };
                }
                break;
            case "5":
                SpoofCustomService();
                return;
            default:
                Console.WriteLine("Invalid choice. Defaulting to Apache.");
                serviceName = "Apache";
                versions = new string[] { "2.6" };
                break;
        }

        SpoofService(serviceName, versions);
    }

    private static void SpoofService(string serviceName, string[] versions)
    {
        Console.WriteLine($"Select a {serviceName} version to spoof:");
        for (int i = 0; i < versions.Length; i++)
        {
            Console.WriteLine($"{i + 1}. {versions[i]}");
        }

        Console.Write("Enter your choice: ");
        string choice = Console.ReadLine();

        if (int.TryParse(choice, out int index) && index > 0 && index <= versions.Length)
        {
            spoofedServiceInfo = $"{serviceName} {versions[index - 1]}";
        }
        else
        {
            Console.WriteLine("Invalid choice. Defaulting to the first version.");
            spoofedServiceInfo = $"{serviceName} {versions[0]}";
        }
    }

    private static void SpoofCustomService()
    {
        Console.Write("Enter a custom service name: ");
        string serviceName = Console.ReadLine();
        Console.Write("Enter a custom service version: ");
        string serviceVersion = Console.ReadLine();
        spoofedServiceInfo = $"{serviceName} {serviceVersion}";
    }

    private static void SpoofTraceroute()
    {
        Console.WriteLine("Enter number of hops to spoof:");
        string hopInput = Console.ReadLine();
        int numHops;
        if (int.TryParse(hopInput, out numHops))
        {
            List<string> hopResolves = new List<string>();
            List<int> hopDelays = new List<int>();

            for (int i = 1; i <= numHops; i++)
            {
                Console.WriteLine($"Enter resolve for hop {i}:");
                string resolveInput = Console.ReadLine();
                hopResolves.Add(resolveInput);

                Console.WriteLine($"Enter delay for hop {i} (in ms), or press Enter for average delay:");
                string delayInput = Console.ReadLine();
                int delay;
                if (int.TryParse(delayInput, out delay))
                {
                    hopDelays.Add(delay);
                }
                else
                {
                    hopDelays.Add(new Random().Next(20, 151));
                }
            }

            spoofedTraceroute = string.Join(" -> ", hopResolves);

            // Store the hop resolves and delays for later use
            // (e.g., when sending spoofed packets)
            tracerouteHops = new Dictionary<int, (string Resolve, int Delay)>();
            for (int i = 0; i < numHops; i++)
            {
                tracerouteHops.Add(i + 1, (hopResolves[i], hopDelays[i]));
            }
        }
    }

    private static void RunSpoofing()
    {
        Console.WriteLine("Spoofing started!");

        /* TODO Implimentation
        For example, in response(if option is toggled) to an smap scan, send a spoofed SYN-ACK packet
        to make a closed port appear open with the proper details, or a custom program.
        Or send a spoofed RST packet to make an open port appear closed, or just not reply to it at all)
        */

        // Spoofed SYN-ACK packet
        var spoofedTcpPacket = new TcpPacket(80, 1234) // Spoof a packet from port 80 to port 1234
        {
            Syn = true,
            Ack = true,
            SequenceNumber = 12345,
            AcknowledgmentNumber = 67890,
            WindowSize = 1024
        };

        var spoofedIpPacket = new IPv4Packet("192.168.1.100", "192.168.1.200") // Spoof a packet from 192.168.1.100 to 192.168.1.200
        {
            PayloadPacket = spoofedTcpPacket
        };

        var spoofedEthernetPacket = new EthernetPacket("00:11:22:33:44:55", "66:77:88:99:AA:BB", EthernetPacketType.IpV4) // Spoof a packet from 00:11:22:33:44:55 to 66:77:88:99:AA:BB
        {
            PayloadPacket = spoofedIpPacket
        };

        device.SendPacket(spoofedEthernetPacket);
    }
}