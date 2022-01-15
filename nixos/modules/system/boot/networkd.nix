{ config, lib, pkgs, utils, ... }:

with utils.systemdUtils.unitOptions;
with utils.systemdUtils.lib;
with lib;

let

  cfg = config.systemd.network;

  check = {

    link = {

      sectionLink = checkUnitConfig "Link" [
        (assertOnlyFields [
          "Description"
          "Alias"
          "MACAddressPolicy"
          "MACAddress"
          "NamePolicy"
          "Name"
          "AlternativeNamesPolicy"
          "AlternativeName"
          "TransmitQueues"
          "ReceiveQueues"
          "TransmitQueueLength="
          "MTUBytes"
          "BitsPerSecond"
          "Duplex"
          "AutoNegotiation"
          "WakeOnLan"
          "Port"
          "Advertise"
          "ReceiveChecksumOffload"
          "TransmitChecksumOffload"
          "TCPSegmentationOffload"
          "TCP6SegmentationOffload"
          "GenericSegmentationOffload"
          "GenericReceiveOffload"
          "LargeReceiveOffload"
          "RxChannels"
          "TxChannels"
          "OtherChannels"
          "CombinedChannels"
          "RxBufferSize"
          "RxMiniBufferSize"
          "RxJumboBufferSize"
          "TxBufferSize"
          "RxFlowControl"
          "TxFlowControl"
          "AutoNegotiationFlowControl"
          "GenericSegmentOffloadMaxBytes"
          "GenericSegmentOffloadMaxSegments"
        ])
        (assertValueOneOf "MACAddressPolicy" ["persistent" "random" "none"])
        (assertMacAddress "MACAddress")
        (assertInt "TransmitQueues")
        (assertRange "TransmitQueues" 0 4096)
        (assertInt "ReceiveQueues")
        (assertRange "ReceiveQueues" 0 4096)
        (assertInt "TransmitQueueLength")
        (assertRange "TransmitQueueLength" 0 4294967294)
        (assertByteFormat "MTUBytes")
        (assertByteFormat "BitsPerSecond")
        (assertValueOneOf "Duplex" ["half" "full"])
        (assertValueOneOf "AutoNegotiation" boolValues)
        (assertValueOneOf "WakeOnLan" ["phy" "unicast" "multicast" "broadcast" "arp" "magic" "secureon" "off"])
        (assertValueOneOf "Port" ["tp" "aui" "bnc" "mii" "fibre"])
        (assertValueOneOf "ReceiveChecksumOffload" boolValues)
        (assertValueOneOf "TransmitChecksumOffload" boolValues)
        (assertValueOneOf "TCPSegmentationOffload" boolValues)
        (assertValueOneOf "TCP6SegmentationOffload" boolValues)
        (assertValueOneOf "GenericSegmentationOffload" boolValues)
        (assertValueOneOf "GenericReceiveOffload" boolValues)
        (assertValueOneOf "LargeReceiveOffload" boolValues)
        (assertInt "RxChannels")
        (assertRange "RxChannels" 1 4294967295)
        (assertInt "TxChannels")
        (assertRange "TxChannels" 1 4294967295)
        (assertInt "OtherChannels")
        (assertRange "OtherChannels" 1 4294967295)
        (assertInt "CombinedChannels")
        (assertRange "CombinedChannels" 1 4294967295)
        (assertInt "RxBufferSize")
        (assertInt "RxMiniBufferSize")
        (assertInt "RxJumboBufferSize")
        (assertInt "TxBufferSize")
        (assertValueOneOf "RxFlowControl" boolValues)
        (assertValueOneOf "AutoNegotiationFlowControl" boolValues)
        (assertByteFormat "GenericSegmentOffloadMaxBytes")
        (assertInt "GenericSegmentOffloadMaxSegments")
        (assertRange "GenericSegmentOffloadMaxSegments" 1 65535)
      ];
    };

    netdev = let

      macvlanChecks = [
        (assertOnlyFields [
          "Mode"
          "SourceMACAddress"
          "BroadcastMulticastQueueLength"
        ])
        (assertValueOneOf "Mode" ["private" "vepa" "bridge" "passthru"])
      ];

      ipvlanChecks = [
        (assertOnlyFields [
          "Mode"
          "Flags"
        ])
        (assertValueOneOf "Mode" ["L2" "L3" "L3S"])
        (assertValueOneOf "Flags" ["bridge" "private" "vepa"])
      ];

      tunChecks = [
        (assertOnlyFields [
          "MultiQueue"
          "PacketInfo"
          "VNetHeader"
          "User"
          "Group"
        ])
        (assertValueOneOf "MultiQueue" boolValues)
        (assertValueOneOf "PacketInfo" boolValues)
        (assertValueOneOf "VNetHeader" boolValues)
      ];

    in {

      sectionNetdev = checkUnitConfig "Netdev" [
        (assertOnlyFields [
          "Description"
          "Name"
          "Kind"
          "MTUBytes"
          "MACAddress"
        ])
        (assertHasField "Name")
        (assertHasField "Kind")
        (assertValueOneOf "Kind" [
          "bond"
          "bridge"
          "dummy"
          "gre"
          "gretap"
          "erspan"
          "ip6gre"
          "ip6tnl"
          "ip6gretap"
          "ipip"
          "ipvlan"
          "macvlan"
          "macvtap"
          "sit"
          "tap"
          "tun"
          "veth"
          "vlan"
          "vti"
          "vti6"
          "vxlan"
          "geneve"
          "l2tp"
          "macsec"
          "vrf"
          "vcan"
          "vxcan"
          "wireguard"
          "netdevsim"
          "nlmon"
          "fou"
          "xfrm"
          "ifb"
          "bareudp"
          "batadv"
        ])
        (assertByteFormat "MTUBytes")
        (assertMacAddress "MACAddress")
      ];

      sectionBridge = checkUnitConfig "Bridge" [
        (assertOnlyFields [
          "HelloTimeSec"
          "MaxAgeSec"
          "ForwardDelaySec"
          "AgeingTimeSec"
          "Priority"
          "GroupForwardMask"
          "DefaultPVID"
          "MulticastQuerier"
          "MulticastSnooping"
          "VLANFiltering"
          "VLANProtocol"
          "STP"
          "MulticastIGMPVersion"
        ])
        (assertInt "Priority")
        (assertRange "Priority" 0 65535)
        (assertValueOneOf "MulticastQuerier" boolValues)
        (assertValueOneOf "MulticastSnooping" boolValues)
        (assertValueOneOf "VLANFiltering" boolValues)
        (assertValueOneOf "VLANProtocol" ["802.1q" "802.1ad"])
        (assertValueOneOf "STP" boolValues)
        (assertInt "MulticastIGMPVersion")
        (assertValueOneOf "MulticastIGMPVersion" [2 3])
      ];

      sectionVLAN = checkUnitConfig "VLAN" [
        (assertOnlyFields [
          "Id"
          "Protocol"
          "GVRP"
          "MVRP"
          "LooseBinding"
          "ReorderHeader"
          "EgressQOSMaps"
          "IngressQOSMaps"
        ])
        (assertInt "Id")
        (assertRange "Id" 0 4094)
        (assertValueOneOf "Protocol" ["802.1q" "802.1ad"])
        (assertValueOneOf "GVRP" boolValues)
        (assertValueOneOf "MVRP" boolValues)
        (assertValueOneOf "LooseBinding" boolValues)
        (assertValueOneOf "ReorderHeader" boolValues)
      ];

      sectionMACVLAN = checkUnitConfig "MACVLAN" macvlanChecks;

      sectionMACVTAP = checkUnitConfig "MACVTAP" macvlanChecks;

      sectionIPVLAN = checkUnitConfig "IPVLAN" ipvlanChecks;

      sectionIPVTAP = checkUnitConfig "IPVTAP" ipvlanChecks;

      sectionVXLAN = checkUnitConfig "VXLAN" [
        (assertOnlyFields [
          "VNI"
          "Remote"
          "Local"
          "Group"
          "TOS"
          "TTL"
          "MacLearning"
          "FDBAgeingSec"
          "MaximumFDBEntries"
          "ReduceARPProxy"
          "L2MissNotification"
          "L3MissNotification"
          "RouteShortCircuit"
          "UDPChecksum"
          "UDP6ZeroChecksumTx"
          "UDP6ZeroChecksumRx"
          "RemoteChecksumTx"
          "RemoteChecksumRx"
          "GroupPolicyExtension"
          "GenericProtocolExtension"
          "DestinationPort"
          "PortRange"
          "FlowLabel"
          "IPDoNotFragment"
        ])
        (assertInt "VNI")
        (assertRange "VNI" 1 16777215)
        (assertValueOneOf "MacLearning" boolValues)
        (assertInt "MaximumFDBEntries")
        (assertValueOneOf "ReduceARPProxy" boolValues)
        (assertValueOneOf "L2MissNotification" boolValues)
        (assertValueOneOf "L3MissNotification" boolValues)
        (assertValueOneOf "RouteShortCircuit" boolValues)
        (assertValueOneOf "UDPChecksum" boolValues)
        (assertValueOneOf "UDP6ZeroChecksumTx" boolValues)
        (assertValueOneOf "UDP6ZeroChecksumRx" boolValues)
        (assertValueOneOf "RemoteChecksumTx" boolValues)
        (assertValueOneOf "RemoteChecksumRx" boolValues)
        (assertValueOneOf "GroupPolicyExtension" boolValues)
        (assertValueOneOf "GenericProtocolExtension" boolValues)
        (assertInt "FlowLabel")
        (assertRange "FlowLabel" 0 1048575)
        (assertValueOneOf "IPDoNotFragment" (boolValues + ["inherit"]))
      ];

      sectionGENEVE = checkUnitConfig "GENEVE" [
        (assertOnlyFields [
          "Id"
          "Remote"
          "TOS"
          "TTL"
          "UDPChecksum"
          "UDP6ZeroChecksumTx"
          "UDP6ZeroChecksumRx"
          "DestinationPort"
          "FlowLabel"
          "IPDoNotFragment"
          "Independent"
        ])
        (assertHasField "Id")
        (assertInt "Id")
        (assertRange "Id" 0 16777215)
        (assertInt "TOS")
        (assertRange "TOS" 1 25)
        (assertValueOneOf "UDPChecksum" boolValues)
        (assertValueOneOf "UDP6ZeroChecksumTx" boolValues)
        (assertValueOneOf "UDP6ZeroChecksumRx" boolValues)
        (assertPort "DestinationPort")
        (assertInt "FlowLabel")
        (assertRange "FlowLabel" 0 1048575)
        (assertValueOneOf "IPDoNotFragment" (boolValues + ["inherit"]))
        (assertValueOneOf "Independent" boolValues)
      ];

      sectionBareUDP = checkUnitConfig "BareUDP" [
        (assertOnlyFields [
          "DestinationPort"
          "EtherType"
        ])
        (assertHasField "DestinationPort")
        (assertPort "DestinationPort")
        (assertHasField "EtherType")
        (assertValueOneOf "EtherType" ["ipv4" "ipv6" "mpls-uc" "mpls-mc"])
      ];

      sectionL2TP = checkUnitConfig "L2TP" [
        (assertOnlyFields [
          "TunnelId"
          "PeerTunnelId"
          "Remote"
          "Local"
          "EncapsulationType"
          "UDPSourcePort"
          "UDPDestinationPort"
          "UDPChecksum"
          "UDP6ZeroChecksumTx"
          "UDP6ZeroChecksumRx"
        ])
        (assertHasField "TunnelId")
        (assertRange "TunnelId" 1 4294967295)
        (assertHasField "PeerTunnelId")
        (assertRange "PeerTunnelId" 1 4294967295)
        (assertHasField "Remote")
        (assertHasField "Local")
        (assertValueOneOf "EncapsulationType" ["udp" "ip"])
        (assertPort "UDPSourcePort")
        (assertPort "UDPDestinationPort")
        (assertValueOneOf "UDPChecksum" boolValues)
        (assertValueOneOf "UDP6ZeroChecksumTx" boolValues)
        (assertValueOneOf "UDP6ZeroChecksumRx" boolValues)
      ];

      sectionL2TPSession = checkUnitConfig "L2TPSession" [
        (assertOnlyFields [
          "Name"
          "SessionId"
          "PeerSessionId"
          "Layer2SpecificHeader"
        ])
        (assertHasField "Name")
        (assertHasField "SessionId")
        (assertRange "SessionId" 1 4294967295)
        (assertHasField "PeerSessionId")
        (assertRange "PeerSessionId" 1 4294967295)
        (assertValueOneOf "Layer2SpecificHeader" ["none" "default"])
      ];

      sectionMACsec = checkUnitConfig "MACsec" [
        (assertOnlyFields [
          "Port"
          "Encrypt"
        ])
        (assertPort "Port")
        (assertValueOneOf "Encrypt" boolValues)
      ];

      sectionMACsecReceiveChannel = checkUnitConfig "MACsecReceiveChannel" [
        (assertOnlyFields [
          "Port"
          "MACAddress"
        ])
        (assertHasField "Port")
        (assertPort "Port")
        (assertHasField "MACAddress")
        (assertMacAddress "MACAddress")
      ];

      # NOTE The Key directive is missing on purpose here, please
      # do not add it to this list. The nix store is world-readable let's
      # refrain ourselves from providing a footgun.
      sectionMACsecTransmitAssociation = checkUnitConfig "MACsecTransmitAssociation" [
        (assertOnlyFields [
          "PacketNumber"
          "KeyId"
          "KeyFile"
          "Activate"
          "UseForEncoding"
        ])
        (assertHasField "KeyId")
        (assertRange "KeyId" 0 255)
        (assertValueOneOf "Activate" boolValues)
        (assertValueOneOf "UseForEncoding" boolValues)
      ];

      # NOTE The Key directive is missing on purpose here, please
      # do not add it to this list. The nix store is world-readable let's
      # refrain ourselves from providing a footgun.
      sectionMACsecReceiveAssociation = checkUnitConfig "MACsecReceiveAssociation" [
        (assertOnlyFields [
          "Port"
          "MACAddress"
          "PacketNumber"
          "KeyId"
          "KeyFile"
          "Activate"
        ])
        (assertHasField "KeyId")
        (assertRange "KeyId" 0 255)
        (assertValueOneOf "Activate" boolValues)
      ];

      sectionTunnel = checkUnitConfig "Tunnel" [
        (assertOnlyFields [
          "Local"
          "Remote"
          "TOS"
          "TTL"
          "DiscoverPathMTU"
          "IPv6FlowLabel"
          "CopyDSCP"
          "EncapsulationLimit"
          "Key"
          "InputKey"
          "OutputKey"
          "Mode"
          "Independent"
          "AssignToLoopback"
          "AllowLocalRemote"
          "FooOverUDP"
          "FOUDestinationPort"
          "FOUSourcePort"
          "Encapsulation"
          "IPv6RapidDeploymentPrefix"
          "ISATAP"
          "SerializeTunneledPackets"
          "ERSPANIndex"
        ])
        (assertInt "TTL")
        (assertRange "TTL" 0 255)
        (assertValueOneOf "DiscoverPathMTU" boolValues)
        (assertValueOneOf "CopyDSCP" boolValues)
        (assertValueOneOf "Mode" ["ip6ip6" "ipip6" "any"])
        (assertValueOneOf "Independent" boolValues)
        (assertValueOneOf "AssignToLoopback" boolValues)
        (assertValueOneOf "AllowLocalRemote" boolValues)
        (assertValueOneOf "FooOverUDP" boolValues)
        (assertPort "FOUDestinationPort")
        (assertPort "FOUSourcePort")
        (assertValueOneOf "Encapsulation" ["FooOverUDP" "GenericUDPEncapsulation"])
        (assertValueOneOf "ISATAP" boolValues)
        (assertValueOneOf "SerializeTunneledPackets" boolValues)
        (assertInt "ERSPANIndex")
        (assertRange "ERSPANIndex" 1 1048575)
      ];

      sectionFooOverUDP = checkUnitConfig "FooOverUDP" [
        (assertOnlyFields [
          "Encapsulation"
          "Port"
          "PeerPort"
          "Protocol"
          "Peer"
          "Local"
        ])
        (assertValueOneOf "Encapsulation" ["FooOverUDP" "GenericUDPEncapsulation"])
        (assertHasField "Port")
        (assertPort "Port")
        (assertPort "PeerPort")
      ];

      sectionPeer = checkUnitConfig "Peer" [
        (assertOnlyFields [
          "Name"
          "MACAddress"
        ])
        (assertHasField "Name")
        (assertMacAddress "MACAddress")
      ];

      sectionVXCAN = checkUnitConfig "VXCAN" [
        (assertOnlyFields [
          "Peer"
        ])
        (assertHasField "Peer")
      ];

      sectionTun = checkUnitConfig "Tun" tunChecks;

      sectionTap = checkUnitConfig "Tap" tunChecks;

      # NOTE The PrivateKey directive is missing on purpose here, please
      # do not add it to this list. The nix store is world-readable let's
      # refrain ourselves from providing a footgun.
      sectionWireGuard = checkUnitConfig "WireGuard" [
        (assertOnlyFields [
          "PrivateKeyFile"
          "ListenPort"
          "FirewallMark"
        ])
        (assertInt "FirewallMark")
        (assertRange "FirewallMark" 1 4294967295)
      ];

      # NOTE The PresharedKey directive is missing on purpose here, please
      # do not add it to this list. The nix store is world-readable,let's
      # refrain ourselves from providing a footgun.
      sectionWireGuardPeer = checkUnitConfig "WireGuardPeer" [
        (assertOnlyFields [
          "PublicKey"
          "PresharedKeyFile"
          "AllowedIPs"
          "Endpoint"
          "PersistentKeepalive"
        ])
        (assertInt "PersistentKeepalive")
        (assertRange "PersistentKeepalive" 0 65535)
      ];

      sectionBond = checkUnitConfig "Bond" [
        (assertOnlyFields [
          "Mode"
          "TransmitHashPolicy"
          "LACPTransmitRate"
          "MIIMonitorSec"
          "UpDelaySec"
          "DownDelaySec"
          "LearnPacketIntervalSec"
          "AdSelect"
          "AdActorSystemPriority"
          "AdUserPortKey"
          "AdActorSystem"
          "FailOverMACPolicy"
          "ARPValidate"
          "ARPIntervalSec"
          "ARPIPTargets"
          "ARPAllTargets"
          "PrimaryReselectPolicy"
          "ResendIGMP"
          "PacketsPerSlave"
          "GratuitousARP"
          "AllSlavesActive"
          "DynamicTransmitLoadBalancing"
          "MinLinks"
        ])
        (assertValueOneOf "Mode" [
          "balance-rr"
          "active-backup"
          "balance-xor"
          "broadcast"
          "802.3ad"
          "balance-tlb"
          "balance-alb"
        ])
        (assertValueOneOf "TransmitHashPolicy" [
          "layer2"
          "layer3+4"
          "layer2+3"
          "encap2+3"
          "encap3+4"
        ])
        (assertValueOneOf "LACPTransmitRate" ["slow" "fast"])
        (assertValueOneOf "AdSelect" ["stable" "bandwidth" "count"])
        (assertInt "AdActorSystemPriority")
        (assertRange "AdActorSystemPriority" 1 65535)
        (assertInt "AdUserPortKey")
        (assertRange "AdUserPortKey" 0 1023)
        (assertValueOneOf "FailOverMACPolicy" ["none" "active" "follow"])
        (assertValueOneOf "ARPValidate" ["none" "active" "backup" "all"])
        (assertValueOneOf "ARPAllTargets" ["any" "all"])
        (assertValueOneOf "PrimaryReselectPolicy" ["always" "better" "failure"])
        (assertInt "ResendIGMP")
        (assertRange "ResendIGMP" 0 255)
        (assertInt "PacketsPerSlave")
        (assertRange "PacketsPerSlave" 0 65535)
        (assertInt "GratuitousARP")
        (assertRange "GratuitousARP" 0 255)
        (assertValueOneOf "AllSlavesActive" boolValues)
        (assertValueOneOf "DynamicTransmitLoadBalancing" boolValues)
        (assertInt "MinLinks")
        (assertMinimum "MinLinks" 0)
      ];

      sectionXfrm = checkUnitConfig "Xfrm" [
        (assertOnlyFields [
          "InterfaceId"
          "Independent"
        ])
        (assertInt "InterfaceId")
        (assertRange "InterfaceId" 1 4294967295)
        (assertValueOneOf "Independent" boolValues)
      ];

      sectionVRF = checkUnitConfig "VRF" [
        (assertOnlyFields [
          "Table"
        ])
        (assertInt "Table")
        (assertMinimum "Table" 0)
      ];

      sectionBatmanAdvanced = checkUnitConfig "BatmanAdvanced" [
        (assertOnlyFields [
          "GatewayMode"
          "Aggregation"
          "BridgeLoopAvoidance"
          "DistributedArpTable"
          "Fragmentation"
          "HopPenalty"
          "OriginatorIntervalSec"
          "GatewayBandwithDown"
          "GatewayBandwithUp"
          "GatewayBandwidthDown"
          "GatewayBandwidthUp"
          "RoutingAlgorithm"
        ])
        (assertValueOneOf "GatewayMode" ["off" "client" "server"])
        (assertValueOneOf "Aggregation" boolValues)
        (assertValueOneOf "BridgeLoopAvoidance" boolValues)
        (assertValueOneOf "DistributedArpTable" boolValues)
        (assertValueOneOf "Fragmentation" boolValues)
        (assertInt "HopPenalty")
        (assertRange "HopPenalty" 0 255)
        (assertValueOneOf "RoutingAlgorithm" ["batman-v" "batman-iv"])
      ];
    };

    network = {

      sectionLink = checkUnitConfig "Link" [
        (assertOnlyFields [
          "MACAddress"
          "MTUBytes"
          "ARP"
          "Multicast"
          "AllMulticast"
          "Promiscuous"
          "Unmanaged"
          "Group"
          "RequiredForOnline"
          "RequiredFamilyForOnline"
          "ActivationPolicy"
        ])
        (assertMacAddress "MACAddress")
        (assertByteFormat "MTUBytes")
        (assertValueOneOf "ARP" boolValues)
        (assertValueOneOf "Multicast" boolValues)
        (assertValueOneOf "AllMulticast" boolValues)
        (assertValueOneOf "Promiscuous" boolValues)
        (assertValueOneOf "Unmanaged" boolValues)
        (assertInt "Group")
        (assertRange "Group" 0 4294967295)
        (assertValueOneOf "RequiredForOnline" (boolValues ++ [
          "missing"
          "off"
          "no-carrier"
          "dormant"
          "degraded-carrier"
          "carrier"
          "degraded"
          "enslaved"
          "routable"
        ]))
        (assertValueOneOf "RequiredFamilyForOnline" ["ipv4" "ipv6" "both" "any"])
        (assertValueOneOf "ActivationPolicy" ([
          "up"
          "always-up"
          "manual"
          "always-down"
          "down"
          "bound"
        ]))
      ];

      sectionNetwork = checkUnitConfig "Network" [
        (assertOnlyFields [
          "Description"
          "DHCP"
          "DHCPServer"
          "LinkLocalAddressing"
          "IPv6LinkLocalAddressGenerationMode"
          "IPv6StableSecretAddress"
          "IPv4LLRoute"
          "DefaultRouteOnDevice"
          "IPv6Token"
          "LLMNR"
          "MulticastDNS"
          "DNSOverTLS"
          "DNSSEC"
          "DNSSECNegativeTrustAnchors"
          "LLDP"
          "EmitLLDP"
          "BindCarrier"
          "Address"
          "Gateway"
          "DNS"
          "Domains"
          "DNSDefaultRoute"
          "NTP"
          "IPForward"
          "IPMasquerade"
          "IPv6PrivacyExtensions"
          "IPv6AcceptRA"
          "IPv6DuplicateAddressDetection"
          "IPv6HopLimit"
          "IPv4AcceptLocal"
          "IPv4RouteLocalnet"
          "IPv4ProxyARP"
          "IPv6ProxyNDP"
          "IPv6ProxyNDPAddress"
          "IPv6SendRA"
          "DHCPv6PrefixDelegation"
          "IPv6MTUBytes"
          "BatmanAdvanced"
          "Bond"
          "Bridge"
          "VRF"
          "IPVLAN"
          "IPVTAP"
          "L2TP"
          "MACsec"
          "MACVLAN"
          "MACVTAP"
          "Tunnel"
          "VLAN"
          "VXLAN"
          "Xfrm"
          "ActiveSlave"
          "PrimarySlave"
          "ConfigureWithoutCarrier"
          "IgnoreCarrierLoss"
          "KeepConfiguration"
        ])
        # Note: For DHCP the values both, none, v4, v6 are deprecated
        (assertValueOneOf "DHCP" ["yes" "no" "ipv4" "ipv6"])
        (assertValueOneOf "DHCPServer" boolValues)
        (assertValueOneOf "LinkLocalAddressing" ["yes" "no" "ipv4" "ipv6" "fallback" "ipv4-fallback"])
        (assertValueOneOf "IPv6LinkLocalAddressGenerationMode" ["eui64" "none" "stable-privacy" "random"])
        (assertValueOneOf "IPv4LLRoute" boolValues)
        (assertValueOneOf "DefaultRouteOnDevice" boolValues)
        (assertValueOneOf "LLMNR" (boolValues ++ ["resolve"]))
        (assertValueOneOf "MulticastDNS" (boolValues ++ ["resolve"]))
        (assertValueOneOf "DNSOverTLS" (boolValues ++ ["opportunistic"]))
        (assertValueOneOf "DNSSEC" (boolValues ++ ["allow-downgrade"]))
        (assertValueOneOf "LLDP" (boolValues ++ ["routers-only"]))
        (assertValueOneOf "EmitLLDP" (boolValues ++ ["nearest-bridge" "non-tpmr-bridge" "customer-bridge"]))
        (assertValueOneOf "DNSDefaultRoute" boolValues)
        (assertValueOneOf "IPForward" (boolValues ++ ["ipv4" "ipv6"]))
        (assertValueOneOf "IPMasquerade" boolValues)
        (assertValueOneOf "IPv6PrivacyExtensions" (boolValues ++ ["prefer-public" "kernel"]))
        (assertValueOneOf "IPv6AcceptRA" boolValues)
        (assertInt "IPv6DuplicateAddressDetection")
        (assertMinimum "IPv6DuplicateAddressDetection" 0)
        (assertInt "IPv6HopLimit")
        (assertMinimum "IPv6HopLimit" 0)
        (assertValueOneOf "IPv4AcceptLocal" boolValues)
        (assertValueOneOf "IPv4RouteLocalnet" boolValues)
        (assertValueOneOf "IPv4ProxyARP" boolValues)
        (assertValueOneOf "IPv6ProxyNDP" boolValues)
        (assertValueOneOf "IPv6SendRA" boolValues)
        (assertValueOneOf "DHCPv6PrefixDelegation" boolValues)
        (assertByteFormat "IPv6MTUBytes")
        (assertValueOneOf "ActiveSlave" boolValues)
        (assertValueOneOf "PrimarySlave" boolValues)
        (assertValueOneOf "ConfigureWithoutCarrier" boolValues)
        (assertValueOneOf "IgnoreCarrierLoss" boolValues)
        (assertValueOneOf "KeepConfiguration" (boolValues ++ ["static" "dhcp-on-stop" "dhcp"]))
      ];

      sectionAddress = checkUnitConfig "Address" [
        (assertOnlyFields [
          "Address"
          "Peer"
          "Broadcast"
          "Label"
          "PreferredLifetime"
          "Scope"
          "RouteMetric"
          "HomeAddress"
          "DuplicateAddressDetection"
          "ManageTemporaryAddress"
          "AddPrefixRoute"
          "AutoJoin"
        ])
        (assertHasField "Address")
        (assertValueOneOf "PreferredLifetime" ["forever" "infinity" "0" 0])
        (assertInt "RouteMetric")
        (assertRange "RouteMetric" 0 4294967295)
        (assertValueOneOf "HomeAddress" boolValues)
        (assertValueOneOf "DuplicateAddressDetection" ["ipv4" "ipv6" "both" "none"])
        (assertValueOneOf "ManageTemporaryAddress" boolValues)
        (assertValueOneOf "AddPrefixRoute" boolValues)
        (assertValueOneOf "AutoJoin" boolValues)
      ];

      # [NEIGHBOR] SECTION OPTIONS
      #  A [Neighbor] section accepts the following keys. The neighbor section adds a permanent, static entry to the neighbor table (IPv6) or ARP table (IPv4) for the given hardware address on the links matched for the network.
      #  Specify several [Neighbor] sections to configure several static neighbors.
      #  Address=
      #      The IP address of the neighbor.
      #  LinkLayerAddress=
      #      The link layer address (MAC address or IP address) of the neighbor.
      sectionNeighbor = checkUnitConfig "Neighbor" [
        (assertOnlyFields [
          "Address"
          "LinkLayerAddress"
        ])
      ];

      # [IPV6ADDRESSLABEL] SECTION OPTIONS
      #  An [IPv6AddressLabel] section accepts the following keys. Specify several [IPv6AddressLabel] sections to configure several address labels. IPv6 address labels are used for address selection. See RFC 3484[14]. Precedence is
      #  managed by userspace, and only the label itself is stored in the kernel.
      #  Label=
      #      The label for the prefix, an unsigned integer in the range 0–4294967294. 0xffffffff is reserved. This setting is mandatory.
      #  Prefix=
      #      IPv6 prefix is an address with a prefix length, separated by a slash "/" character. This key is mandatory.
      sectionIPv6AddressLabel = checkUnitConfig "IPv6AddressLabel" [
        (assertOnlyFields [
          "Label"
          "Prefix"
        ])
      ];

      sectionRoutingPolicyRule = checkUnitConfig "RoutingPolicyRule" [
        (assertOnlyFields [
          "TypeOfService"
          "From"
          "To"
          "FirewallMark"
          "Table"
          "Priority"
          "IncomingInterface"
          "OutgoingInterface"
          "SourcePort"
          "DestinationPort"
          "IPProtocol"
          "InvertRule"
          "Family"
          "User"
          "SuppressPrefixLength"
          "Type"
        ])
        (assertInt "TypeOfService")
        (assertRange "TypeOfService" 0 255)
        (assertInt "FirewallMark")
        (assertRange "FirewallMark" 1 4294967295)
        (assertInt "Priority")
        (assertPort "SourcePort")
        (assertPort "DestinationPort")
        (assertValueOneOf "InvertRule" boolValues)
        (assertValueOneOf "Family" ["ipv4" "ipv6" "both"])
        (assertInt "SuppressPrefixLength")
        (assertRange "SuppressPrefixLength" 0 128)
        (assertValueOneOf "Type" ["blackhole" "unreachable" "prohibit"])
      ];


      # [NEXTHOP] SECTION OPTIONS
      #  The [NextHop] section is used to manipulate entries in the kernel's "nexthop" tables. The [NextHop] section accepts the following keys. Specify several [NextHop] sections to configure several hops.
      #  Id=
      #      The id of the next hop. Takes an unsigned integer in the range 1...4294967295. If left unspecified, then automatically chosen by kernel.
      #  Gateway=
      #      As in the [Network] section.
      #  Family=
      #      Takes one of the special values "ipv4" or "ipv6". By default, the family is determined by the address specified in Gateway=. If Gateway= is not specified, then defaults to "ipv4".
      #  OnLink=
      #      Takes a boolean. If set to true, the kernel does not have to check if the gateway is reachable directly by the current machine (i.e., attached to the local network), so that we can insert the nexthop in the kernel table
      #      without it being complained about. Defaults to "no".
      #  Blackhole=
      #      Takes a boolean. If enabled, packets to the corresponding routes are discarded silently, and Gateway= cannot be specified. Defaults to "no".
      #  Group=
      #      Takes a whitespace separated list of nexthop IDs. Each ID must be in the range 1...4294967295. Optionally, each nexthop ID can take a weight after a colon ("id[:weight]"). The weight must be in the range 1...255. If the
      #      weight is not specified, then it is assumed that the weight is 1. This setting cannot be specified with Gateway=, Family=, Blackhole=. This setting can be specified multiple times. If an empty string is assigned, then
      #      the all previous assignments are cleared. Defaults to unset.
      sectionNextHop = checkUnitConfig "NextHop" [
        (assertOnlyFields [
          "Id"
          "Gateway"
          "Family"
          "OnLink"
          "Blackhole"
          "Group"
        ])
      ];

      sectionRoute = checkUnitConfig "Route" [
        (assertOnlyFields [
          "Gateway"
          "GatewayOnLink"
          "Destination"
          "Source"
          "Metric"
          "IPv6Preference"
          "Scope"
          "PreferredSource"
          "Table"
          "Protocol"
          "Type"
          "InitialCongestionWindow"
          "InitialAdvertisedReceiveWindow"
          "QuickAck"
          "FastOpenNoCookie"
          "TTLPropagate"
          "MTUBytes"
          "IPServiceType"
          "TCPAdvertisedMaximumSegmentSize"
          "MultiPathRoute"
          "NextHop"
        ])
        (assertValueOneOf "GatewayOnLink" boolValues)
        (assertInt "Metric")
        (assertValueOneOf "IPv6Preference" ["low" "medium" "high"])
        (assertValueOneOf "Scope" ["global" "site" "link" "host" "nowhere"])
        (assertValueOneOf "Type" [
          "unicast"
          "local"
          "broadcast"
          "anycast"
          "multicast"
          "blackhole"
          "unreachable"
          "prohibit"
          "throw"
          "nat"
          "xresolve"
        ])
        (assertValueOneOf "QuickAck" boolValues)
        (assertValueOneOf "FastOpenNoCookie" boolValues)
        (assertValueOneOf "TTLPropagate" boolValues)
        (assertByteFormat "MTUBytes")
        (assertValueOneOf "IPServiceType" ["CS6" "CS4"])
        (assertInt "NextHop")
        (assertRange "NextHop" 1 4294967295)
      ];

      sectionDHCPv4 = checkUnitConfig "DHCPv4" [
        (assertOnlyFields [
          "SendHostname"
          "Hostname"
          "MUDURL"
          "ClientIdentifier"
          "VendorClassIdentifier"
          "UserClass"
          "DUIDType"
          "DUIDRawData"
          "IAID"
          "Anonymize"
          "RequestOptions"
          "SendOption"
          "SendVendorOption"
          "UseDNS"
          "RoutesToDNS"
          "UseNTP"
          "RoutesToNTP"
          "UseSIP"
          "UseMTU"
          "UseHostname"
          "UseDomains"
          "UseRoutes"
          "RouteMetric"
          "RouteTable"
          "RouteMTUBytes"
          "UseGateway"
          "UseTimezone"
          "FallbackLeaseLifetimeSec"
          "RequestBroadcast"
          "MaxAttempts"
          "ListenPort"
          "DenyList"
          "AllowList"
          "SendRelease"
          "SendDecline"
          "BlackList" # not present, probably dropped in favour of DenyList?
        ])
        (assertValueOneOf "SendHostname" boolValues)
        (assertValueOneOf "ClientIdentifier" ["mac" "duid" "duid-only"])
        (assertInt "IAID")
        (assertValueOneOf "Anonymize" boolValues)
        (assertValueOneOf "UseDNS" boolValues)
        (assertValueOneOf "RoutesToDNS" boolValues)
        (assertValueOneOf "UseNTP" boolValues)
        (assertValueOneOf "RoutesToNTP" boolValues)
        (assertValueOneOf "UseSIP" boolValues)
        (assertValueOneOf "UseMTU" boolValues)
        (assertValueOneOf "UseHostname" boolValues)
        (assertValueOneOf "UseDomains" (boolValues ++ ["route"]))
        (assertValueOneOf "UseRoutes" boolValues)
        (assertInt "RouteMetric")
        (assertInt "RouteTable")
        (assertRange "RouteTable" 0 4294967295)
        (assertByteFormat "RouteMTUBytes")
        (assertValueOneOf "UseGateway" boolValues)
        (assertValueOneOf "UseTimezone" boolValues)
        (assertValueOneOf "FallbackLeaseLifetimeSec" ["forever" "infinity" "0" 0])
        (assertValueOneOf "RequestBroadcast" boolValues)
        (assertPort "ListenPort")
        (assertValueOneOf "SendRelease" boolValues)
        (assertValueOneOf "SendDecline" boolValues)
      ];

      sectionDHCPv6 = checkUnitConfig "DHCPv6" [
        (assertOnlyFields [
          "MUDURL"
          "IAID"
          "DUIDType"
          "DUIDRawData"
          "RequestOptions"
          "SendOption"
          "SendVendorOption"
          "UserClass"
          "VendorClass"
          "PrefixDelegationHint"
          "UseAddress"
          "UseDNS"
          "UseNTP"
          "UseHostname"
          "UseDomains"
          "ForceDHCPv6PDOtherInformation"
          "WithoutRA"
          "RapidCommit"
#          "RouteMetric" # was moved to [IPv6AcceptRA] https://github.com/yuwata/systemd/commit/8ebafba9f987c21aa5787c8767f2e390b4ec0bc5
        ])
        # (assertRange "SendOption" 1 65536) doesn't seem coorect
        (assertInt "IAID")
        (assertValueOneOf "UseAddress" boolValues)
        (assertValueOneOf "UseDNS" boolValues)
        (assertValueOneOf "UseNTP" boolValues)
        (assertValueOneOf "UseHostname" boolValues)
        (assertValueOneOf "UseDomains" boolValues)
        (assertValueOneOf "ForceDHCPv6PDOtherInformation" boolValues)
        (assertValueOneOf "WithoutRA" ["solicit" "information-request"])
        (assertValueOneOf "RapidCommit" boolValues)
      ];

      sectionDHCPv6PrefixDelegation = checkUnitConfig "DHCPv6PrefixDelegation" [
        (assertOnlyFields [
          "SubnetId"
          "Announce"
          "Assign"
          "Token"
          "ManageTemporaryAddress"
          "RouteMetric"
        ])
        (assertValueOneOf "Announce" boolValues)
        (assertValueOneOf "Assign" boolValues)
        (assertValueOneOf "ManageTemporaryAddress" boolValues)
        (assertInt "RouteMetric")
        (assertRange "RouteMetric" 0 4294967295)
      ];

      sectionIPv6AcceptRA = checkUnitConfig "IPv6AcceptRA" [
        (assertOnlyFields [
          "UseDNS"
          "UseDomains"
          "RouteTable"
          "RouteMetric"
          "UseAutonomousPrefix"
          "UseOnLinkPrefix"
          "RouterDenyList"
          "RouterAllowList"
          "PrefixDenyList"
          "PrefixAllowList"
          "RouteDenyList"
          "RouteAllowList"
          "DHCPv6Client"
        ])
        (assertValueOneOf "UseDNS" boolValues)
        (assertValueOneOf "UseDomains" (boolValues ++ ["route"]))
        (assertInt "RouteTable")
        (assertRange "RouteTable" 0 4294967295)
        (assertInt "RouteMetric")
        (assertRange "RouteMetric" 0 4294967295)
        (assertValueOneOf "UseAutonomousPrefix" boolValues)
        (assertValueOneOf "UseOnLinkPrefix" boolValues)
        (assertValueOneOf "DHCPv6Client" (boolValues ++ ["always"]))
      ];

      sectionDHCPServer = checkUnitConfig "DHCPServer" [
        (assertOnlyFields [
          "ServerAddress"
          "PoolOffset"
          "PoolSize"
          "DefaultLeaseTimeSec"
          "MaxLeaseTimeSec"
          "UplinkInterface"
          "EmitDNS"
          "DNS"
          "EmitNTP"
          "NTP"
          "EmitSIP"
          "SIP"
          "EmitPOP3"
          "POP3"
          "EmitSMTP"
          "SMTP"
          "EmitLPR"
          "LPR"
          "EmitRouter"
          "EmitTimezone"
          "Timezone"
          "SendOption"
          "SendVendorOption"
          "BindToInterface"
          "RelayTarget"
          "RelayAgentCircuitId"
          "RelayAgentRemoteId"
        ])
        (assertInt "PoolOffset")
        (assertMinimum "PoolOffset" 0)
        (assertInt "PoolSize")
        (assertMinimum "PoolSize" 0)
        (assertValueOneOf "EmitDNS" boolValues)
        (assertValueOneOf "EmitNTP" boolValues)
        (assertValueOneOf "EmitSIP" boolValues)
        (assertValueOneOf "EmitPOP3" boolValues)
        (assertValueOneOf "EmitSMTP" boolValues)
        (assertValueOneOf "EmitLPR" boolValues)
        (assertValueOneOf "EmitRouter" boolValues)
        (assertValueOneOf "EmitTimezone" boolValues)
        (assertValueOneOf "BindToInterface" boolValues)
      ];

      sectionIPv6SendRA = checkUnitConfig "IPv6SendRA" [
        (assertOnlyFields [
          "Managed"
          "OtherInformation"
          "RouterLifetimeSec"
          "RouterPreference"
          "EmitDNS"
          "DNS"
          "EmitDomains"
          "Domains"
          "DNSLifetimeSec"
        ])
        (assertValueOneOf "Managed" boolValues)
        (assertValueOneOf "OtherInformation" boolValues)
        (assertValueOneOf "RouterPreference" ["high" "medium" "low" "normal" "default"])
        (assertValueOneOf "EmitDNS" boolValues)
        (assertValueOneOf "EmitDomains" boolValues)
      ];

      sectionIPv6Prefix = checkUnitConfig "IPv6Prefix" [
        (assertOnlyFields [
          "AddressAutoconfiguration"
          "OnLink"
          "Prefix"
          "PreferredLifetimeSec"
          "ValidLifetimeSec"
          "Assign"
          "RouteMetric"
        ])
        (assertValueOneOf "AddressAutoconfiguration" boolValues)
        (assertValueOneOf "OnLink" boolValues)
        (assertValueOneOf "Assign" boolValues)
        (assertInt "RouteMetric")
        (assertRange "RouteMetric" 0 4294967295)
      ];

      # [IPV6ROUTEPREFIX] SECTION OPTIONS
      #  One or more [IPv6RoutePrefix] sections contain the IPv6 prefix routes that are announced via Router Advertisements. See RFC 4191[15] for further details.
      #  Route=
      #      The IPv6 route that is to be distributed to hosts. Similarly to configuring static IPv6 routes, the setting is configured as an IPv6 prefix routes and its prefix route length, separated by a "/" character. Use multiple
      #      [IPv6PrefixRoutes] sections to configure multiple IPv6 prefix routes.
      #  LifetimeSec=
      #      Lifetime for the route prefix measured in seconds.  LifetimeSec= defaults to 604800 seconds (one week).
      sectionIPv6RoutePrefix = checkUnitConfig "IPv6RoutePrefix" [
        (assertOnlyFields [
          "Route"
          "LifetimeSec"
        ])
      ];

      # [BRIDGE] SECTION OPTIONS
      #  The [Bridge] section accepts the following keys:
      #  UnicastFlood=
      #      Takes a boolean. Controls whether the bridge should flood traffic for which an FDB entry is missing and the destination is unknown through this port. When unset, the kernel's default will be used.
      #  MulticastFlood=
      #      Takes a boolean. Controls whether the bridge should flood traffic for which an MDB entry is missing and the destination is unknown through this port. When unset, the kernel's default will be used.
      #  MulticastToUnicast=
      #      Takes a boolean. Multicast to unicast works on top of the multicast snooping feature of the bridge. Which means unicast copies are only delivered to hosts which are interested in it. When unset, the kernel's default will
      #      be used.
      #  NeighborSuppression=
      #      Takes a boolean. Configures whether ARP and ND neighbor suppression is enabled for this port. When unset, the kernel's default will be used.
      #  Learning=
      #      Takes a boolean. Configures whether MAC address learning is enabled for this port. When unset, the kernel's default will be used.
      #  HairPin=
      #      Takes a boolean. Configures whether traffic may be sent back out of the port on which it was received. When this flag is false, then the bridge will not forward traffic back out of the receiving port. When unset, the
      #      kernel's default will be used.
      #  UseBPDU=
      #      Takes a boolean. Configures whether STP Bridge Protocol Data Units will be processed by the bridge port. When unset, the kernel's default will be used.
      #  FastLeave=
      #      Takes a boolean. This flag allows the bridge to immediately stop multicast traffic on a port that receives an IGMP Leave message. It is only used with IGMP snooping if enabled on the bridge. When unset, the kernel's
      #      default will be used.
      #  AllowPortToBeRoot=
      #      Takes a boolean. Configures whether a given port is allowed to become a root port. Only used when STP is enabled on the bridge. When unset, the kernel's default will be used.
      #  ProxyARP=
      #      Takes a boolean. Configures whether proxy ARP to be enabled on this port. When unset, the kernel's default will be used.
      #  ProxyARPWiFi=
      #      Takes a boolean. Configures whether proxy ARP to be enabled on this port which meets extended requirements by IEEE 802.11 and Hotspot 2.0 specifications. When unset, the kernel's default will be used.
      #  MulticastRouter=
      #      Configures this port for having multicast routers attached. A port with a multicast router will receive all multicast traffic. Takes one of "no" to disable multicast routers on this port, "query" to let the system detect
      #      the presence of routers, "permanent" to permanently enable multicast traffic forwarding on this port, or "temporary" to enable multicast routers temporarily on this port, not depending on incoming queries. When unset,
      #      the kernel's default will be used.
      #  Cost=
      #      Sets the "cost" of sending packets of this interface. Each port in a bridge may have a different speed and the cost is used to decide which link to use. Faster interfaces should have lower costs. It is an integer value
      #      between 1 and 65535.
      #  Priority=
      #      Sets the "priority" of sending packets on this interface. Each port in a bridge may have a different priority which is used to decide which link to use. Lower value means higher priority. It is an integer value between 0
      #      to 63. Networkd does not set any default, meaning the kernel default value of 32 is used.
      sectionBridge = checkUnitConfig "Bridge" [
        (assertOnlyFields [
          "UnicastFlood"
          "MulticastFlood"
          "MulticastToUnicast"
          "NeighborSuppression"
          "Learning"
          "HairPin"
          "UseBPDU"
          "FastLeave"
          "AllowPortToBeRoot"
          "ProxyARP"
          "ProxyARPWiFi"
          "MulticastRouter"
          "Cost"
          "Priority"
        ])
      ];

      # [BRIDGEFDB] SECTION OPTIONS
      #  The [BridgeFDB] section manages the forwarding database table of a port and accepts the following keys. Specify several [BridgeFDB] sections to configure several static MAC table entries.
      #  MACAddress=
      #      As in the [Network] section. This key is mandatory.
      #  Destination=
      #      Takes an IP address of the destination VXLAN tunnel endpoint.
      #  VLANId=
      #      The VLAN ID for the new static MAC table entry. If omitted, no VLAN ID information is appended to the new static MAC table entry.
      #  VNI=
      #      The VXLAN Network Identifier (or VXLAN Segment ID) to use to connect to the remote VXLAN tunnel endpoint. Takes a number in the range 1...16777215. Defaults to unset.
      #  AssociatedWith=
      #      Specifies where the address is associated with. Takes one of "use", "self", "master" or "router".  "use" means the address is in use. User space can use this option to indicate to the kernel that the fdb entry is in use.
      #      "self" means the address is associated with the port drivers fdb. Usually hardware.  "master" means the address is associated with master devices fdb.  "router" means the destination address is associated with a router.
      #      Note that it's valid if the referenced device is a VXLAN type device and has route shortcircuit enabled. Defaults to "self".
      #  OutgoingInterface=
      #      Specifies the name or index of the outgoing interface for the VXLAN device driver to reach the remote VXLAN tunnel endpoint. Defaults to unset.
      sectionBridgeFDB = checkUnitConfig "BridgeFDB" [
        (assertOnlyFields [
          "MACAddress"
          "Destination"
          "VLANId"
          "VNI"
          "AssociatedWith"
          "OutgoingInterface"
        ])
      ];

      # [BRIDGEMDB] SECTION OPTIONS
      #  The [BridgeMDB] section manages the multicast membership entries forwarding database table of a port and accepts the following keys. Specify several [BridgeMDB] sections to configure several permanent multicast membership
      #  entries.
      #  MulticastGroupAddress=
      #      Specifies the IPv4 or IPv6 multicast group address to add. This setting is mandatory.
      #  VLANId=
      #      The VLAN ID for the new entry. Valid ranges are 0 (no VLAN) to 4094. Optional, defaults to 0.
      sectionBridgeMDB = checkUnitConfig "BridgeMDB" [
        (assertOnlyFields [
          "entries."
          "MulticastGroupAddress"
          "VLANId"
        ])
      ];

      # [LLDP] SECTION OPTIONS
      #  The [LLDP] section manages the Link Layer Discovery Protocol (LLDP) and accepts the following keys:
      #  MUDURL=
      #      When configured, the specified Manufacturer Usage Descriptions (MUD) URL will be sent in LLDP packets. The syntax and semantics are the same as for MUDURL= in the [DHCPv4] section described above.
      #      The MUD URLs received via LLDP packets are saved and can be read using the sd_lldp_neighbor_get_mud_url() function.
      sectionLLDP = checkUnitConfig "LLDP" [
        (assertOnlyFields [
          "MUDURL"
        ])
      ];
      # [CAN] SECTION OPTIONS
      #  The [CAN] section manages the Controller Area Network (CAN bus) and accepts the following keys:
      #  BitRate=
      #      The bitrate of CAN device in bits per second. The usual SI prefixes (K, M) with the base of 1000 can be used here. Takes a number in the range 1...4294967295.
      #  SamplePoint=
      #      Optional sample point in percent with one decimal (e.g.  "75%", "87.5%") or permille (e.g.  "875‰").
      #  DataBitRate=, DataSamplePoint=
      #      The bitrate and sample point for the data phase, if CAN-FD is used. These settings are analogous to the BitRate= and SamplePoint= keys.
      #  FDMode=
      #      Takes a boolean. When "yes", CAN-FD mode is enabled for the interface. Note, that a bitrate and optional sample point should also be set for the CAN-FD data phase using the DataBitRate= and DataSamplePoint= keys.
      #  FDNonISO=
      #      Takes a boolean. When "yes", non-ISO CAN-FD mode is enabled for the interface. When unset, the kernel's default will be used.
      #  RestartSec=
      #      Automatic restart delay time. If set to a non-zero value, a restart of the CAN controller will be triggered automatically in case of a bus-off condition after the specified delay time. Subsecond delays can be specified
      #      using decimals (e.g.  "0.1s") or a "ms" or "us" postfix. Using "infinity" or "0" will turn the automatic restart off. By default automatic restart is disabled.
      #  Termination=
      #      Takes a boolean. When "yes", the termination resistor will be selected for the bias network. When unset, the kernel's default will be used.
      #  TripleSampling=
      #      Takes a boolean. When "yes", three samples (instead of one) are used to determine the value of a received bit by majority rule. When unset, the kernel's default will be used.
      #  BusErrorReporting=
      #      Takes a boolean. When "yes", reporting of CAN bus errors is activated (those include single bit, frame format, and bit stuffing errors, unable to send dominant bit, unable to send recessive bit, bus overload, active
      #      error announcement, error occurred on transmission). When unset, the kernel's default will be used. Note: in case of a CAN bus with a single CAN device, sending a CAN frame may result in a huge number of CAN bus errors.
      #  ListenOnly=
      #      Takes a boolean. When "yes", listen-only mode is enabled. When the interface is in listen-only mode, the interface neither transmit CAN frames nor send ACK bit. Listen-only mode is important to debug CAN networks without
      #      interfering with the communication or acknowledge the CAN frame. When unset, the kernel's default will be used.
      sectionCAN = checkUnitConfig "CAN" [
        (assertOnlyFields [
          "BitRate"
          "SamplePoint"
          "DataBitRate, DataSamplePoint"
          "FDMode"
          "FDNonISO"
          "RestartSec"
          "Termination"
          "TripleSampling"
          "BusErrorReporting"
          "ListenOnly"
        ])
      ];
      # [QDISC] SECTION OPTIONS
      #  The [QDisc] section manages the traffic control queueing discipline (qdisc).
      #  Parent=
      #      Specifies the parent Queueing Discipline (qdisc). Takes one of "clsact" or "ingress". This is mandatory.
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      sectionQDisc = checkUnitConfig "QDisc" [
        (assertOnlyFields [
          "Parent"
          "Handle"
        ])
      ];

      # [NETWORKEMULATOR] SECTION OPTIONS
      #  The [NetworkEmulator] section manages the queueing discipline (qdisc) of the network emulator. It can be used to configure the kernel packet scheduler and simulate packet delay and loss for UDP or TCP applications, or limit
      #  the bandwidth usage of a particular service to simulate internet connections.
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  DelaySec=
      #      Specifies the fixed amount of delay to be added to all packets going out of the interface. Defaults to unset.
      #  DelayJitterSec=
      #      Specifies the chosen delay to be added to the packets outgoing to the network interface. Defaults to unset.
      #  PacketLimit=
      #      Specifies the maximum number of packets the qdisc may hold queued at a time. An unsigned integer in the range 0–4294967294. Defaults to 1000.
      #  LossRate=
      #      Specifies an independent loss probability to be added to the packets outgoing from the network interface. Takes a percentage value, suffixed with "%". Defaults to unset.
      #  DuplicateRate=
      #      Specifies that the chosen percent of packets is duplicated before queuing them. Takes a percentage value, suffixed with "%". Defaults to unset.
      sectionNetworkEmulator = checkUnitConfig "NetworkEmulator" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "DelaySec"
          "DelayJitterSec"
          "PacketLimit"
          "LossRate"
          "DuplicateRate"
        ])
      ];

      # [TOKENBUCKETFILTER] SECTION OPTIONS
      #  The [TokenBucketFilter] section manages the queueing discipline (qdisc) of token bucket filter (tbf).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  LatencySec=
      #      Specifies the latency parameter, which specifies the maximum amount of time a packet can sit in the Token Bucket Filter (TBF). Defaults to unset.
      #  LimitBytes=
      #      Takes the number of bytes that can be queued waiting for tokens to become available. When the size is suffixed with K, M, or G, it is parsed as Kilobytes, Megabytes, or Gigabytes, respectively, to the base of 1024.
      #      Defaults to unset.
      #  BurstBytes=
      #      Specifies the size of the bucket. This is the maximum amount of bytes that tokens can be available for instantaneous transfer. When the size is suffixed with K, M, or G, it is parsed as Kilobytes, Megabytes, or
      #      Gigabytes, respectively, to the base of 1024. Defaults to unset.
      #  Rate=
      #      Specifies the device specific bandwidth. When suffixed with K, M, or G, the specified bandwidth is parsed as Kilobits, Megabits, or Gigabits, respectively, to the base of 1000. Defaults to unset.
      #  MPUBytes=
      #      The Minimum Packet Unit (MPU) determines the minimal token usage (specified in bytes) for a packet. When suffixed with K, M, or G, the specified size is parsed as Kilobytes, Megabytes, or Gigabytes, respectively, to the
      #      base of 1024. Defaults to zero.
      #  PeakRate=
      #      Takes the maximum depletion rate of the bucket. When suffixed with K, M, or G, the specified size is parsed as Kilobits, Megabits, or Gigabits, respectively, to the base of 1000. Defaults to unset.
      #  MTUBytes=
      #      Specifies the size of the peakrate bucket. When suffixed with K, M, or G, the specified size is parsed as Kilobytes, Megabytes, or Gigabytes, respectively, to the base of 1024. Defaults to unset.
      sectionTokenBucketFilter = checkUnitConfig "TokenBucketFilter" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "LatencySec"
          "LimitBytes"
          "BurstBytes"
          "Rate"
          "MPUBytes"
          "PeakRate"
          "MTUBytes"
        ])
      ];

      # [PIE] SECTION OPTIONS
      #  The [PIE] section manages the queueing discipline (qdisc) of Proportional Integral controller-Enhanced (PIE).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  PacketLimit=
      #      Specifies the hard limit on the queue size in number of packets. When this limit is reached, incoming packets are dropped. An unsigned integer in the range 1...4294967294. Defaults to unset and kernel's default is used.
      sectionPIE = checkUnitConfig "PIE" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "PacketLimit"
        ])
      ];

      # [FLOWQUEUEPIE] SECTION OPTIONS
      #  The "[FlowQueuePIE]" section manages the queueing discipline (qdisc) of Flow Queue Proportional Integral controller-Enhanced (fq_pie).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  PacketLimit=
      #      Specifies the hard limit on the queue size in number of packets. When this limit is reached, incoming packets are dropped. An unsigned integer ranges 1 to 4294967294. Defaults to unset and kernel's default is used.
      sectionFlowQueuePIE = checkUnitConfig "FlowQueuePIE" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "PacketLimit"
        ])
      ];

      # [STOCHASTICFAIRBLUE] SECTION OPTIONS
      #  The [StochasticFairBlue] section manages the queueing discipline (qdisc) of stochastic fair blue (sfb).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  PacketLimit=
      #      Specifies the hard limit on the queue size in number of packets. When this limit is reached, incoming packets are dropped. An unsigned integer in the range 0–4294967294. Defaults to unset and kernel's default is used.
      sectionStochasticFairBlue = checkUnitConfig "StochasticFairBlue" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "PacketLimit"
        ])
      ];

      # [STOCHASTICFAIRNESSQUEUEING] SECTION OPTIONS
      #  The [StochasticFairnessQueueing] section manages the queueing discipline (qdisc) of stochastic fairness queueing (sfq).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  PerturbPeriodSec=
      #      Specifies the interval in seconds for queue algorithm perturbation. Defaults to unset.
      sectionStochasticFairnessQueueing = checkUnitConfig "StochasticFairnessQueueing" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "PerturbPeriodSec"
        ])
      ];

      # [BFIFO] SECTION OPTIONS
      #  The [BFIFO] section manages the queueing discipline (qdisc) of Byte limited Packet First In First Out (bfifo).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  LimitBytes=
      #      Specifies the hard limit in bytes on the FIFO buffer size. The size limit prevents overflow in case the kernel is unable to dequeue packets as quickly as it receives them. When this limit is reached, incoming packets are
      #      dropped. When suffixed with K, M, or G, the specified size is parsed as Kilobytes, Megabytes, or Gigabytes, respectively, to the base of 1024. Defaults to unset and kernel default is used.
      sectionBFIFO = checkUnitConfig "BFIFO" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "LimitBytes"
        ])
      ];

      # [PFIFO] SECTION OPTIONS
      #  The [PFIFO] section manages the queueing discipline (qdisc) of Packet First In First Out (pfifo).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  PacketLimit=
      #      Specifies the hard limit on the number of packets in the FIFO queue. The size limit prevents overflow in case the kernel is unable to dequeue packets as quickly as it receives them. When this limit is reached, incoming
      #      packets are dropped. An unsigned integer in the range 0–4294967294. Defaults to unset and kernel's default is used.
      sectionPFIFO = checkUnitConfig "PFIFO" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "PacketLimit"
        ])
      ];

      # [PFIFOHEADDROP] SECTION OPTIONS
      #  The [PFIFOHeadDrop] section manages the queueing discipline (qdisc) of Packet First In First Out Head Drop (pfifo_head_drop).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  PacketLimit=
      #      As in [PFIFO] section.
      sectionPFIFOHeadDrop = checkUnitConfig "PFIFOHeadDrop" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "PacketLimit"
        ])
      ];

      # [PFIFOFAST] SECTION OPTIONS
      #  The [PFIFOFast] section manages the queueing discipline (qdisc) of Packet First In First Out Fast (pfifo_fast).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      sectionPFIFOFast = checkUnitConfig "PFIFOFast" [
        (assertOnlyFields [
          "Parent"
          "Handle"
        ])
      ];

      # [CAKE] SECTION OPTIONS
      #  The [CAKE] section manages the queueing discipline (qdisc) of Common Applications Kept Enhanced (CAKE).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  OverheadBytes=
      #      Specifies that bytes to be addeded to the size of each packet. Bytes may be negative. Takes an integer in the range from -64 to 256. Defaults to unset and kernel's default is used.
      #  Bandwidth=
      #      Specifies the shaper bandwidth. When suffixed with K, M, or G, the specified size is parsed as Kilobits, Megabits, or Gigabits, respectively, to the base of 1000. Defaults to unset and kernel's default is used.
      sectionCAKE = checkUnitConfig "CAKE" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "OverheadBytes"
          "Bandwidth"
        ])
      ];

      # [CONTROLLEDDELAY] SECTION OPTIONS
      #  The [ControlledDelay] section manages the queueing discipline (qdisc) of controlled delay (CoDel).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  PacketLimit=
      #      Specifies the hard limit on the queue size in number of packets. When this limit is reached, incoming packets are dropped. An unsigned integer in the range 0–4294967294. Defaults to unset and kernel's default is used.
      #  TargetSec=
      #      Takes a timespan. Specifies the acceptable minimum standing/persistent queue delay. Defaults to unset and kernel's default is used.
      #  IntervalSec=
      #      Takes a timespan. This is used to ensure that the measured minimum delay does not become too stale. Defaults to unset and kernel's default is used.
      #  ECN=
      #      Takes a boolean. This can be used to mark packets instead of dropping them. Defaults to unset and kernel's default is used.
      #  CEThresholdSec=
      #      Takes a timespan. This sets a threshold above which all packets are marked with ECN Congestion Experienced (CE). Defaults to unset and kernel's default is used.
      sectionControlledDelay = checkUnitConfig "ControlledDelay" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "PacketLimit"
          "TargetSec"
          "IntervalSec"
          "ECN"
          "CEThresholdSec"
        ])
      ];

      # [DEFICITROUNDROBINSCHEDULER] SECTION OPTIONS
      #  The [DeficitRoundRobinScheduler] section manages the queueing discipline (qdisc) of Deficit Round Robin Scheduler (DRR).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      sectionDeficitRoundRobinScheduler = checkUnitConfig "DeficitRoundRobinScheduler" [
        (assertOnlyFields [
          "Parent"
          "Handle"
        ])
      ];

      # [DEFICITROUNDROBINSCHEDULERCLASS] SECTION OPTIONS
      #  The [DeficitRoundRobinSchedulerClass] section manages the traffic control class of Deficit Round Robin Scheduler (DRR).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", or a qdisc identifier. The qdisc identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff separated with a
      #      colon ("major:minor"). Defaults to "root".
      #  ClassId=
      #      Configures the unique identifier of the class. It is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff separated with a colon ("major:minor"). Defaults to unset.
      #  QuantumBytes=
      #      Specifies the amount of bytes a flow is allowed to dequeue before the scheduler moves to the next class. When suffixed with K, M, or G, the specified size is parsed as Kilobytes, Megabytes, or Gigabytes, respectively, to
      #      the base of 1024. Defaults to the MTU of the interface.
      sectionDeficitRoundRobinSchedulerClass = checkUnitConfig "DeficitRoundRobinSchedulerClass" [
        (assertOnlyFields [
          "Parent"
          "ClassId"
          "QuantumBytes"
        ])
      ];

      # [ENHANCEDTRANSMISSIONSELECTION] SECTION OPTIONS
      #  The [EnhancedTransmissionSelection] section manages the queueing discipline (qdisc) of Enhanced Transmission Selection (ETS).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  Bands=
      #      Specifies the number of bands. An unsigned integer in the range 1–16. This value has to be at least large enough to cover the strict bands specified through the StrictBands= and bandwidth-sharing bands specified in
      #      QuantumBytes=.
      #  StrictBands=
      #      Specifies the number of bands that should be created in strict mode. An unsigned integer in the range 1–16.
      #  QuantumBytes=
      #      Specifies the white-space separated list of quantum used in band-sharing bands. When suffixed with K, M, or G, the specified size is parsed as Kilobytes, Megabytes, or Gigabytes, respectively, to the base of 1024. This
      #      setting can be specified multiple times. If an empty string is assigned, then the all previous assignments are cleared.
      #  PriorityMap=
      #      The priority map maps the priority of a packet to a band. The argument is a whitespace separated list of numbers. The first number indicates which band the packets with priority 0 should be put to, the second is for
      #      priority 1, and so on. There can be up to 16 numbers in the list. If there are fewer, the default band that traffic with one of the unmentioned priorities goes to is the last one. Each band number must be in the range
      #      0...255. This setting can be specified multiple times. If an empty string is assigned, then the all previous assignments are cleared.
      sectionEnhancedTransmissionSelection = checkUnitConfig "EnhancedTransmissionSelection" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "Bands"
          "StrictBands"
          "QuantumBytes"
          "PriorityMap"
        ])
      ];

      # [GENERICRANDOMEARLYDETECTION] SECTION OPTIONS
      #  The [GenericRandomEarlyDetection] section manages the queueing discipline (qdisc) of Generic Random Early Detection (GRED).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  VirtualQueues=
      #      Specifies the number of virtual queues. Takes an integer in the range 1...16. Defaults to unset and kernel's default is used.
      #  DefaultVirtualQueue=
      #      Specifies the number of default virtual queue. This must be less than VirtualQueue=. Defaults to unset and kernel's default is used.
      #  GenericRIO=
      #      Takes a boolean. It turns on the RIO-like buffering scheme. Defaults to unset and kernel's default is used.
      sectionGenericRandomEarlyDetection = checkUnitConfig "GenericRandomEarlyDetection" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "VirtualQueues"
          "DefaultVirtualQueue"
          "GenericRIO"
        ])
      ];

      # [FAIRQUEUEINGCONTROLLEDDELAY] SECTION OPTIONS
      #  The [FairQueueingControlledDelay] section manages the queueing discipline (qdisc) of fair queuing controlled delay (FQ-CoDel).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  PacketLimit=
      #      Specifies the hard limit on the real queue size. When this limit is reached, incoming packets are dropped. Defaults to unset and kernel's default is used.
      #  MemoryLimitBytes=
      #      Specifies the limit on the total number of bytes that can be queued in this FQ-CoDel instance. When suffixed with K, M, or G, the specified size is parsed as Kilobytes, Megabytes, or Gigabytes, respectively, to the base
      #      of 1024. Defaults to unset and kernel's default is used.
      #  Flows=
      #      Specifies the number of flows into which the incoming packets are classified. Defaults to unset and kernel's default is used.
      #  TargetSec=
      #      Takes a timespan. Specifies the acceptable minimum standing/persistent queue delay. Defaults to unset and kernel's default is used.
      #  IntervalSec=
      #      Takes a timespan. This is used to ensure that the measured minimum delay does not become too stale. Defaults to unset and kernel's default is used.
      #  QuantumBytes=
      #      Specifies the number of bytes used as the "deficit" in the fair queuing algorithm timespan. When suffixed with K, M, or G, the specified size is parsed as Kilobytes, Megabytes, or Gigabytes, respectively, to the base of
      #      1024. Defaults to unset and kernel's default is used.
      #  ECN=
      #      Takes a boolean. This can be used to mark packets instead of dropping them. Defaults to unset and kernel's default is used.
      #  CEThresholdSec=
      #      Takes a timespan. This sets a threshold above which all packets are marked with ECN Congestion Experienced (CE). Defaults to unset and kernel's default is used.
      sectionFairQueueingControlledDelay = checkUnitConfig "FairQueueingControlledDelay" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "PacketLimit"
          "MemoryLimitBytes"
          "Flows"
          "TargetSec"
          "IntervalSec"
          "QuantumBytes"
          "ECN"
          "CEThresholdSec"
        ])
      ];

      # [FAIRQUEUEING] SECTION OPTIONS
      #  The [FairQueueing] section manages the queueing discipline (qdisc) of fair queue traffic policing (FQ).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  PacketLimit=
      #      Specifies the hard limit on the real queue size. When this limit is reached, incoming packets are dropped. Defaults to unset and kernel's default is used.
      #  FlowLimit=
      #      Specifies the hard limit on the maximum number of packets queued per flow. Defaults to unset and kernel's default is used.
      #  QuantumBytes=
      #      Specifies the credit per dequeue RR round, i.e. the amount of bytes a flow is allowed to dequeue at once. When suffixed with K, M, or G, the specified size is parsed as Kilobytes, Megabytes, or Gigabytes, respectively,
      #      to the base of 1024. Defaults to unset and kernel's default is used.
      #  InitialQuantumBytes=
      #      Specifies the initial sending rate credit, i.e. the amount of bytes a new flow is allowed to dequeue initially. When suffixed with K, M, or G, the specified size is parsed as Kilobytes, Megabytes, or Gigabytes,
      #      respectively, to the base of 1024. Defaults to unset and kernel's default is used.
      #  MaximumRate=
      #      Specifies the maximum sending rate of a flow. When suffixed with K, M, or G, the specified size is parsed as Kilobits, Megabits, or Gigabits, respectively, to the base of 1000. Defaults to unset and kernel's default is
      #      used.
      #  Buckets=
      #      Specifies the size of the hash table used for flow lookups. Defaults to unset and kernel's default is used.
      #  OrphanMask=
      #      Takes an unsigned integer. For packets not owned by a socket, fq is able to mask a part of hash and reduce number of buckets associated with the traffic. Defaults to unset and kernel's default is used.
      #  Pacing=
      #      Takes a boolean, and enables or disables flow pacing. Defaults to unset and kernel's default is used.
      #  CEThresholdSec=
      #      Takes a timespan. This sets a threshold above which all packets are marked with ECN Congestion Experienced (CE). Defaults to unset and kernel's default is used.
      sectionFairQueueing = checkUnitConfig "FairQueueing" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "PacketLimit"
          "FlowLimit"
          "QuantumBytes"
          "InitialQuantumBytes"
          "MaximumRate"
          "Buckets"
          "OrphanMask"
          "Pacing"
          "CEThresholdSec"
        ])
      ];

      # [TRIVIALLINKEQUALIZER] SECTION OPTIONS
      #  The [TrivialLinkEqualizer] section manages the queueing discipline (qdisc) of trivial link equalizer (teql).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  Id=
      #      Specifies the interface ID "N" of teql. Defaults to "0". Note that when teql is used, currently, the module sch_teql with max_equalizers=N+1 option must be loaded before systemd-networkd is started.
      sectionTrivialLinkEqualizer = checkUnitConfig "TrivialLinkEqualizer" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "Id"
        ])
      ];

      # [HIERARCHYTOKENBUCKET] SECTION OPTIONS
      #  The [HierarchyTokenBucket] section manages the queueing discipline (qdisc) of hierarchy token bucket (htb).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  DefaultClass=
      #      Takes the minor id in hexadecimal of the default class. Unclassified traffic gets sent to the class. Defaults to unset.
      #  RateToQuantum=
      #      Takes an unsigned integer. The DRR quantums are calculated by dividing the value configured in Rate= by RateToQuantum=.
      sectionHierarchyTokenBucket = checkUnitConfig "HierarchyTokenBucket" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "DefaultClass"
          "RateToQuantum"
        ])
      ];
      # [HIERARCHYTOKENBUCKETCLASS] SECTION OPTIONS
      #  The [HierarchyTokenBucketClass] section manages the traffic control class of hierarchy token bucket (htb).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", or a qdisc identifier. The qdisc identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff separated with a
      #      colon ("major:minor"). Defaults to "root".
      #  ClassId=
      #      Configures the unique identifier of the class. It is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff separated with a colon ("major:minor"). Defaults to unset.
      #  Priority=
      #      Specifies the priority of the class. In the round-robin process, classes with the lowest priority field are tried for packets first.
      #  QuantumBytes=
      #      Specifies how many bytes to serve from leaf at once. When suffixed with K, M, or G, the specified size is parsed as Kilobytes, Megabytes, or Gigabytes, respectively, to the base of 1024.
      #  MTUBytes=
      #      Specifies the maximum packet size we create. When suffixed with K, M, or G, the specified size is parsed as Kilobytes, Megabytes, or Gigabytes, respectively, to the base of 1024.
      #  OverheadBytes=
      #      Takes an unsigned integer which specifies per-packet size overhead used in rate computations. When suffixed with K, M, or G, the specified size is parsed as Kilobytes, Megabytes, or Gigabytes, respectively, to the base
      #      of 1024.
      #  Rate=
      #      Specifies the maximum rate this class and all its children are guaranteed. When suffixed with K, M, or G, the specified size is parsed as Kilobits, Megabits, or Gigabits, respectively, to the base of 1000. This setting
      #      is mandatory.
      #  CeilRate=
      #      Specifies the maximum rate at which a class can send, if its parent has bandwidth to spare. When suffixed with K, M, or G, the specified size is parsed as Kilobits, Megabits, or Gigabits, respectively, to the base of
      #      1000. When unset, the value specified with Rate= is used.
      #  BufferBytes=
      #      Specifies the maximum bytes burst which can be accumulated during idle period. When suffixed with K, M, or G, the specified size is parsed as Kilobytes, Megabytes, or Gigabytes, respectively, to the base of 1024.
      #  CeilBufferBytes=
      #      Specifies the maximum bytes burst for ceil which can be accumulated during idle period. When suffixed with K, M, or G, the specified size is parsed as Kilobytes, Megabytes, or Gigabytes, respectively, to the base of
      #      1024.
      sectionHierarchyTokenBucketClass = checkUnitConfig "HierarchyTokenBucketClass" [
        (assertOnlyFields [
          "Parent"
          "ClassId"
          "Priority"
          "QuantumBytes"
          "MTUBytes"
          "OverheadBytes"
          "Rate"
          "CeilRate"
          "BufferBytes"
          "CeilBufferBytes"
        ])
      ];

      # [HEAVYHITTERFILTER] SECTION OPTIONS
      #  The [HeavyHitterFilter] section manages the queueing discipline (qdisc) of Heavy Hitter Filter (hhf).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      #  PacketLimit=
      #      Specifies the hard limit on the queue size in number of packets. When this limit is reached, incoming packets are dropped. An unsigned integer in the range 0–4294967294. Defaults to unset and kernel's default is used.
      sectionHeavyHitterFilter = checkUnitConfig "HeavyHitterFilter" [
        (assertOnlyFields [
          "Parent"
          "Handle"
          "PacketLimit"
        ])
      ];

      # [QUICKFAIRQUEUEING] SECTION OPTIONS
      #  The [QuickFairQueueing] section manages the queueing discipline (qdisc) of Quick Fair Queueing (QFQ).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", "clsact", "ingress" or a class identifier. The class identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff
      #      separated with a colon ("major:minor"). Defaults to "root".
      #  Handle=
      #      Configures the major number of unique identifier of the qdisc, known as the handle. Takes a hexadecimal number in the range 0x1–0xffff. Defaults to unset.
      sectionQuickFairQueueing = checkUnitConfig "QuickFairQueueing" [
        (assertOnlyFields [
          "Parent"
          "Handle"
        ])
      ];

      # [QUICKFAIRQUEUEINGCLASS] SECTION OPTIONS
      #  The [QuickFairQueueingClass] section manages the traffic control class of Quick Fair Queueing (qfq).
      #  Parent=
      #      Configures the parent Queueing Discipline (qdisc). Takes one of "root", or a qdisc identifier. The qdisc identifier is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff separated with a
      #      colon ("major:minor"). Defaults to "root".
      #  ClassId=
      #      Configures the unique identifier of the class. It is specified as the major and minor numbers in hexadecimal in the range 0x1–Oxffff separated with a colon ("major:minor"). Defaults to unset.
      #  Weight=
      #      Specifies the weight of the class. Takes an integer in the range 1...1023. Defaults to unset in which case the kernel default is used.
      #  MaxPacketBytes=
      #      Specifies the maximum packet size in bytes for the class. When suffixed with K, M, or G, the specified size is parsed as Kilobytes, Megabytes, or Gigabytes, respectively, to the base of 1024. When unset, the kernel
      #      default is used.
      sectionQuickFairQueueingClass = checkUnitConfig "QuickFairQueueingClass" [
        (assertOnlyFields [
          "Parent"
          "ClassId"
          "Weight"
          "MaxPacketBytes"
        ])
      ];

      # [BRIDGEVLAN] SECTION OPTIONS
      #  The [BridgeVLAN] section manages the VLAN ID configuration of a bridge port and accepts the following keys. Specify several [BridgeVLAN] sections to configure several VLAN entries. The VLANFiltering= option has to be
      #  enabled, see the [Bridge] section in systemd.netdev(5).
      #  VLAN=
      #      The VLAN ID allowed on the port. This can be either a single ID or a range M-N. VLAN IDs are valid from 1 to 4094.
      #  EgressUntagged=
      #      The VLAN ID specified here will be used to untag frames on egress. Configuring EgressUntagged= implicates the use of VLAN= above and will enable the VLAN ID for ingress as well. This can be either a single ID or a range
      #      M-N.
      #  PVID=
      #      The Port VLAN ID specified here is assigned to all untagged frames at ingress.  PVID= can be used only once. Configuring PVID= implicates the use of VLAN= above and will enable the VLAN ID for ingress as well.
      sectionBridgeVLAN = checkUnitConfig "BridgeVLAN" [
        (assertOnlyFields [
          "VLAN"
          "EgressUntagged"
          "PVID"
        ])
      ];

      sectionDHCPServerStaticLease = checkUnitConfig "DHCPServerStaticLease" [
        (assertOnlyFields [
          "MACAddress"
          "Address"
        ])
        (assertHasField "MACAddress")
        (assertHasField "Address")
        (assertMacAddress "MACAddress")
      ];

    };
  };

  commonNetworkOptions = {

    enable = mkOption {
      default = true;
      type = types.bool;
      description = ''
        Whether to manage network configuration using <command>systemd-network</command>.
      '';
    };

    matchConfig = mkOption {
      default = {};
      example = { Name = "eth0"; };
      type = types.attrsOf unitOption;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[Match]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.link</refentrytitle><manvolnum>5</manvolnum></citerefentry>
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle><manvolnum>5</manvolnum></citerefentry>
        <citerefentry><refentrytitle>systemd.network</refentrytitle><manvolnum>5</manvolnum></citerefentry>
        for details.
      '';
    };

    extraConfig = mkOption {
      default = "";
      type = types.lines;
      description = "Extra configuration append to unit";
    };
  };

  linkOptions = commonNetworkOptions // {
    # overwrite enable option from above
    enable = mkOption {
      default = true;
      type = types.bool;
      description = ''
        Whether to enable this .link unit. It's handled by udev no matter if <command>systemd-networkd</command> is enabled or not
      '';
    };

    linkConfig = mkOption {
      default = {};
      example = { MACAddress = "00:ff:ee:aa:cc:dd"; };
      type = types.addCheck (types.attrsOf unitOption) check.link.sectionLink;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[Link]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.link</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

  };

  l2tpSessionOptions = {
    options = {
      l2tpSessionConfig = mkOption {
        default = {};
        type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionL2TPSession;
        description = ''
          Each attribute in this set specifies an option in the
          <literal>[L2TPSession]</literal> section of the unit.  See
          <citerefentry><refentrytitle>systemd.network</refentrytitle>
          <manvolnum>5</manvolnum></citerefentry> for details.
        '';
      };
    };
  };

  wireguardPeerOptions = {
    options = {
      wireguardPeerConfig = mkOption {
        default = {};
        type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionWireGuardPeer;
        description = ''
          Each attribute in this set specifies an option in the
          <literal>[WireGuardPeer]</literal> section of the unit.  See
          <citerefentry><refentrytitle>systemd.network</refentrytitle>
          <manvolnum>5</manvolnum></citerefentry> for details.
        '';
      };
    };
  };

  netdevOptions = commonNetworkOptions // {

    netdevConfig = mkOption {
      example = { Name = "mybridge"; Kind = "bridge"; };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionNetdev;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[Netdev]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    bridgeConfig = mkOption {
      default = {};
      example = { VLANProtocol = "802.1ad"; };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionBridge;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[Bridge]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    vlanConfig = mkOption {
      default = {};
      example = { Id = 4; };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionVLAN;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[VLAN]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    macvlanConfig = mkOption {
      default = {};
      example = { Mode = "private"; };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionMACVLAN;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[MACVLAN]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    macvtapConfig = mkOption {
      default = {};
      example = { Mode = "private"; };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionMACVTAP;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[MACVTAP]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    ipvlanConfig = mkOption {
      default = {};
      example = { Mode = "L2"; };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionIPVLAN;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[IPVLAN]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    ipvtapConfig = mkOption {
      default = {};
      example = { Mode = "L2"; };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionIPVTAP;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[IPVTAP]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    vxlanConfig = mkOption {
      default = {};
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionVXLAN;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[VXLAN]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    geneveConfig = mkOption {
      default = {};
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionGENEVE;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[GENEVE]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    bareudpConfig = mkOption {
      default = {};
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionBareUDP;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[BareUDP]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    l2tpConfig = mkOption {
      default = {};
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionL2TP;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[L2TP]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    l2tpSessionConfig = mkOption {
      default = {};
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionL2TPSession;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[L2TPSession]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    l2tpSessions = mkOption {
      default = [];
      example = [ { l2tpSessionConfig={
        Name = "test";
        SessionId = 24;
        PeerSessionId = 42;
      };}];
      type = with types; listOf (submodule l2tpSessionOptions);
      description = ''
        Each item in this array specifies an option in the
        <literal>[WireGuardPeer]</literal> section of the unit. See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
        Use <literal>PresharedKeyFile</literal> instead of
        <literal>PresharedKey</literal>: the nix store is
        world-readable.
      '';
    };

    macsecConfig = mkOption {
      default = {};
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionMACsec;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[MACsec]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    macsecReceiveChannelConfig = mkOption {
      default = {};
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionMACsecReceiveChannel;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[MACsecReceiveChannel]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    macsecTransmitAssociationConfig = mkOption {
      default = {};
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionMACsecTransmitAssociation;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[MACsecTransmitAssociation]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    macsecReceiveAssociationConfig = mkOption {
      default = {};
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionMACsecReceiveAssociation;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[MACsecReceiveAssociation]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    tunnelConfig = mkOption {
      default = {};
      example = { Remote = "192.168.1.1"; };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionTunnel;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[Tunnel]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    fooOverUDPConfig = mkOption {
      default = { };
      example = { Port = 9001; };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionFooOverUDP;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[FooOverUDP]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    peerConfig = mkOption {
      default = {};
      example = { Name = "veth2"; };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionPeer;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[Peer]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    vxcanConfig = mkOption {
      default = {};
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionVXCAN;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[VXCAN]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    tunConfig = mkOption {
      default = {};
      example = { User = "openvpn"; };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionTun;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[Tun]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    tapConfig = mkOption {
      default = {};
      example = { User = "openvpn"; };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionTap;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[Tap]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    wireguardConfig = mkOption {
      default = {};
      example = {
        PrivateKeyFile = "/etc/wireguard/secret.key";
        ListenPort = 51820;
        FirewallMark = 42;
      };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionWireGuard;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[WireGuard]</literal> section of the unit. See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
        Use <literal>PrivateKeyFile</literal> instead of
        <literal>PrivateKey</literal>: the nix store is
        world-readable.
      '';
    };

    wireguardPeers = mkOption {
      default = [];
      example = [ { wireguardPeerConfig={
        Endpoint = "192.168.1.1:51820";
        PublicKey = "27s0OvaBBdHoJYkH9osZpjpgSOVNw+RaKfboT/Sfq0g=";
        PresharedKeyFile = "/etc/wireguard/psk.key";
        AllowedIPs = [ "10.0.0.1/32" ];
        PersistentKeepalive = 15;
      };}];
      type = with types; listOf (submodule wireguardPeerOptions);
      description = ''
        Each item in this array specifies an option in the
        <literal>[WireGuardPeer]</literal> section of the unit. See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
        Use <literal>PresharedKeyFile</literal> instead of
        <literal>PresharedKey</literal>: the nix store is
        world-readable.
      '';
    };

    bondConfig = mkOption {
      default = {};
      example = { Mode = "802.3ad"; };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionBond;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[Bond]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    xfrmConfig = mkOption {
      default = {};
      example = { InterfaceId = 1; };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionXfrm;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[Xfrm]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    vrfConfig = mkOption {
      default = {};
      example = { Table = 2342; };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionVRF;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[VRF]</literal> section of the unit. See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
        A detailed explanation about how VRFs work can be found in the
        <link xlink:href="https://www.kernel.org/doc/Documentation/networking/vrf.txt">kernel
        docs</link>.
      '';
    };

    batmanAdvancedConfig = mkOption {
      default = {};
      example = {
        GatewayMode = "server";
        RoutingAlgorithm = "batman-v";
      };
      type = types.addCheck (types.attrsOf unitOption) check.netdev.sectionBatmanAdvanced;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[BatmanAdvanced]</literal> section of the unit. See
        <citerefentry><refentrytitle>systemd.netdev</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

  };

  addressOptions = {
    options = {
      addressConfig = mkOption {
        example = { Address = "192.168.0.100/24"; };
        type = types.addCheck (types.attrsOf unitOption) check.network.sectionAddress;
        description = ''
          Each attribute in this set specifies an option in the
          <literal>[Address]</literal> section of the unit.  See
          <citerefentry><refentrytitle>systemd.network</refentrytitle>
          <manvolnum>5</manvolnum></citerefentry> for details.
        '';
      };
    };
  };

  neighborConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionNeighbor;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[Neighbor]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };

  ipv6AddressLabelConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionIPv6AddressLabel;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[IPv6AddressLabel]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };

  routingPolicyRulesOptions = {
    options = {
      routingPolicyRuleConfig = mkOption {
        default = { };
        example = { Table = 10; IncomingInterface = "eth1"; Family = "both"; };
        type = types.addCheck (types.attrsOf unitOption) check.network.sectionRoutingPolicyRule;
        description = ''
          Each attribute in this set specifies an option in the
          <literal>[RoutingPolicyRule]</literal> section of the unit.  See
          <citerefentry><refentrytitle>systemd.network</refentrytitle>
          <manvolnum>5</manvolnum></citerefentry> for details.
        '';
      };
    };
  };

  nextHopConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionNextHop;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[NextHop]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };

  routeOptions = {
    options = {
      routeConfig = mkOption {
        default = {};
        example = { Gateway = "192.168.0.1"; };
        type = types.addCheck (types.attrsOf unitOption) check.network.sectionRoute;
        description = ''
          Each attribute in this set specifies an option in the
          <literal>[Route]</literal> section of the unit.  See
          <citerefentry><refentrytitle>systemd.network</refentrytitle>
          <manvolnum>5</manvolnum></citerefentry> for details.
        '';
      };
    };
  };

  ipv6PrefixOptions = {
    options = {
      ipv6PrefixConfig = mkOption {
        default = {};
        example = { Prefix = "fd00::/64"; };
        type = types.addCheck (types.attrsOf unitOption) check.network.sectionIPv6Prefix;
        description = ''
          Each attribute in this set specifies an option in the
          <literal>[IPv6Prefix]</literal> section of the unit.  See
          <citerefentry><refentrytitle>systemd.network</refentrytitle>
          <manvolnum>5</manvolnum></citerefentry> for details.
        '';
      };
    };
  };

  ipv6RoutePrefixConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionIPv6RoutePrefix;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[IPv6RoutePrefix]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  bridgeConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionBridge;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[Bridge]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  bridgeFDBConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionBridgeFDB;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[BridgeFDB]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  bridgeMDBConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionBridgeMDB;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[BridgeMDB]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  lldpConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionLLDP;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[LLDP]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  canConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionCAN;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[CAN]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  qDiscConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionQDisc;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[QDisc]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  networkEmulatorConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionNetworkEmulator;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[NetworkEmulator]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  tokenBucketFilterConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionTokenBucketFilter;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[TokenBucketFilter]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  pieConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionPIE;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[PIE]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  flowQueuePIEConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionFlowQueuePIE;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[FlowQueuePIE]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  stochasticFairBlueConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionStochasticFairBlue;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[StochasticFairBlue]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  stochasticFairnessQueueingConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionStochasticFairnessQueueing;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[StochasticFairnessQueueing]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  bfifoConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionBFIFO;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[BFIFO]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  pfifoConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionPFIFO;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[PFIFO]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  pfifoHeadDropConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionPFIFOHeadDrop;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[PFIFOHeadDrop]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  pfifoFastConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionPFIFOFast;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[PFIFOFast]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  cakeConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionCAKE;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[CAKE]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  controlledDelayConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionControlledDelay;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[ControlledDelay]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  deficitRoundRobinSchedulerConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionDeficitRoundRobinScheduler;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[DeficitRoundRobinScheduler]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  deficitRoundRobinSchedulerClassConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionDeficitRoundRobinSchedulerClass;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[DeficitRoundRobinSchedulerClass]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  enhancedTransmissionSelectionConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionEnhancedTransmissionSelection;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[EnhancedTransmissionSelection]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  genericRandomEarlyDetectionConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionGenericRandomEarlyDetection;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[GenericRandomEarlyDetection]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  fairQueueingControlledDelayConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionFairQueueingControlledDelay;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[FairQueueingControlledDelay]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  fairQueueingConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionFairQueueing;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[FairQueueing]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  trivialLinkEqualizerConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionTrivialLinkEqualizer;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[TrivialLinkEqualizer]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  hierarchyTokenBucketConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionHierarchyTokenBucket;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[HierarchyTokenBucket]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  hierarchyTokenBucketClassConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionHierarchyTokenBucketClass;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[HierarchyTokenBucketClass]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  heavyHitterFilterConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionHeavyHitterFilter;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[HeavyHitterFilter]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  quickFairQueueingConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionQuickFairQueueing;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[QuickFairQueueing]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  quickFairQueueingClassConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionQuickFairQueueingClass;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[QuickFairQueueingClass]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };
  bridgeVLANConfig = mkOption {
    default = {};
    type = types.addCheck (types.attrsOf unitOption) check.network.sectionBridgeVLAN;
    description = ''
      Each attribute in this set specifies an option in the
      <literal>[BridgeVLAN]</literal> section of the unit.  See
      <citerefentry><refentrytitle>systemd.network</refentrytitle>
      <manvolnum>5</manvolnum></citerefentry> for details.
    '';
  };

  dhcpServerStaticLeaseOptions = {
    options = {
      dhcpServerStaticLeaseConfig = mkOption {
        default = {};
        example = { MACAddress = "65:43:4a:5b:d8:5f"; Address = "192.168.1.42"; };
        type = types.addCheck (types.attrsOf unitOption) check.network.sectionDHCPServerStaticLease;
        description = ''
          Each attribute in this set specifies an option in the
          <literal>[DHCPServerStaticLease]</literal> section of the unit.  See
          <citerefentry><refentrytitle>systemd.network</refentrytitle>
          <manvolnum>5</manvolnum></citerefentry> for details.

          Make sure to configure the corresponding client interface to use
          <literal>ClientIdentifier=mac</literal>.
        '';
      };
    };
  };

  networkOptions = commonNetworkOptions // {

    linkConfig = mkOption {
      default = {};
      example = { Unmanaged = true; };
      type = types.addCheck (types.attrsOf unitOption) check.network.sectionLink;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[Link]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    networkConfig = mkOption {
      default = {};
      example = { Description = "My Network"; };
      type = types.addCheck (types.attrsOf unitOption) check.network.sectionNetwork;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[Network]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    # systemd.network.networks.*.dhcpConfig has been deprecated in favor of ….dhcpV4Config
    # Produce a nice warning message so users know it is gone.
    dhcpConfig = mkOption {
      visible = false;
      apply = _: throw "The option `systemd.network.networks.*.dhcpConfig` can no longer be used since it's been removed. Please use `systemd.network.networks.*.dhcpV4Config` instead.";
    };

    dhcpV4Config = mkOption {
      default = {};
      example = { UseDNS = true; UseRoutes = true; };
      type = types.addCheck (types.attrsOf unitOption) check.network.sectionDHCPv4;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[DHCPv4]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    dhcpV6Config = mkOption {
      default = {};
      example = { UseDNS = true; };
      type = types.addCheck (types.attrsOf unitOption) check.network.sectionDHCPv6;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[DHCPv6]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    dhcpV6PrefixDelegationConfig = mkOption {
      default = {};
      example = { SubnetId = "auto"; Announce = true; };
      type = types.addCheck (types.attrsOf unitOption) check.network.sectionDHCPv6PrefixDelegation;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[DHCPv6PrefixDelegation]</literal> section of the unit. See
        <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    ipv6AcceptRAConfig = mkOption {
      default = {};
      example = { UseDNS = true; DHCPv6Client = "always"; };
      type = types.addCheck (types.attrsOf unitOption) check.network.sectionIPv6AcceptRA;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[IPv6AcceptRA]</literal> section of the unit. See
        <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    dhcpServerConfig = mkOption {
      default = {};
      example = { PoolOffset = 50; EmitDNS = false; };
      type = types.addCheck (types.attrsOf unitOption) check.network.sectionDHCPServer;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[DHCPServer]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    # systemd.network.networks.*.ipv6PrefixDelegationConfig has been deprecated
    # in 247 in favor of systemd.network.networks.*.ipv6SendRAConfig.
    ipv6PrefixDelegationConfig = mkOption {
      visible = false;
      apply = _: throw "The option `systemd.network.networks.*.ipv6PrefixDelegationConfig` has been replaced by `systemd.network.networks.*.ipv6SendRAConfig`.";
    };

    ipv6SendRAConfig = mkOption {
      default = {};
      example = { EmitDNS = true; Managed = true; OtherInformation = true; };
      type = types.addCheck (types.attrsOf unitOption) check.network.sectionIPv6SendRA;
      description = ''
        Each attribute in this set specifies an option in the
        <literal>[IPv6SendRA]</literal> section of the unit.  See
        <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    dhcpServerStaticLeases = mkOption {
      default = [];
      example = [ { MACAddress = "65:43:4a:5b:d8:5f"; Address = "192.168.1.42"; } ];
      type = with types; listOf (submodule dhcpServerStaticLeaseOptions);
      description = ''
        A list of DHCPServerStaticLease sections to be added to the unit.  See
        <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    ipv6Prefixes = mkOption {
      default = [];
      example = [ { AddressAutoconfiguration = true; OnLink = true; } ];
      type = with types; listOf (submodule ipv6PrefixOptions);
      description = ''
        A list of ipv6Prefix sections to be added to the unit.  See
        <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    name = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        The name of the network interface to match against.
      '';
    };

    DHCP = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Whether to enable DHCP on the interfaces matched.
      '';
    };

    domains = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = ''
        A list of domains to pass to the network config.
      '';
    };

    address = mkOption {
      default = [ ];
      type = types.listOf types.str;
      description = ''
        A list of addresses to be added to the network section of the
        unit.  See <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    gateway = mkOption {
      default = [ ];
      type = types.listOf types.str;
      description = ''
        A list of gateways to be added to the network section of the
        unit.  See <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    dns = mkOption {
      default = [ ];
      type = types.listOf types.str;
      description = ''
        A list of dns servers to be added to the network section of the
        unit.  See <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    ntp = mkOption {
      default = [ ];
      type = types.listOf types.str;
      description = ''
        A list of ntp servers to be added to the network section of the
        unit.  See <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    bridge = mkOption {
      default = [ ];
      type = types.listOf types.str;
      description = ''
        A list of bridge interfaces to be added to the network section of the
        unit.  See <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    bond = mkOption {
      default = [ ];
      type = types.listOf types.str;
      description = ''
        A list of bond interfaces to be added to the network section of the
        unit.  See <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    vrf = mkOption {
      default = [ ];
      type = types.listOf types.str;
      description = ''
        A list of vrf interfaces to be added to the network section of the
        unit.  See <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    vlan = mkOption {
      default = [ ];
      type = types.listOf types.str;
      description = ''
        A list of vlan interfaces to be added to the network section of the
        unit.  See <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    macvlan = mkOption {
      default = [ ];
      type = types.listOf types.str;
      description = ''
        A list of macvlan interfaces to be added to the network section of the
        unit.  See <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    vxlan = mkOption {
      default = [ ];
      type = types.listOf types.str;
      description = ''
        A list of vxlan interfaces to be added to the network section of the
        unit.  See <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    tunnel = mkOption {
      default = [ ];
      type = types.listOf types.str;
      description = ''
        A list of tunnel interfaces to be added to the network section of the
        unit.  See <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    xfrm = mkOption {
      default = [ ];
      type = types.listOf types.str;
      description = ''
        A list of xfrm interfaces to be added to the network section of the
        unit.  See <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    addresses = mkOption {
      default = [ ];
      type = with types; listOf (submodule addressOptions);
      description = ''
        A list of address sections to be added to the unit.  See
        <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    routingPolicyRules = mkOption {
      default = [ ];
      type = with types; listOf (submodule routingPolicyRulesOptions);
      description = ''
        A list of routing policy rules sections to be added to the unit.  See
        <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

    routes = mkOption {
      default = [ ];
      type = with types; listOf (submodule routeOptions);
      description = ''
        A list of route sections to be added to the unit.  See
        <citerefentry><refentrytitle>systemd.network</refentrytitle>
        <manvolnum>5</manvolnum></citerefentry> for details.
      '';
    };

  };

  networkConfig = { config, ... }: {
    config = {
      matchConfig = optionalAttrs (config.name != null) {
        Name = config.name;
      };
      networkConfig = optionalAttrs (config.DHCP != null) {
        DHCP = config.DHCP;
      } // optionalAttrs (config.domains != null) {
        Domains = concatStringsSep " " config.domains;
      };
    };
  };

  commonMatchText = def: optionalString (def.matchConfig != { }) ''
    [Match]
    ${attrsToSection def.matchConfig}
  '';

  linkToUnit = name: def:
    { inherit (def) enable;
      text = commonMatchText def
        + ''
          [Link]
          ${attrsToSection def.linkConfig}
        ''
        + def.extraConfig;
    };

  netdevToUnit = name: def:
    { inherit (def) enable;
      text = commonMatchText def
        + ''
          [NetDev]
          ${attrsToSection def.netdevConfig}
        ''
        + optionalString (def.bridgeConfig != { }) ''
          [Bridge]
          ${attrsToSection def.bridgeConfig}
        ''
        + optionalString (def.vlanConfig != { }) ''
          [VLAN]
          ${attrsToSection def.vlanConfig}
        ''
        + optionalString (def.macvlanConfig != { }) ''
          [MACVLAN]
          ${attrsToSection def.macvlanConfig}
        ''
        + optionalString (def.macvtapConfig != { }) ''
          [MACVTAP]
          ${attrsToSection def.macvtapConfig}
        ''
        + optionalString (def.ipvlanConfig != { }) ''
          [IPVLAN]
          ${attrsToSection def.ipvlanConfig}
        ''
        + optionalString (def.ipvtapConfig != { }) ''
          [IPVTAP]
          ${attrsToSection def.ipvtapConfig}
        ''
        + optionalString (def.vxlanConfig != { }) ''
          [VXLAN]
          ${attrsToSection def.vxlanConfig}
        ''
        + optionalString (def.geneveConfig != { }) ''
          [GENEVE]
          ${attrsToSection def.geneveConfig}
        ''
        + optionalString (def.bareudpConfig != { }) ''
          [BareUDP]
          ${attrsToSection def.bareudpConfig}
        ''
        + optionalString (def.l2tpConfig != { }) ''
          [L2TP]
          ${attrsToSection def.l2tpConfig}
        ''
        + flip concatMapStrings def.addresses (x: ''
          [L2TPSession]
          ${attrsToSection x.l2tpSessionConfig}
        '')
        + optionalString (def.macsecConfig != { }) ''
          [MACsec]
          ${attrsToSection def.macsecConfig}
        ''
        + optionalString (def.macsecReceiveChannelConfig != { }) ''
          [MACsecReceiveChannel]
          ${attrsToSection def.macsecReceiveChannelConfig}
        ''
        + optionalString (def.macsecTransmitAssociationConfig != { }) ''
          [MACsecTransmitAssociation]
          ${attrsToSection def.macsecTransmitAssociationConfig}
        ''
        + optionalString (def.macsecReceiveAssociationConfig != { }) ''
          [MACsecReceiveAssociation]
          ${attrsToSection def.macsecReceiveAssociationConfig}
        ''
        + optionalString (def.tunnelConfig != { }) ''
          [Tunnel]
          ${attrsToSection def.tunnelConfig}
        ''
        + optionalString (def.fooOverUDPConfig != { }) ''
          [FooOverUDP]
          ${attrsToSection def.fooOverUDPConfig}
        ''
        + optionalString (def.peerConfig != { }) ''
          [Peer]
          ${attrsToSection def.peerConfig}
        ''
        + optionalString (def.vxcanConfig != { }) ''
          [VXCAN]
          ${attrsToSection def.vxcanConfig}
        ''
        + optionalString (def.tunConfig != { }) ''
          [Tun]
          ${attrsToSection def.tunConfig}
        ''
        + optionalString (def.tapConfig != { }) ''
          [Tap]
          ${attrsToSection def.tapConfig}
        ''
        + optionalString (def.wireguardConfig != { }) ''
          [WireGuard]
          ${attrsToSection def.wireguardConfig}
        ''
        + flip concatMapStrings def.wireguardPeers (x: ''
          [WireGuardPeer]
          ${attrsToSection x.wireguardPeerConfig}
        '')
        + optionalString (def.bondConfig != { }) ''
          [Bond]
          ${attrsToSection def.bondConfig}
        ''
        + optionalString (def.xfrmConfig != { }) ''
          [Xfrm]
          ${attrsToSection def.xfrmConfig}
        ''
        + optionalString (def.vrfConfig != { }) ''
          [VRF]
          ${attrsToSection def.vrfConfig}
        ''
        + optionalString (def.batmanAdvancedConfig != { }) ''
          [BatmanAdvanced]
          ${attrsToSection def.batmanAdvancedConfig}
        ''
        + def.extraConfig;
    };

  networkToUnit = name: def:
    { inherit (def) enable;
      text = commonMatchText def
        + optionalString (def.linkConfig != { }) ''
          [Link]
          ${attrsToSection def.linkConfig}
        ''
        + ''
          [Network]
        ''
        + attrsToSection def.networkConfig
        + optionalString (def.address != [ ]) ''
          ${concatStringsSep "\n" (map (s: "Address=${s}") def.address)}
        ''
        + optionalString (def.gateway != [ ]) ''
          ${concatStringsSep "\n" (map (s: "Gateway=${s}") def.gateway)}
        ''
        + optionalString (def.dns != [ ]) ''
          ${concatStringsSep "\n" (map (s: "DNS=${s}") def.dns)}
        ''
        + optionalString (def.ntp != [ ]) ''
          ${concatStringsSep "\n" (map (s: "NTP=${s}") def.ntp)}
        ''
        + optionalString (def.bridge != [ ]) ''
          ${concatStringsSep "\n" (map (s: "Bridge=${s}") def.bridge)}
        ''
        + optionalString (def.bond != [ ]) ''
          ${concatStringsSep "\n" (map (s: "Bond=${s}") def.bond)}
        ''
        + optionalString (def.vrf != [ ]) ''
          ${concatStringsSep "\n" (map (s: "VRF=${s}") def.vrf)}
        ''
        + optionalString (def.vlan != [ ]) ''
          ${concatStringsSep "\n" (map (s: "VLAN=${s}") def.vlan)}
        ''
        + optionalString (def.macvlan != [ ]) ''
          ${concatStringsSep "\n" (map (s: "MACVLAN=${s}") def.macvlan)}
        ''
        + optionalString (def.vxlan != [ ]) ''
          ${concatStringsSep "\n" (map (s: "VXLAN=${s}") def.vxlan)}
        ''
        + optionalString (def.tunnel != [ ]) ''
          ${concatStringsSep "\n" (map (s: "Tunnel=${s}") def.tunnel)}
        ''
        + optionalString (def.xfrm != [ ]) ''
          ${concatStringsSep "\n" (map (s: "Xfrm=${s}") def.xfrm)}
        ''
        + ''

        ''
        + flip concatMapStrings def.addresses (x: ''
          [Address]
          ${attrsToSection x.addressConfig}
        '')
        + optionalString (def.neighborConfig != { }) ''
          [Neighbor]
          ${attrsToSection def.neighborConfig}
        ''
        + optionalString (def.ipv6AddressLabelConfig != { }) ''
          [IPv6AddressLabel]
          ${attrsToSection def.ipv6AddressLabelConfig}
        ''
        + flip concatMapStrings def.routingPolicyRules (x: ''
          [RoutingPolicyRule]
          ${attrsToSection x.routingPolicyRuleConfig}
        '')
        + optionalString (def.nextHopConfig != { }) ''
          [NextHop]
          ${attrsToSection def.nextHopConfig}
        ''
        + flip concatMapStrings def.routes (x: ''
          [Route]
          ${attrsToSection x.routeConfig}
        '')
        + optionalString (def.dhcpV4Config != { }) ''
          [DHCPv4]
          ${attrsToSection def.dhcpV4Config}
        ''
        + optionalString (def.dhcpV6Config != { }) ''
          [DHCPv6]
          ${attrsToSection def.dhcpV6Config}
        ''
        + optionalString (def.dhcpV6PrefixDelegationConfig != { }) ''
          [DHCPv6PrefixDelegation]
          ${attrsToSection def.dhcpV6PrefixDelegationConfig}
        ''
        + optionalString (def.ipv6AcceptRAConfig != { }) ''
          [IPv6AcceptRA]
          ${attrsToSection def.ipv6AcceptRAConfig}
        ''
        + optionalString (def.dhcpServerConfig != { }) ''
          [DHCPServer]
          ${attrsToSection def.dhcpServerConfig}
        ''
        + optionalString (def.ipv6SendRAConfig != { }) ''
          [IPv6SendRA]
          ${attrsToSection def.ipv6SendRAConfig}
        ''
        + flip concatMapStrings def.ipv6Prefixes (x: ''
          [IPv6Prefix]
          ${attrsToSection x.ipv6PrefixConfig}
        '')
        + optionalString (def.ipv6RoutePrefixConfig != { }) ''
          [IPv6RoutePrefix]
          ${attrsToSection def.ipv6RoutePrefixConfig}
        ''
        + optionalString (def.bridgeConfig != { }) ''
          [Bridge]
          ${attrsToSection def.bridgeConfig}
        ''
        + optionalString (def.bridgeFDBConfig != { }) ''
          [BridgeFDB]
          ${attrsToSection def.bridgeFDBConfig}
        ''
        + optionalString (def.bridgeMDBConfig != { }) ''
          [BridgeMDB]
          ${attrsToSection def.bridgeMDBConfig}
        ''
        + optionalString (def.lldpConfig != { }) ''
          [LLDP]
          ${attrsToSection def.lldpConfig}
        ''
        + optionalString (def.canConfig != { }) ''
          [CAN]
          ${attrsToSection def.canConfig}
        ''
        + optionalString (def.qDiscConfig != { }) ''
          [QDisc]
          ${attrsToSection def.qDiscConfig}
        ''
        + optionalString (def.networkEmulatorConfig != { }) ''
          [NetworkEmulator]
          ${attrsToSection def.networkEmulatorConfig}
        ''
        + optionalString (def.tokenBucketFilterConfig != { }) ''
          [TokenBucketFilter]
          ${attrsToSection def.tokenBucketFilterConfig}
        ''
        + optionalString (def.pieConfig != { }) ''
          [PIE]
          ${attrsToSection def.pieConfig}
        ''
        + optionalString (def.flowQueuePIEConfig != { }) ''
          [FlowQueuePIE]
          ${attrsToSection def.flowQueuePIEConfig}
        ''
        + optionalString (def.stochasticFairBlueConfig != { }) ''
          [StochasticFairBlue]
          ${attrsToSection def.stochasticFairBlueConfig}
        ''
        + optionalString (def.stochasticFairnessQueueingConfig != { }) ''
          [StochasticFairnessQueueing]
          ${attrsToSection def.stochasticFairnessQueueingConfig}
        ''
        + optionalString (def.bfifoConfig != { }) ''
          [BFIFO]
          ${attrsToSection def.bfifoConfig}
        ''
        + optionalString (def.pfifoConfig != { }) ''
          [PFIFO]
          ${attrsToSection def.pfifoConfig}
        ''
        + optionalString (def.pfifoHeadDropConfig != { }) ''
          [PFIFOHeadDrop]
          ${attrsToSection def.pfifoHeadDropConfig}
        ''
        + optionalString (def.pfifoFastConfig != { }) ''
          [PFIFOFast]
          ${attrsToSection def.pfifoFastConfig}
        ''
        + optionalString (def.cakeConfig != { }) ''
          [CAKE]
          ${attrsToSection def.cakeConfig}
        ''
        + optionalString (def.controlledDelayConfig != { }) ''
          [ControlledDelay]
          ${attrsToSection def.controlledDelayConfig}
        ''
        + optionalString (def.deficitRoundRobinSchedulerConfig != { }) ''
          [DeficitRoundRobinScheduler]
          ${attrsToSection def.deficitRoundRobinSchedulerConfig}
        ''
        + optionalString (def.deficitRoundRobinSchedulerClassConfig != { }) ''
          [DeficitRoundRobinSchedulerClass]
          ${attrsToSection def.deficitRoundRobinSchedulerClassConfig}
        ''
        + optionalString (def.enhancedTransmissionSelectionConfig != { }) ''
          [EnhancedTransmissionSelection]
          ${attrsToSection def.enhancedTransmissionSelectionConfig}
        ''
        + optionalString (def.genericRandomEarlyDetectionConfig != { }) ''
          [GenericRandomEarlyDetection]
          ${attrsToSection def.genericRandomEarlyDetectionConfig}
        ''
        + optionalString (def.fairQueueingControlledDelayConfig != { }) ''
          [FairQueueingControlledDelay]
          ${attrsToSection def.fairQueueingControlledDelayConfig}
        ''
        + optionalString (def.fairQueueingConfig != { }) ''
          [FairQueueing]
          ${attrsToSection def.fairQueueingConfig}
        ''
        + optionalString (def.trivialLinkEqualizerConfig != { }) ''
          [TrivialLinkEqualizer]
          ${attrsToSection def.trivialLinkEqualizerConfig}
        ''
        + optionalString (def.hierarchyTokenBucketConfig != { }) ''
          [HierarchyTokenBucket]
          ${attrsToSection def.hierarchyTokenBucketConfig}
        ''
        + optionalString (def.hierarchyTokenBucketClassConfig != { }) ''
          [HierarchyTokenBucketClass]
          ${attrsToSection def.hierarchyTokenBucketClassConfig}
        ''
        + optionalString (def.heavyHitterFilterConfig != { }) ''
          [HeavyHitterFilter]
          ${attrsToSection def.heavyHitterFilterConfig}
        ''
        + optionalString (def.quickFairQueueingConfig != { }) ''
          [QuickFairQueueing]
          ${attrsToSection def.quickFairQueueingConfig}
        ''
        + optionalString (def.quickFairQueueingClassConfig != { }) ''
          [QuickFairQueueingClass]
          ${attrsToSection def.quickFairQueueingClassConfig}
        ''
        + optionalString (def.bridgeVLANConfig != { }) ''
          [BridgeVLAN]
          ${attrsToSection def.bridgeVLANConfig}
        ''
        + flip concatMapStrings def.dhcpServerStaticLeases (x: ''
          [DHCPServerStaticLease]
          ${attrsToSection x.dhcpServerStaticLeaseConfig}
        '')
        + def.extraConfig;
    };

  unitFiles = listToAttrs (map (name: {
    name = "systemd/network/${name}";
    value.source = "${cfg.units.${name}.unit}/${name}";
  }) (attrNames cfg.units));
in

{
  options = {

    systemd.network.enable = mkOption {
      default = false;
      type = types.bool;
      description = ''
        Whether to enable networkd or not.
      '';
    };

    systemd.network.links = mkOption {
      default = {};
      type = with types; attrsOf (submodule [ { options = linkOptions; } ]);
      description = "Definition of systemd network links.";
    };

    systemd.network.netdevs = mkOption {
      default = {};
      type = with types; attrsOf (submodule [ { options = netdevOptions; } ]);
      description = "Definition of systemd network devices.";
    };

    systemd.network.networks = mkOption {
      default = {};
      type = with types; attrsOf (submodule [ { options = networkOptions; } networkConfig ]);
      description = "Definition of systemd networks.";
    };

    systemd.network.units = mkOption {
      description = "Definition of networkd units.";
      default = {};
      internal = true;
      type = with types; attrsOf (submodule (
        { name, config, ... }:
        { options = mapAttrs (_: x: x // { internal = true; }) concreteUnitOptions;
          config = {
            unit = mkDefault (makeUnit name config);
          };
        }));
    };

  };

  config = mkMerge [

    # .link units are honored by udev, no matter if systemd-networkd is enabled or not.
    {
      systemd.network.units = mapAttrs' (n: v: nameValuePair "${n}.link" (linkToUnit n v)) cfg.links;
      environment.etc = unitFiles;
    }

    (mkIf config.systemd.network.enable {

      users.users.systemd-network.group = "systemd-network";

      systemd.additionalUpstreamSystemUnits = [
        "systemd-networkd-wait-online.service"
        "systemd-networkd.service"
        "systemd-networkd.socket"
      ];

      systemd.network.units = mapAttrs' (n: v: nameValuePair "${n}.netdev" (netdevToUnit n v)) cfg.netdevs
        // mapAttrs' (n: v: nameValuePair "${n}.network" (networkToUnit n v)) cfg.networks;

      # systemd-networkd is socket-activated by kernel netlink route change
      # messages. It is important to have systemd buffer those on behalf of
      # networkd.
      systemd.sockets.systemd-networkd.wantedBy = [ "sockets.target" ];

      systemd.services.systemd-networkd = {
        wantedBy = [ "multi-user.target" ];
        aliases = [ "dbus-org.freedesktop.network1.service" ];
        restartTriggers = map (x: x.source) (attrValues unitFiles);
      };

      systemd.services.systemd-networkd-wait-online = {
        wantedBy = [ "network-online.target" ];
      };

      systemd.services."systemd-network-wait-online@" = {
        description = "Wait for Network Interface %I to be Configured";
        conflicts = [ "shutdown.target" ];
        requisite = [ "systemd-networkd.service" ];
        after = [ "systemd-networkd.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${config.systemd.package}/lib/systemd/systemd-networkd-wait-online -i %I";
        };
      };

      services.resolved.enable = mkDefault true;
    })
  ];
}
