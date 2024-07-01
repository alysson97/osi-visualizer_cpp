#OSI Visualizer

##Tracking the tcp/ip traffic in your network with OSI model.

`This project run only in Linux for now, but soon (trust me) I will give you guys a release for Windows 11`

<p>This project was wrote using C++ and "pcap" library, so if you're not used to run C++ project, don't forger to install any compiler you need</p>
<p>You also need to install pcap, then if you're in Ubuntu just run "sudo apt install pcap" or the packet manager of your distro</p>

<p>For compile, just run `$ g++ -o rastreador-tcp main.cpp lib/packetHandler.cpp lib/dnsLabelToString.cpp lib/listAllDevices.cpp lib/getHostname.cpp -lpcap`</p>

<p>Then just run `$sudo .\rastreador-tcp` and then you could track every packet sent to your network interface</p>
