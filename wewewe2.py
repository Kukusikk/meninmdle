from scapy.all import *

mac_a={}

mac_my='88:77:66:55:44:33'
i=0

def we_have_p(x):
    global mac_a,i

    if x.src == mac_my:
        return

    if x.haslayer(IPv6):
        x.src = mac_my
        if x.sniffed_on == 'eth0':
            sendp(x, iface = 'eth1')
        else:
            sendp(x, iface = 'eth0')
        return
    print('polychili--->>istochnik  ') 
    print(x.src) 
    print('   priemnik   ----->>') 
    print(x.dst) 
    if (x.haslayer(ARP)):
        i=1
    if i==0:
        return
    if not x.src in mac_a.keys() and not x.src in mac_a.values():
        if x.dst != mac_my:
            mac_a[x.src] = x.dst
    if x.haslayer(ARP):
        x[ARP].hwsrc = mac_my
        if x.dst == mac_my:
            for key in mac_a:
                if mac_a[key] == 'ff:ff:ff:ff:ff:ff':
                    mac_a[key] = x.src


    if x.src in mac_a.keys():
        x.dst=mac_a[x.src]
    else:
        for key in mac_a:
            if mac_a[key]==x.src:
                x.dst=key
    x.src=mac_my

    print('send--->>istochnik  ') 
    print(x.src) 
    print('   priemnik   ----->>') 
    print(x.dst)     

    if (x.sniffed_on=='eth0'):
        print('from A in B')
        sendp(x, iface = 'eth1')



    if (x.sniffed_on=='eth1'):
        print('from B in A')
        sendp(x, iface = 'eth0')




sniff(iface = ['eth0', 'eth1'], prn = we_have_p)
