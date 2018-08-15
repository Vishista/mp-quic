from mininet.cli import CLI
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel

from time import sleep
import sys

class SPTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        self.addLink(h1, s1, bw=100, delay=10)
        self.addLink(s1, s2, bw=1, delay=500)
        self.addLink(s2, h2, bw=100, delay=10)

class MPTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        self.addLink(h1, s1, bw=100, delay=10)
        self.addLink(s1, s2, bw=1, delay=500)
        self.addLink(s2, h2, bw=100, delay=10)

        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        self.addLink(h1, s3, bw=100, delay=10)
        self.addLink(s3, s4, bw=1, delay=500)
        self.addLink(h2, s4, bw=100, delay=10)

if __name__ == '__main__':
    net_sp = Mininet(topo=SPTopo(), link=TCLink)
    net_mp = Mininet(topo=MPTopo(), link=TCLink)
    net_sp.start()
    net_mp.start()
    h1_sp = net_sp.get('h1')
    h2_sp = net_sp.get('h2')
    h1_mp = net_mp.get('h1')
    h2_mp = net_mp.get('h2')

    # configure the IP adresses
    h1_sp.cmd('ifconfig h1-eth0 10.0.0.1')
    h2_sp.cmd('ifconfig h2-eth0 10.0.0.2')
    h1_sp.cmd('ping 10.0.0.2 -c 4')
    for i in range(0, 2):
        h1_mp.cmd('ifconfig h1-eth' + str(i) + ' 1' + str(i) + '.0.0.1')
        h2_mp.cmd('ifconfig h2-eth' + str(i) + ' 1' + str(i) + '.0.0.2')
        # heat up network to avoid initial high delays
        h1_mp.cmd('ping 1' + str(i) + '.0.0.2 -c 4')

    sleep(4)
    print "you might want to type xterm h1 h2 in the console and start wireshark in the correct context... enter exit to exit"
    CLI(net)
	
    scheduler = "rr"
    if (len(sys.argv) > 0):
        scheduler = sys.argv[0]

    h2.cmd('/usr/local/go/bin/go run ../example/server_main.go  -sc='+scheduler+' -www ../example/web  &> mp_server_'+scheduler+'.out &')
    # the server requires some startup time
    sleep(4)
    h1.cmd('/usr/local/go/bin/go run ../example/client/client_main.go  https://10.0.0.2:6121/testimage2.jpg &> mp_client_'+scheduler+'.out')
    CLI(net)
    net.stop()

    # TODO print out / parse client result...
