from mininet.cli import CLI
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel

from time import sleep
import sys
class StaticTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        self.addLink(h1, s1, bw=100, delay='1ms')
        self.addLink(s1, s2, bw=10, delay='10ms')
        self.addLink(s2, h2, bw=100, delay='1ms')

        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        self.addLink(h1, s3, bw=100, delay='1ms')
        self.addLink(s3, s4, bw=1, delay='10ms')
        self.addLink(h2, s4, bw=100, delay='1ms')

if __name__ == '__main__':
    net = Mininet(topo=StaticTopo(), link=TCLink)
    net.start()
    h1 = net.get('h1')
    h2 = net.get('h2')

    # there is probably a better way, but somehow we have to configure
    # the IP adresses

    for i in range(0, 2):
        h1.cmd('ifconfig h1-eth' + str(i) + ' 1' + str(i) + '.0.0.1')
        h2.cmd('ifconfig h2-eth' + str(i) + ' 1' + str(i) + '.0.0.2')
        # heat up network to avoid initial high delays
        h1.cmd('ping 1' + str(i) + '.0.0.2 -c 4')

    if (len(sys.argv) > 1):
        scheduler = sys.argv[1]
    else:
        scheduler = "rr"

    sleep(2)
    print "you might want to type xterm h1 h2 in the console and start wireshark in the correct context... enter exit to exit"
    CLI(net)

    h2.cmd('/usr/local/go/bin/go run ../example/server_main.go  -sc='+scheduler+' -v=1 -www ../example/web  &> mp_server_'+scheduler+'.out &')
    # the server requires some startup time
    sleep(2)
    h1.cmd('/usr/local/go/bin/go run ../example/client/client_main.go -v=1 https://10.0.0.2:6121/test1Mb.db &> mp_client_'+scheduler+'.out')
    CLI(net)
    net.stop()

    # TODO print out / parse client result...
