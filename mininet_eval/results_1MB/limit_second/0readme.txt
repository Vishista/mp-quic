single path:
        self.addLink(h1, s1, bw=100, delay=1)
        self.addLink(s1, s2, bw=10, delay=10)
        self.addLink(s2, h2, bw=100, delay=1)

additional path:
        self.addLink(h1, s3, bw=100, delay=1)
        self.addLink(s3, s4, bw=1, delay=100)
        self.addLink(h2, s4, bw=100, delay=1)
