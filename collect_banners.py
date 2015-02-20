#all it does is collecting banners :3
#usage: ./banner_collector.py %ip_address_range% %out_file%
#like 97.246.47.0/24
#or   97.246.47.21-97.246.48.0

import sys
from threading import *
from netaddr import *
from urllib import request
import re


class Banner:
    def __init__(self):
        self.banner = ''
        self.ips = []
        self.count = 0


class Scan:
    def __init__(self, ipRange):
        self.banners = []
        self.numberOfWorkers = 16
        self.lock = Lock()
        self.id = 0
        self.upHosts = 0
        #check wheter ip's are given as low-high
        ipRange.replace(' ', '')
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ipRange):
            try:
                ips = ipRange.split('-')
                self.ipRange = (int(IPAddress(ips[0])), int(IPAddress(ips[1])))
            except:
                return

        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}", ipRange):
            try:
                ips = ipRange.split('/')
                self.ipRange = (int(IPAddress(ips[0])), int(IPAddress(ips[0])) + 2**(32-int(ips[1])))
            except:
                return


    def IsInitialized(self):
        try:
            if self.ipRange is not None:
                return True
        except:
            return False


    def __HasBanner(self, banner):
        for bBanner in range(len(self.banners)):
            if self.banners[bBanner].banner == banner:
                return bBanner
        return -1


    def __ScanWorker(self, ipRange):
        for ip in ipRange:
            try:
                banner = str(request.urlopen('http://' + str(ip), timeout=4).read())
                banner.replace('\n', ' ').replace('\r', '')
                with self.lock:
                    self.upHosts += 1
                    t = self.__HasBanner(banner)
                    if t == -1:
                        self.banners.append(Banner())
                        t = -1
                        self.banners[t].banner = banner
                    self.banners[t].ips.append(int(IPAddress(ip)))
                    self.banners[t].count += 1
            except:
                pass


    def Scan(self):
        print('Scanning from ' + str(IPAddress(self.ipRange[0])) + ' till ' + str(IPAddress(self.ipRange[1])))
        threads = []
        startIp = self.ipRange[0]
        rangeLength = int((self.ipRange[1] - startIp) // self.numberOfWorkers)
        if rangeLength != 0: #CUS I WANNA SLEEP THAT'S WHY
            for i in range(self.numberOfWorkers):
                t = Thread(target=self.__ScanWorker, args=[IPRange(startIp, startIp + rangeLength - 1)])
                threads.append(t)
                t.start()
                startIp += rangeLength
        t = Thread(target=self.__ScanWorker, args=[IPRange(startIp, self.ipRange[1])])
        threads.append(t)
        t.start()

        for t in threads:
            t.join()

        #sort ip's
        for banner in self.banners:
            banner.ips = sorted(banner.ips)


    def WriteFile(self, fileName):
        try:
            with open(fileName, 'w+') as out:
                pass
        except:
            print('Malformed path to output file, using default out.txt')
            fileName = 'out.txt'

        with open(fileName, 'w+') as out:
            out.write('Total '+ str(self.upHosts) + 'up hosts\n')
            for banner in self.banners:
                out.write(str(banner.banner) + '\n')
                out.write('Found ' + str(banner.count) + ' devices:\n')
                for ip in banner.ips:
                    out.write(str(IPAddress(ip)) + '\n')


def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("./banner_collector.py %ip_address_range% %out_file%")
        print("%ip_address_range%:")
        print("97.246.47.0/24")
        print("97.246.47.21-97.246.48.0")
        exit()

    MyScan = Scan(sys.argv[1])
    if not MyScan.IsInitialized():
        print("Bad input")
        exit()

    MyScan.Scan()
    MyScan.WriteFile(sys.argv[2])

if __name__ == "__main__":
    main()