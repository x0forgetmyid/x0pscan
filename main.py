import csv
import sqlite3
from datetime import datetime
from ipaddress import ip_address
import socks
import socket
import random
import time

from threading import Lock

D_CSV_BASE = "/home/user/PycharmProjects/x0pscan/ip2location.csv"
D_SQLITE_BASE = "/home/user/PycharmProjects/x0pscan/x0pscan.db"

P_TCP = 0
P_UDP = 1
SCAN_CONNECTED = 1
SCAN_FAILED = 0
PROXY_FAILED = -1

ATTEMPT_LIMIT = 10
ATTEMPT_PAUSE = 6

LIMIT_PROXY_ERRORS = 120
LIMIT_BEFORE_PROXY_TIMEOUT = 15
MAX_THREADS = 74


def ip_range_list(start_ip, end_ip):
  start = list(map(int, start_ip.split(".")))
  end = list(map(int, end_ip.split(".")))
  temp = start
  ip_range = list()

  ip_range.append(start_ip)
  while temp != end:
    start[3] += 1
    for i in (3, 2, 1):
      if temp[i] == 256:
        temp[i] = 0
        temp[i-1] += 1
      ip_range.append(".".join(map(str, temp)))
  random.shuffle(ip_range)
  return ip_range


def ip_conv(ip_src):
    i = int(ip_src)
    ip = ip_address(i)
    return str(ip)


class service:
    def __init__(self, port=0, protocol=P_TCP):
        self.port = port
        self.protocol = protocol


class proxyentry:
    def __init__(self,
                 proxy_type = None,
                 ip_addr = None,
                 port = None,
                 username = None,
                 password = None,
                 svc = None,
                 limit_conn = None):
        self.proxy_type = proxy_type
        self.ip_addr = ip_addr
        self.port = port
        self.username = username
        self.password = password
        self.svc = svc
        self.limit_conn = limit_conn

    def compare(self, p):
        return (self.proxy_type == p.proxy_type and
        self.ip_addr == p.ip_addr and
        self.port == p.port and
        self.username == p.username and
        self.password == p.password)


class proxypoolentry:
    def __init__(self, proxy):
        self.p = proxy
        self.err = 0
        self.conn = 0
        self.dq = False


class scanentry:
    def __init__(self, ip_addr=None, svc=None, res=None, dt_scan=None):
        self.ip_addr = ip_addr
        self.svc = svc
        self.res = res
        self.dt_scan = dt_scan


class dbmodel:
    def __init__(self, sqlite_base="x0pscan.db"):
        self._sqlite_base = sqlite_base
        
    def create(self):
        con = sqlite3.connect(self._sqlite_base)  # change to 'sqlite:///ip2location.db'
        cur = con.cursor()

        cur.execute(
            "CREATE TABLE IF NOT EXISTS ranges (ip_start TEXT, ip_end TEXT, ip_count INT, country_code TEXT, country_name TEXT, region TEXT, city TEXT, dt_added INT);")  # use your column names here
        cur.execute(
            "CREATE TABLE IF NOT EXISTS proxies (ip_addr TEXT, port INT, proxy_type INT, username TEXT, password TEXT, service TEXT, limit_conn INT);")
        # cur.execute("INSERT INTO proxies (ip_addr, port, proxy_type, username, password, service, limit_conn) VALUES (\"102.129.209.214\", 15956, 2, \"user47288\", \"pg6t09\", \"proxys.io\", 1);")
        cur.execute("CREATE TABLE IF NOT EXISTS pscan (ip_addr TEXT, port INT, protocol INT, res INT, dt_scan INT);")

        con.commit()
        con.close()

    def select_pscan(self, ip_addr, svc):
        con = sqlite3.connect(self._sqlite_base)  # change to 'sqlite:///ip2location.db'
        cur = con.cursor()
        cur.execute("SELECT res, dt_scan FROM pscan WHERE (ip_addr=?)AND(port=?)AND(protocol=?)AND(res>-1) ORDER BY dt_scan DESC;", (ip_addr, svc.port, svc.protocol))
        rows = cur.fetchall()
        if len(rows) > 0:
            row = rows[0]
            return scanentry(ip_addr=ip_addr, svc=svc, res=row[3], dt_scan=row[4])
        else:
            return None

    def insert_pscan(self, ip_addr, svc, res, dt_scan=int(datetime.now().timestamp())):
        con = sqlite3.connect(self._sqlite_base) # change to 'sqlite:///ip2location.db'
        cur = con.cursor()


        cur.execute("INSERT INTO pscan (ip_addr, port, protocol, res, dt_scan) VALUES (?, ?, ?, ?, ?);",
                    (str(ip_addr), svc.port, svc.protocol, res, int(dt_scan)))
        con.commit()
        con.close()

 #   def insert_pscan(self, ip_addr, svc, res):
 #       self.insert_pscan(ip_addr, svc, datetime.now().timestamp())

    def select_proxies(self):
        pl = list()
        con = sqlite3.connect(self._sqlite_base)  # change to 'sqlite:///ip2location.db'
        cur = con.cursor()
        cur.execute("SELECT ip_addr, port, proxy_type, username, password, limit_conn FROM proxies")
        rows = cur.fetchall()

        for row in rows:
            pe = proxyentry(ip_addr=ip_address(row[0]), port=row[1], proxy_type=row[2], username=row[3], password=
            row[4], limit_conn=row[5])
            pl.append(pe)
        con.close()
        return pl

    def ip2location_import(self, f=D_CSV_BASE, dt=False):
        con = sqlite3.connect(self._sqlite_base) # change to 'sqlite:///ip2location.db'
        dt = int(datetime.now().timestamp())
        cur = con.cursor()

        if dt:
            print ("Drop table ranges!")
            cur.execute("DROP TABLE ranges;")
            print ("Create again!")

        cur.execute(
            "CREATE TABLE IF NOT EXISTS ranges (ip_start TEXT, ip_end TEXT, ip_count INT, country_code TEXT, country_name TEXT, region TEXT, city TEXT, dt_added INT);")  # use your column names here

        with open(f,'r') as fin: # `with` statement available in 2.5+
            br = csv.reader(fin, delimiter=',', quotechar='"')
            rows = list(br)
            rows.pop(0)

            for row in rows:
                ip_start=ip_conv(row[0])
                ip_end=ip_conv(row[1])
                ip_count=int(row[1]) - int(row[0])
                country_code=row[2]

                print("Range: " + ip_start + " " + ip_end + " (" + str(ip_count) + " ips): " + country_code)

                cur.execute("INSERT INTO ranges (ip_start, ip_end, ip_count, country_code, country_name, region, city, dt_added, i_start, i_end) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (ip_start, ip_end, ip_count, country_code, row[3], row[4], row[5], dt))

            con.commit()
            con.close()


class scansocket:
    def __init__(self, proxy=None, protocol=P_TCP):
        socket_type = socket.SOCK_DGRAM if protocol == P_UDP else socket.SOCK_STREAM

        self._socket = socks.socksocket(type=socket_type)
        if not proxy is None:
            self.proxy(proxy)

    def proxy(self, p):
        self._socket.set_proxy(proxy_type=p.proxy_type, addr=p.ip_addr, port=p.port, username=p.username, password=p.password)

    def scan(self, addr, svc):
        res = SCAN_FAILED
        try:
            self._socket.connect(addr, svc.port)
            res = SCAN_CONNECTED
            self._socket.close()
        except socks.ProxyError:
            res = PROXY_FAILED
        except:
            res = SCAN_FAILED
        return res

class proxypool:
    def __init__(self):
        self._pool = list()
        self._queue_pos = 0
        self._lock = Lock()
        self.limit_errors = LIMIT_PROXY_ERRORS

    def contains(self, proxy, proxy_list):
        self._lock.acquire()

        for pe in proxy_list:
            if pe.compare(proxy):
                return pe
        return None

    def reload(self, pl):
        self._lock.acquire()
        if self._pool is None:
            self._pool=list()

        proxy_list = pl
        for pool_entry in self._pool:
            proxy_entry = self.contains(pool_entry.p, proxy_list)
            if not proxy_entry is None:
                pool_entry.p.limit_conn = proxy_entry.limit_conn
                proxy_list.remove(proxy_entry)
            else:
                pool_entry.dq = True
        for proxy_entry in proxy_list:
            pool_entry=proxypoolentry(proxy_entry)
            self._pool.append(pool_entry)
        self._lock.release()

    def acquire_proxy(self):
        if len(self._pool) == 0:
            return None

        i = 0
        attempts = 0
        while True:
            self._lock.acquire()
            self._queue_pos = self._queue_pos + 1
            if self._queue_pos > len(self._pool):
                self._queue_pos = 0

            current_pool_entry = self._pool[self._queue_pos]
            if current_pool_entry.dq and  current_pool_entry.conn == 0:
                self._pool.pop(self._queue_pos)
            elif current_pool_entry.err < self.limit_errors and current_pool_entry.conn < current_pool_entry.p.limit_conn:
                current_pool_entry.conn = current_pool_entry.conn + 1
                self._lock.release()
                return current_pool_entry.p

            self._lock.release()

            i = i + 1
            if i == len(self._pool):
                i = 0
                attempts = attempts + 1
                if attempts > ATTEMPT_LIMIT:
                    return None
                else:
                    time.sleep(ATTEMPT_PAUSE)


    def release_proxy(self, p, error=False):
        for pe in self._pool:
            if pe.p.compare(p):
                pe.conn = pe.conn -1
                if error:
                    pe.err = pe.err + 1
                if pe.conn <= 0 and pe.dq:
                    self._pool = self._pool.remove(pe)

class scanner:
    def __init__(self, db):
        self._lock = Lock()
        self._stop = False
        self.db = db

    def stop(self):
        self._lock.acquire()
        self._stop = True
        self._lock.release()

    def scan(self, ip_start, ip_end, services, pool):
        range_list = ip_range_list(ip_start, ip_end)
        for i in range_list:
            self._lock.acquire()
            if self._stop:
                self._lock.release()
                return
            self._lock.release()

            rnd_svc = list(services)
            random.shuffle(rnd_svc)

            for svc in rnd_svc:
                res = PROXY_FAILED
                while res == PROXY_FAILED:
                    ip_addr = ip_address(i)
                    proxy = pool.acquire_proxy()
                    scan_socket = scansocket(proxy, svc.protocol)
                    res = scan_socket.scan(ip_addr, svc)
                    pool.release_proxy(proxy, error=(res == PROXY_FAILED))
                    if res == SCAN_CONNECTED or res == SCAN_FAILED:
                        self.db.insert_pscan(ip_addr, svc, res)
                        break


def test_scan():
    db = dbmodel(D_SQLITE_BASE)
#    print ("Init DB (create)")
#    db.create()
#    print ("ip2location import frmo CSV")
#    db.ip2location_import(D_CSV_BASE)

    print ("Init proxy pool")
    proxy_pool = proxypool()
    proxy_list = db.select_proxies()
    proxy_pool.reload(proxy_list)
    scanner_work = scanner(db)
    scanner_work.scan("4.21.41.0", "4.21.69.255",
                      (service(22, P_TCP), service(2222, P_TCP), service(8022, P_TCP), service(23, P_TCP)), proxy_pool)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    test_scan()
# See PyCharm help at https://www.jetbrains.com/help/pycharm/
