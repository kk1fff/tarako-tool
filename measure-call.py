#!/usr/bin/env python

import subprocess, signal, sys, re, datetime, StringIO
import threading, time

sp = subprocess.Popen(['adb', 'logcat', '-s', 'CALLTRY'], stdout=subprocess.PIPE)
procWatcher = None

def call_and_store(cmd_array):
    cmd = ['adb', 'shell'] + cmd_array
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    buf = ""
    while True:
        l = proc.stdout.readline().decode('utf-8')
        if l == "":
            break
        buf = buf + l
    return buf

class ProcInfoDiff:
    def __init__(self, diff):
        self._diff = diff
    def duration(self):
        return (float)(self._diff['time_delta'].seconds) + float(self._diff['time_delta'].microseconds) / 1000000.0
    def user(self):
        return (float)(self._diff['user'])/(float)(self._diff['tick'])
    def utime(self):
        return (float)(self._diff['user'])/100.0
    def nice(self):
        return (float)(self._diff['nice'])/(float)(self._diff['tick'])
    def sys(self):
        return (float)(self._diff['sys'])/(float)(self._diff['tick'])
    def stime(self):
        return (float)(self._diff['sys'])/100.0
    def idle(self):
        return (float)(self._diff['idle'])/(float)(self._diff['tick'])
    def iow(self):
        return (float)(self._diff['iow'])/(float)(self._diff['tick'])
    def irq(self):
        return (float)(self._diff['irq'])/(float)(self._diff['tick'])
    def sirq(self):
        return (float)(self._diff['sirq'])/(float)(self._diff['tick'])
    def pgin(self):
        return self._diff['pgpgin']
    def pgout(self):
        return self._diff['pgpgout']
    def swpin(self):
        return self._diff['pswpin']
    def swpout(self):
        return self._diff['pswpout']

class ProcInfo:
    def __init__(self):
        self._time = datetime.datetime.now()
        self._stat = call_and_store(['cat', '/proc/stat'])
        self._vmstat =  call_and_store(['cat', '/proc/vmstat'])
        self._is_read = False
        self._vmstat_data = None
        self._stat_data = None

    def diff(self, earlier_data):
        self._read()
        earlier_data._read()

        return ProcInfoDiff({
            'time_delta': self._time - earlier_data._time,
            'tick': self._diff_of_stat_cpu('total', earlier_data),
            'user': self._diff_of_stat_cpu('user', earlier_data),
            'nice': self._diff_of_stat_cpu('nice', earlier_data),
            'sys': self._diff_of_stat_cpu('sys', earlier_data),
            'idle': self._diff_of_stat_cpu('idle', earlier_data),
            'iow': self._diff_of_stat_cpu('iow', earlier_data),
            'irq': self._diff_of_stat_cpu('irq', earlier_data),
            'sirq': self._diff_of_stat_cpu('sirq', earlier_data),
            'pgpgin': self._diff_of_vmstat('pgpgin', earlier_data),
            'pgpgout': self._diff_of_vmstat('pgpgout', earlier_data),
            'pswpin': self._diff_of_vmstat('pswpin', earlier_data),
            'pswpout': self._diff_of_vmstat('pswpout', earlier_data),
        })

    def _diff_of_vmstat(self, prop, earlier_data):
        return self._vmstat_data[prop] - earlier_data._vmstat_data[prop]

    def _diff_of_stat_cpu(self, prop, earlier_data):
        return self._stat_data['cpu'][prop] - earlier_data._stat_data['cpu'][prop]

    def _read(self):
        # lazily read
        if self._is_read:
            return
        # parse data
        self._parse_vmstat()
        self._parse_stat()
        self._is_read = True

    def _parse_vmstat(self):
        self._vmstat_data = dict()
        ins = StringIO.StringIO(self._vmstat)
        while True:
            l = ins.readline()
            if l == "":
                break
            m = re.search(r'^([A-Za-z0-9]+) +([0-9]+)', l)
            if m != None:
                self._vmstat_data[m.group(1)] = int(m.group(2))

    def _parse_stat(self):
        self._stat_data = dict()
        ins = StringIO.StringIO(self._stat)
        while True:
            l = ins.readline()
            if l == "":
                break
            # cpu  16881 6898 252366 383850 136582 0 1535 0 0 0
            m = re.search(r'cpu +([0-9]+) +([0-9]+) +([0-9]+) +([0-9]+) +([0-9]+) +([0-9]+) +([0-9]+) +([0-9]+) +([0-9]+) +([0-9]+)', l)
            if m != None:
                self._stat_data['cpu'] = {
                    'user': int(m.group(1)),
                    'nice': int(m.group(2)),
                    'sys':  int(m.group(3)),
                    'idle': int(m.group(4)),
                    'iow':  int(m.group(5)),
                    'irq':  int(m.group(6)),
                    'sirq': int(m.group(7)),

                    # virtualized
                    'stolen':   int(m.group(8)),
                    'gst':      int(m.group(9)),
                    'gst_nice': int(m.group(9))
                }
                self._stat_data['cpu']['total'] = (int(m.group(1)) + int(m.group(2)) + int(m.group(3)) +
                                                   int(m.group(4)) + int(m.group(5)) + int(m.group(6)) +
                                                   int(m.group(7)) + int(m.group(8)) + int(m.group(9)) +
                                                   int(m.group(10)))

class MapInfoDiff:
    def __init__(self, name, start, size, permission, diff):
        self._diff = diff
        self._file = name
        self._start = start
        self._size = size
        self._permission = permission

    def report(self):
        d = self._diff
        return "{:50} {:10d} {:10d} {:10d} {:10d} {:10d} {:10d} {:10d} {:10d}".format(self._name()[:50],
                                                                                      self._size,
                                                                                      d['rss'], d['pss'], d['sc'], d['sd'], d['pc'],
                                                                                      d['pd'], d['swap'])

    def _name(self):
        if self._file != None:
            return self._file
        else:
            return "{:x} {}".format(self._start, self._permission)

class MapInfo:
    def __init__(self):
        self._start = -1

    def feed(self, line):
        if self._start == -1:
            return self._parse_firstline(line)
        else:
            return self._parse_value(line)

    def _parse_firstline(self, line):
        # be9f3000-bea14000 rw-p 00000000 00:00 0          [stack]
        m = re.search(r'([0-9a-f]+)-([0-9a-f]+) ([r-][w-][x-][ps]) ([0-9a-f]+) [0-9a-f]{2}:[0-9a-f]{2} [0-9]+(.+|)$', line.strip())
        if m == None:
            raise Exception("Can not parse first line of smaps: '"+ line.strip() + "'")

        self._start = int(m.group(1), 16)
        self._end = int(m.group(2), 16)
        self._permission = m.group(3)
        self._offset = int(m.group(4), 16)
        self._file = m.group(5).strip() if m.group(5) != '' else None
        return True
 
    def _parse_value(self, line):
        m = re.search(r'([A-Za-z0-9_]+):[ \t]+([0-9]+) kB', line.strip())
        if m == None:
            return False
        name = m.group(1)
        value = int(m.group(2))

        if name == "Size":
            self._size = value
        elif name == "Rss":
            self._rss = value
        elif name == "Pss":
            self._pss = value
        elif name == "Shared_Clean":
            self._shared_clean = value
        elif name == "Shared_Dirty":
            self._shared_dirty = value
        elif name == "Private_Clean":
            self._private_clean = value
        elif name == "Private_Dirty":
            self._private_dirty = value
        elif name == "Swap":
            self._swap = value
        return True

    def diff(self, old):
        # return None if they are considered as difference maps
        if self._size != old._size:
            return None
        if self._file != old._file:
            return None
        return MapInfoDiff(self._file, self._start, self._size, self._permission, {
            'rss': self._rss - old._rss,
            'pss': self._pss - old._pss,
            'sc': self._shared_clean - old._shared_clean,
            'sd': self._shared_dirty - old._shared_dirty,
            'pc': self._private_clean - old._private_clean,
            'pd': self._private_dirty - old._private_dirty,
            'swap': self._swap - old._swap
        });

    def start(self):
        return self._start

    def report(self):
        return "{:50} {:10d} {:10d} {:10d} {:10d} {:10d} {:10d} {:10d} {:10d}".format(self._file[:50] if self._file != None else "{:x} {}".format(self.start(), self._permission),
                                                                                      self._size, self._rss, self._pss, self._shared_clean,
                                                                                      self._shared_dirty, self._private_clean, self._private_dirty,
                                                                                      self._swap)

class SingleProcInfoDiff:
    def __init__(self, pid, diff):
        self._diff = diff
        self._pid = pid

    def duration(self):
        return (float)(self._diff['time_delta'].seconds) + float(self._diff['time_delta'].microseconds) / 1000000.0

    def minflt(self):
        return self._diff['minflt']

    def majflt(self):
        return self._diff['majflt']

    def utime(self):
        return (float)(self._diff['utime']) / 100.0

    def stime(self):
        return (float)(self._diff['stime']) / 100.0

    def pid(self):
        return self._pid

    def reportMapDiff(self):
        if self._diff['smaps'] == None:
            return ""
        ret = ""
        ret = ret + "diff:\n"

        for mapdiff in self._diff['smaps']['diff']:
            ret = ret + mapdiff.report() + "\n"

        ret = ret + "created:\n"
        for maps in self._diff['smaps']['created']:
            ret = ret + maps.report() + "\n"

        ret = ret + "deleted:\n"
        for maps in self._diff['smaps']['deleted']:
            ret = ret + maps.report() + "\n"
        return ret

class SingleProcInfo:
    def __init__(self, pid = 0, stat = None, time = None):
        if pid != 0:
            self._time = datetime.datetime.now()
            self._stat = call_and_store(['cat', '/proc/{0}/stat'.format(pid)])
            self._smaps = call_and_store(['cat', '/proc/{}/smaps'.format(pid)])
        elif stat != None and time != None:
            self._time = time
            self._stat = stat
            self._smaps = None
        m = re.search(r'^(\d+) ', self._stat)
        self._pid = int(m.group(1)) if m != None else 0
        self._parsed = False
        self._smaps_data = None

    def diff(self, old):
        if self._pid != old._pid:
            return None

        self._parse()
        old._parse()
        return SingleProcInfoDiff(self._pid, {
            'time_delta': self._time - old._time,
            'minflt':     self._minflt - old._minflt,
            'majflt':     self._majflt - old._majflt,
            'utime':      self._utime - old._utime,
            'stime':      self._stime - old._stime,
            'smaps':      self._diff_smaps(old)
        })

    def _parse(self):
        self._parse_smaps()
        if self._parsed:
            return
        self._parse_stat()

    def _parse_stat(self):
        m = re.search(r'^(\d+) \(.*\) \w+ \d+ \d+ \d+ \d+ [0-9-]+ \d+ (\d+) \d+ (\d+) \d+ (\d+) (\d+)', self._stat)
        self._minflt = int(m.group(2))
        self._majflt = int(m.group(3))
        self._utime = int(m.group(4))
        self._stime = int(m.group(5))

    def _parse_smaps(self):
        if self._smaps == None:
            return
        self._smaps_data = {}
        reader = StringIO.StringIO(self._smaps)
        mapInfo = None
        while True:
            l = reader.readline()
            if l == "":
                if mapInfo != None:
                    self._smaps_data[mapInfo.start()] = mapInfo
                break
            if mapInfo == None:
                mapInfo = MapInfo()
            if mapInfo.feed(l) == False:
                self._smaps_data[mapInfo.start()] = mapInfo
                mapInfo = MapInfo()
                mapInfo.feed(l)

    def _diff_smaps(self, old):
        if self._smaps_data == None or old._smaps_data == None:
            return None

        diffs = []
        for addr in self._smaps_data.keys():
            if addr in old._smaps_data:
                diff = self._smaps_data[addr].diff(old._smaps_data[addr])
                if diff != None:
                    diffs.append(diff)
                    del self._smaps_data[addr]
                    del old._smaps_data[addr]
        created = self._smaps_data
        deleted = old._smaps_data
        return {
            'diff': diffs,
            'created': created.values(),
            'deleted': deleted.values()
        }
        

    def pid(self):
        return self._pid

    def smaps(self):
        return self._smaps

def get_system_proc_stat():
    catproc = subprocess.Popen(['adb', 'shell', 'getsysstat'], stdout = subprocess.PIPE)
    rets = []
    now = datetime.datetime.now()
    while True:
        l = catproc.stdout.readline().decode('utf-8')
        if l == "":
            break
        if l.strip() == "":
            continue
        rets.append(SingleProcInfo(stat = l, time = now))
    return rets

class ProcWatcher(threading.Thread):
    def __init__(self, preallocated_pid, b2g_pid):
        super(ProcWatcher, self).__init__()
        self._still_run_lock = threading.Lock()
        self._still_run = True
        self._buf_lock = threading.Lock()
        self._buf = None
        self._preallocated_pid = preallocated_pid
        self._b2g_pid = b2g_pid

    def run(self):
        while self.still_run():
            buf = {
                'system': ProcInfo(),
                'prea':   SingleProcInfo(self._preallocated_pid),
                'b2g':    SingleProcInfo(self._b2g_pid),
                'proc':   get_system_proc_stat()
            }

            self._buf_lock.acquire()
            self._buf = buf
            self._buf_lock.release()
            time.sleep(1)

    def still_run(self):
        self._still_run_lock.acquire()
        r = self._still_run
        self._still_run_lock.release()
        return r

    def set_dont_run(self):
        self._still_run_lock.acquire()
        self._still_run = False
        self._still_run_lock.release()

    def get_buf(self):
        self._buf_lock.acquire()
        buf = self._buf
        self._buf = None
        self._buf_lock.release()
        return buf
        
def get_pid(app):
    b2ginfo = subprocess.Popen(['adb', 'shell', 'b2g-ps'], stdout=subprocess.PIPE)
    pid = 0
    while True:
        l = b2ginfo.stdout.readline().decode('utf-8')
        if l == "":
            break
        m = re.search(app, l.strip())
        if m == None:
            continue
        m = re.search(r'^(\d+)', l[27:])
        pid = int(m.group(1))
        break

    b2ginfo.terminate()
    return pid

def signal_handler(signal, frame):
    print "Got Ctrl-C, terminate"
    sp.terminate()
    if procWatcher != None:
        procWatcher.set_dont_run()
    sys.exit(0)

def killapp(app):
    pid = get_pid(app)
    if pid > 0:
        subprocess.call(['adb', 'shell', 'kill', '-9', str(pid)])
        print "Kill {0}({1}).".format(app, pid)
    else:
        print "{0} is not running.".format(app)

def cleanlog():
    subprocess.call(['adb', 'logcat', '-c'])

################################################################################
# Start

killapp('Communications')

# clean log
cleanlog()

# get proc info
b2g_pid = get_pid('b2g')
preallocated_pid = get_pid('Preallocated')
procWatcher = ProcWatcher(preallocated_pid, b2g_pid)
procWatcher.start()

logb = StringIO.StringIO()

# log start time
now = datetime.datetime.now()
logb.write("start: {0}/{1}/{2} {3}:{4}:{5}\n".format(now.year, now.month, now.day,
                                                     now.hour, now.minute, now.second))
now = None

p = subprocess.Popen(['adb', 'shell', 'b2g-info'], stdout=subprocess.PIPE)
while True:
    l = p.stdout.readline().decode('utf-8')
    if l == "":
        break
    logb.write(l)

signal.signal(signal.SIGINT, signal_handler)
cs = 0
ring = 0
procInfo = None
while True:
    l = sp.stdout.readline().decode('utf-8')
    if l == '':
        break

    l = l.strip()
    m = re.search(r'cs ([0-9]+)$', l)
    if m != None:
        cs = int(m.group(1))
        procInfo = procWatcher.get_buf()
        procWatcher.set_dont_run()
        continue
    m = re.search(r'ring ([0-9]+)$', l)
    if m != None and cs > 0:
        ring = int(m.group(1))
        print "Ringing: {0:.3f}".format(float(ring - cs)/1000000000.0)
        break

procInfoDiff = ProcInfo().diff(procInfo['system'])
b2gProcInfoEnd = SingleProcInfo(b2g_pid)
commProcInfoEnd = SingleProcInfo(preallocated_pid)

b2gProcInfoDiff = b2gProcInfoEnd.diff(procInfo['b2g'])
commProcInfoDiff = commProcInfoEnd.diff(procInfo['prea'])

# whole system data
wholeSystemProc = ""
procStatEnd = get_system_proc_stat()
procStatEndMap = dict()
for proc in procStatEnd:
    procStatEndMap[proc.pid()] = proc

for proc in procInfo['proc']:
    if proc.pid() == 0:
        continue
    if proc.pid() in procStatEndMap:
        diff = procStatEndMap[proc.pid()].diff(proc)
        if diff != None:
            wholeSystemProc = wholeSystemProc + "{0:5}{1:6.02f}{2:6.02f}\n".format(diff.pid(), diff.utime(), diff.stime())

procData = """
system
duration: {}
user:     {:.2f}% {} sec
sys:      {:.2f}% {} sec
nice:     {:.2f}%
idle:     {:.2f}%
iowait:   {:.2f}%
irq:      {:.2f}%
sirq:     {:.2f}%
pgin:     {}
pgout:    {}
swpin:    {}
swpout:   {}

b2g({})
majflt:   {}
minflt:   {}
utime:    {} secs
stime:    {} secs

comms({})
majflt:   {}
minflt:   {}
utime:    {} secs
stime:    {} secs

{}

map diff:
b2g:
{}

comms:
{}
""".format(procInfoDiff.duration(),
           procInfoDiff.user() * 100.0, procInfoDiff.utime(),
           procInfoDiff.sys() * 100.0, procInfoDiff.stime(),
           procInfoDiff.nice() * 100.0,
           procInfoDiff.idle() * 100.0,
           procInfoDiff.iow() * 100.0,
           procInfoDiff.irq() * 100.0,
           procInfoDiff.sirq() * 100.0,
           procInfoDiff.pgin(),
           procInfoDiff.pgout(),
           procInfoDiff.swpin(),
           procInfoDiff.swpout(),
           b2g_pid,
           b2gProcInfoDiff.majflt(),
           b2gProcInfoDiff.minflt(),
           b2gProcInfoDiff.utime(),
           b2gProcInfoDiff.stime(),
           preallocated_pid,
           commProcInfoDiff.majflt(),
           commProcInfoDiff.minflt(),
           commProcInfoDiff.utime(),
           commProcInfoDiff.stime(),
           wholeSystemProc,
           b2gProcInfoDiff.reportMapDiff(),
           commProcInfoDiff.reportMapDiff())

print procData

logb.write(procData)
logb.write("Ringing: {0:.3f}\n".format(float(ring - cs)/1000000000.0))

log_filename = "call-time.log"
if len(sys.argv) > 2:
    log_filename = sys.argv[1]
logf = open(log_filename, 'a')
logf.write(logb.getvalue())
logf.write(".\n")
logf.close()
