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
    def nice(self):
        return (float)(self._diff['nice'])/(float)(self._diff['tick'])
    def sys(self):
        return (float)(self._diff['sys'])/(float)(self._diff['tick'])
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
                    'sys': int(m.group(3)),
                    'idle': int(m.group(4)),
                    'iow': int(m.group(5)),
                    'irq': int(m.group(6)),
                    'sirq': int(m.group(7)),

                    # virtualized
                    'stolen': int(m.group(8)),
                    'gst': int(m.group(9)),
                    'gst_nice': int(m.group(9))
                }
                self._stat_data['cpu']['total'] = (int(m.group(1)) + int(m.group(2)) + int(m.group(3)) +
                                                   int(m.group(4)) + int(m.group(5)) + int(m.group(6)) +
                                                   int(m.group(7)) + int(m.group(8)) + int(m.group(9)) +
                                                   int(m.group(10)))
class ProcWatcher(threading.Thread):
    def __init__(self):
        super(ProcWatcher, self).__init__()
        self._still_run_lock = threading.Lock()
        self._still_run = True
        self._buf_lock = threading.Lock()
        self._buf = None

    def run(self):
        while self.still_run():
            buf = ProcInfo()

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
        

def signal_handler(signal, frame):
    print "Got Ctrl-C, terminate"
    sp.terminate()
    if procWatcher != None:
        procWatcher.set_dont_run()
    sys.exit(0)

def killapp(app):
    b2ginfo = subprocess.Popen(['adb', 'shell', 'b2g-ps'], stdout=subprocess.PIPE)
    pid = 0
    while True:
        l = b2ginfo.stdout.readline().decode('utf-8')
        if l == "":
            break
        m = re.search(r'^' + app + r'[ \t]+app_[0-9]+[ \t]+([0-9]+)', l.strip())
        if m != None:
            pid = int(m.group(1))
            break
    b2ginfo.terminate()
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
cleanlog()
procWatcher = ProcWatcher()
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

procInfoDiff = ProcInfo().diff(procInfo)

procData = """
duration: {0}
user:     {1:.2f}%
sys:      {2:.2f}% 
nice:     {3:.2f}%
idle:     {4:.2f}%
iowait:   {5:.2f}%
irq:      {6:.2f}%
sirq:     {7:.2f}%
pgin:     {8}
pgout:    {9}
swpin:    {10}
swpout:   {11}

""".format(procInfoDiff.duration(),
           procInfoDiff.user() * 100.0,
           procInfoDiff.sys() * 100.0,
           procInfoDiff.nice() * 100.0,
           procInfoDiff.idle() * 100.0,
           procInfoDiff.iow() * 100.0,
           procInfoDiff.irq() * 100.0,
           procInfoDiff.sirq() * 100.0,
           procInfoDiff.pgin(),
           procInfoDiff.pgout(),
           procInfoDiff.swpin(),
           procInfoDiff.swpout())

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
