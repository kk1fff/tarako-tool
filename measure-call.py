#!/usr/bin/env python

import subprocess, signal, sys, re, datetime, StringIO

sp = subprocess.Popen(['adb', 'logcat', '-s', 'CALLTRY'], stdout=subprocess.PIPE)

def signal_handler(signal, frame):
    print "Got Ctrl-C, terminate"
    sp.terminate()
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

killapp('Communications')
cleanlog()

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
while True:
    l = sp.stdout.readline().decode('utf-8')
    if l == '':
        break

    l = l.strip()
    m = re.search(r'cs ([0-9]+)$', l)
    if m != None:
        cs = int(m.group(1))
        continue
    m = re.search(r'ring ([0-9]+)$', l)
    if m != None and cs > 0:
        ring = int(m.group(1))
        print "Ringing: {0:.3f}".format(float(ring - cs)/1000000000.0)
        logb.write("Ringing: {0:.3f}\n".format(float(ring - cs)/1000000000.0))
        cs = 0
        break

log_filename = "call-time.log"
if len(sys.argv) > 2:
    log_filename = sys.argv[1]
logf = open(log_filename, 'a')
logf.write(logb.getvalue())
logf.write(".\n")
logf.close()
