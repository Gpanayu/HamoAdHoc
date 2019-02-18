import thread
import scapy.all as scp
from random import randint
import time
from scapy.utils import hexdump
import RPi.GPIO as GPIO
import time

GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
GPIO.setup(18,GPIO.OUT)

delay = 5
overwatchDelay = 20
meetingDelay = 20
gapMargin = 20
bufferSize = 10
averageLocation = (0,0)
latestCompleteSeq = -1
members = {'Peer1': '192.168.1.42', 'Peer2': '192.168.1.41', "Peer3": '192.168.1.43'}
acceptedMembers = ['Peer1', 'Peer2', 'Peer3']

memberData = {
    "Peer1": [],
    "Peer2": [],
    "Peer3": []
    }
memberDataLatest = {
    "Peer1" : -1,
    "Peer2" : -1,
    "Peer3" : -1
    }
myname = "Peer1"
myseq = 0
mode = "explore"


def sender():
    global mode
    while(1):
        #generate GPS location
        print("MODE: ",mode)
        if mode == "explore":
            GPIO.output(18,GPIO.HIGH)
            time.sleep(0.1)
            GPIO.output(18,GPIO.LOW)
        if mode == "emergency":
            GPIO.output(18,GPIO.HIGH)
        global myseq
        lat = randint(0,10)
        lon = randint(0, 10)
        ts = time.time()
        try:
            msg = myname+","+str(myseq)+","+str(lat)+","+str(lon)+","+str(ts)
            myseq += 1
            for member in members:
                packet = scp.IP(dst=members[member])/scp.ICMP()/scp.Raw(load=msg)
                scp.send(packet)
        except:
            print('cannot send message')
        time.sleep(delay)
 
def packet_handler(packet):
    global memberDataLatest
    print(memberDataLatest)
    raw_pkt = scp.raw(packet)
    enableFlag = False
    if(b'Peer1' in raw_pkt and 'Peer1' in acceptedMembers):
        enableFlag = True
        idx = raw_pkt.index("Peer1")
        data = str(raw_pkt[idx+5:]).strip().split(',')
        msg2 = raw_pkt[idx:].strip()
        name = "Peer1"
    if(b'Peer2' in raw_pkt and 'Peer2' in acceptedMembers):
        enableFlag = True
        idx = raw_pkt.index("Peer2")
        data = str(raw_pkt[idx+5:]).strip().split(',')
        msg2 = raw_pkt[idx:].strip()
        name = "Peer2"
    if(b'Peer3' in raw_pkt and 'Peer3' in acceptedMembers):
        enableFlag = True
        idx = raw_pkt.index("Peer3")
        data = str(raw_pkt[idx+5:]).strip().split(',')
        msg2 = raw_pkt[idx:].strip()
        name = "Peer3"
    if ((b'Peer1' in raw_pkt) or (b'Peer2' in raw_pkt) or (b'Peer3' in raw_pkt)) and enableFlag:
        mData = data
        if int(mData[0]) > memberDataLatest[name]:
            memberDataLatest[name] = int(mData[0])
            mData[-1] = str(time.time())
            memberData[name].append(mData)
            for member in members:
                pkt = scp.IP(dst=members[member])/scp.ICMP()/scp.Raw(load=msg2)
                scp.send(pkt)
            if len(memberData[name]) > bufferSize:
                memberData[name].pop(0)
            
def receiver():
    scp.sniff(iface='wlan0', filter='icmp and (host 192.168.1.41 or host 192.168.1.42 or host 192.168.1.43) and host not 192.168.1.40'
              , prn=packet_handler, store=0)
    
def overwatch():
    global mode
    global memberDataLatest
    global memberData
    missingMember = ''
    latestSynced = {}
    refTimestamp = 0
    while (1):
        if mode == "explore":
            print("Exploring")
            while True:                
                time.sleep(overwatchDelay)
                timeTmp = time.time()
                copyOfMemberData = memberData.copy()
                flagAllMembers = True
                for member in copyOfMemberData:
                    if len(copyOfMemberData[member]) == 0:
                        print('Wait for all members')
                        print('Not found = '+str(member))
                        flagAllMembers = False
                if flagAllMembers == False:
                    continue
                for member in copyOfMemberData:
                    if(len(copyOfMemberData[member]) ==  0):
                        print('Wait for members')
                        print(copyOfMemberData)
                        continue
                    timeDiff = timeTmp - float(copyOfMemberData[member][-1][-1])
                    if timeDiff > gapMargin:
                        print('Someone is missing')
                        print("Member = "+str(member))
                        print("timeDiff = "+str(timeDiff))
                        print("timeTmp = "+str(timeTmp))
                        print("float(copyOfMemberData[member][-1][-1])"+str(float(copyOfMemberData[member][-1][-1])))
                        print(str(copyOfMemberData))
                        missingMember = member
                        refTimestamp = float(copyOfMemberData[member][-1][-1])
                        mode = "emergency"
                        memberDataLatest[member] = -1
                    else: print('OK')
                copyOfMemberData.clear()
                if mode == "emergency":
                    break
        else:
            # Emergency mode
            copyOfMemberData = memberData.copy()
            print("Emergency")
            sumRefLat = 0
            sumRefLon = 0
            for member in copyOfMemberData:
                minDiff = 1000000000
                refMemberTimestamp = -1
                refMemberLat = -1
                refMemberLon = -1
                for i in range(len(copyOfMemberData[member])):
                    row = copyOfMemberData[member][len(copyOfMemberData[member])-1-i]
                    row[-1] = float(row[-1])
                    row[0] = float(row[0])
                    row[1] = float(row[1])
                    if (abs(float(row[-1]) - float(refTimestamp)) <= minDiff and float(row[-1]) <= refTimestamp):
                        refMemberTimestamp = row[-1]
                        refMemberLat = float(row[1])
                        refMemberLon = float(row[2])
                        minDiff = abs(row[-1] - refTimestamp)
                    if abs(row[-1] - refTimestamp) > minDiff and row[-1] < refTimestamp:
                        break
                latestSynced[member] = (refMemberTimestamp, refMemberLat, refMemberLon)
                sumRefLat += refMemberLat
                sumRefLon += refMemberLon
            copyOfMemberData.clear()
            avgLat = sumRefLat / len(members)
            avgLon = sumRefLon / len(members)
            print("Meeting point (lat, lon) = ("+str(avgLat)+", "+str(avgLon)+")")
            memberData[member] = []
            while True:
                ts = time.time()
                copyMemberData = memberData.copy()
                checker = True
                for member in copyMemberData:
                    print("member = "+str(member)+" memberlatest = "+str(memberDataLatest[member]))
                    if memberDataLatest[member] == -1:
                        print("that member = "+str(member))
                        checker = False
                        break
                copyMemberData.clear()
                if checker:
                    mode = "explore"
                    break
                time.sleep(5)
      
try:
    thread.start_new_thread(sender, ())
    thread.start_new_thread(receiver, ())
    thread.start_new_thread(overwatch, ())
    while True:
        s = raw_input()
        s = s.strip().split()
        acceptedMembers = []
        for i in range(len(s)):
            if s[i] == myname:
                continue
            elif s[i] == 'Peer1':
                if 'Peer1' in acceptedMembers:
                    acceptedMembers.append('Peer1')
            elif s[i] == 'Peer2':
                if 'Peer2' in acceptedMembers:
                    acceptedMembers.append('Peer2')
            elif s[i] == 'Peer3':
                if 'Peer3' in acceptedMembers:
                    acceptedMembers.append('Peer3')
        acceptedMembers.append(myname)
except:
    print("Failed miserably")

while(1): pass
