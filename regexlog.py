import re
import pandas as pd
import schedule as sch
import time




pattern = r"(?P<DATE>(?:[12]\d{3})-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01]))\s+\d+\:\d+\:\d+\s+" \
          r"(?P<ACTION>\w+[ALLOW|DENY|DROP])\s+(?P<PROTOCOL>\w+[UDP|TCP])\s+" \
          r"(?P<STD_IP>(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]))\s+" \
          r"(?P<DES_IP>(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]))\s+" \
          r"(?P<STD_PORT>\d+)\s+(?P<DES_PORT>\d+)\s+\w*.{1,15}(?P<PATH>\w+[SEND|RECEIVCE])"
def parser() :
    global num,counter
    num = 0
    counter = 1
       
    file_Path = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
    with open(file_Path) as myfile :
        DATE = []
        ACTION = []
        PROTOCOL = []
        STD_IP = []
        DES_IP = []
        STD_PORT = []
        DES_PORT = []
        PATH = []
        for num,line in enumerate(myfile,counter) :
            for match in re.finditer(pattern , line) :
                DATE.append(match.group("DATE"))
                ACTION.append(match.group("ACTION"))
                PROTOCOL.append(match.group("PROTOCOL"))
                DES_IP.append(match.group("DES_IP"))
                STD_IP.append(match.group("STD_IP"))
                STD_PORT.append(match.group("STD_PORT"))
                DES_PORT.append(match.group("DES_PORT"))
                PATH.append(match.group("PATH"))
        if counter  == 1 :
            header = True
            counter = 0
        else :
            header = False
        counter +=num
         
        df = pd.DataFrame({
            'DATE' : DATE,
            'ACTION' : ACTION,
            'PROTOCOL' : PROTOCOL ,
            'STD_IP' : STD_IP ,
            'DES_IP' : DES_IP ,
            'STD_PORT' : STD_PORT ,
            'DES_PORT' : DES_PORT ,
            'PATH' : PATH ,
        })

        df.to_csv('FW_LOG.csv',mode='a',index=False,header=header)

    myfile.close()



sch.every(1).minutes.do(parser)
while True :
    sch.run_pending()
    time.sleep(1)




