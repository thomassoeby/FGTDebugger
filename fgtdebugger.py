import netmiko
import sys
import datetime
import logging
import time
import keyboard
import re
import os
import getpass
import ipaddress
import configparser
from netmiko import ConnectHandler

HostIP = ""
Username = "admin"
Password = ""
filterValueType = ""
filterValueOption1 = ""
filterValueOption2 = ""
configFile = None
useConfig = False
dataDict = {}

cmdListClearDebug = [
    'diagnose debug reset',
    'diagnose debug disable',
    'diagnose debug flow trace stop',
    'diagnose debug flow filter clear'
]

cmdListEnableDebug = [
    'diagnose debug console timestamp enable',
    'diagnose debug flow show function-name',
    'filter-placeholder',
    'diagnose debug enable',
    'diagnose debug flow trace start 1000'
]

filterOptions = ['addr','saddr','daddr','port','sport','dport']
## 'vd' and 'negate' are not implemented yet.
# filterOptions_NYI = ['vd','negate']

logging.basicConfig(filename="test.log", level=logging.DEBUG)
logger = logging.getLogger("netmiko")

#Validate that input is an actual IPv4 address.
def validateIPv4(_ipaddress):
    try:
        ipaddress.IPv4Address(_ipaddress)
    except ValueError:
        print("Invalid IPv4 Address: " + _ipaddress)
        return False
    except:
        print("Unhandled error occured on: " + _ipaddress)
        return False
    return True    

#Validate that input is a tcp/udp port number (0-65535).
def validatePort(_port):
    regex = re.match('^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$',_port)
    return regex

def convertLogToDict(_data):
    dataList = _data.splitlines()
    global dataDict
    for x in dataList:
        traceid = re.search(r".+trace_id=(\d+)\s",x).group(1)
        if traceid not in dataDict:
            dataDict[traceid] = [x]
        else:
            dataDict[traceid].append(x)
    return

def saveAsHTML(_data):
    now = datetime.datetime.now()
    htmlfile = open("output-" + now.strftime("%d-%m-%Y_%H-%M-%S") + ".html","a+")

    #Prepare static header/footer code, write header code and then proceed to create dynamic content.

    metadata_top = """
    <!DOCTYPE html>
    <html>
    <head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
    .collapsible {
    background-color: #777;
    color: white;
    cursor: pointer;
    padding: 18px;
    width: 100%;
    border: none;
    text-align: left;
    outline: none;
    font-size: 15px;
    }

    .active, .collapsible:hover {
    background-color: #555;
    }

    .content {
    padding: 0 18px;
    display: none;
    overflow: hidden;
    background-color: #f1f1f1;
    }
    </style>
    </head>
    <body>
    """
    metadata_bottom = """
    <script>
    var coll = document.getElementsByClassName("collapsible");
    var i;

    for (i = 0; i < coll.length; i++) {
    coll[i].addEventListener("click", function() {
        this.classList.toggle("active");
        var content = this.nextElementSibling;
        if (content.style.display === "block") {
        content.style.display = "none";
        } else {
        content.style.display = "block";
        }
    });
    }
    </script>

    </body>
    </html>

    """
    htmlfile.write(metadata_top)
    htmlfile.write("<h2>Diagnose Debug Flow Report</h2>")
    htmlfile.write("<h3>Host: " + HostIP + "</h3>\n")
    htmlfile.write("<h3>Filter type: " + filterValueType + "</h3>\n")
    htmlfile.write("<h3>Filter Option 1: " + filterValueOption1 + "</h3>\n")
    htmlfile.write("<h3>Filter Option 2: " + filterValueOption2 + "</h3>\n")
    #Extract data fields from log and parse them to header text.
    for key in _data:
        regexSrcDst = re.match(r".+proto=\d+,\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})..(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}:(\d{1,5})).+",_data[key][0])
        regexTimestamp = re.match(r"(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}).+",_data[key][0])
        sourceIP = regexSrcDst.group(1)
        sourcePort = regexSrcDst.group(2)
        destIP = regexSrcDst.group(3)
        destPort = regexSrcDst.group(4)
        timestamp = regexTimestamp.group(1)
        header = timestamp + " Src: " + sourceIP + ":" + sourcePort + " -->> Dst: " + destIP + ":" + destPort 
        htmlfile.write("<button type=\"button\" class=\"collapsible\">" + str(header) + "</button>\n")
        htmlfile.write("<div class=\"content\">\n")
        #output raw loglines in collapsible row
        for item in _data[key]:
            htmlfile.write("<p>" + item + "</p>\n")
        htmlfile.write("</div>\n")
    htmlfile.write(metadata_bottom)
    htmlfile.close()
    return


#Validate if config file exists, and the key values are acceptable.
def checkConfig():
    invalidValues = []
    if os.path.exists('./host.cfg'):
        global configFile
        configFile = configparser.ConfigParser()
        configFile.read('host.cfg')

        if configFile.has_section('FGTDebugger') == False:
            print('Invalid or empty config file.')
            return False

        if validateIPv4(configFile['FGTDebugger']['HostIP']) == False:
            invalidValues.append("HostIP")
        
        if configFile['FGTDebugger']['Username'] == '':
            invalidValues.append("Username")

        if configFile['FGTDebugger']['Password'] == '':
            invalidValues.append("Password")

        if configFile['FGTDebugger']['filterValueType'] not in filterOptions:
            invalidValues.append("filterValueType")
        else:
            if configFile['FGTDebugger']['filterValueType'] in ['saddr','daddr','addr']:
                if validateIPv4(configFile['FGTDebugger']['filterValueOption1']) == False:
                    invalidValues.append("filterValueOption1")
                if configFile['FGTDebugger']['filterValueOption2'] != '':
                    if validateIPv4(configFile['FGTDebugger']['filterValueOption2']) == False:
                        invalidValues.append('filterValueOption2')
            if configFile['FGTDebugger']['filterValueType'] in ['sport', 'dport', 'port']:
                if validatePort(configFile['FGTDebugger']['filterValueOption1']) == False:
                    invalidValues.append('filterValueOption1')
                if configFile['FGTDebugger']['filterValueOption2'] != '':
                    if validatePort(configFile['FGTDebugger']['filterValueOption2']) == False:
                        invalidValues.append('filterValueOption2')

        if not invalidValues:
            print("**** Config validated ****")
            return True
        else:
            print('**** Error loading host.cfg. Falling back to manual input.****\n  ->Invalid values found:') 
            for x in invalidValues:
                print("->" + x + " = " + configFile['FGTDebugger'][x])
            return False

    else:
        print('**** Config file host.cfg not present, creating ****')

        return False

#Load all values from the config file into vars
def loadConfigValues(_configFile):
    global HostIP
    global Username
    global Password
    global filterValueType
    global filterValueOption1
    global filterValueOption2
    global configFile

    HostIP = configFile['FGTDebugger']['HostIP']
    Username = configFile['FGTDebugger']['Username']
    Password = configFile['FGTDebugger']['Password']
    filterValueType = configFile['FGTDebugger']['filterValueType']
    filterValueOption1 = configFile['FGTDebugger']['filterValueOption1']
    filterValueOption2 = configFile['FGTDebugger']['filterValueOption2']

    print("**** Config loaded ****")
    for key in configFile['FGTDebugger']:
        if(key.lower() == 'password'):
            print("->" + key + ": ******")
        else:
            print("->" + key + ": " + configFile['FGTDebugger'][key])
    return

#Save config file with manually typed values.
def saveConfig():
    global configFile

    if configFile == None:
        configFile = configparser.ConfigParser()

    if configFile.has_section('FGTDebugger') == False:
        configFile.add_section('FGTDebugger')

    configFile.set('FGTDebugger','HostIP',HostIP)
    configFile.set('FGTDebugger','Username',Username)
    configFile.set('FGTDebugger','Password',Password)
    configFile.set('FGTDebugger','filterValueType',filterValueType)
    configFile.set('FGTDebugger','filterValueOption1',filterValueOption1)
    configFile.set('FGTDebugger','filterValueOption2',filterValueOption2)

    with open('host.cfg', 'w') as file:
        configFile.write(file)

    print("Config saved.")
    return


if checkConfig() == True:
    while True:
        choice = input('Load options from config(y/n): ')
        if choice.lower() == 'y':
            useConfig = True
            break
        elif choice.lower() == 'n':
            useConfig = False
            break

if useConfig == True:
    print('*** Using Config file host.cfg ****')
    loadConfigValues(configFile)
else:
    while True:
        userInput = input("Enter FortiGate IP: ")

        if validateIPv4(userInput):
            HostIP = userInput
            break
        else:
            print("invalid IP")

    userInput = input("Username (leave blank for 'admin'): ")
    if userInput != '':
        Username = userInput
    else:
        Username = 'admin'


    while True:
        userInput = getpass.getpass('Password: ')
        if userInput != '':
            Password = userInput
            break
        else:
            print('No password entered.')


    options = ""

    for value in filterOptions:
        options += value + " "

    while True:    
        print("Valid filter options are: {}".format(options))
        userInput = input("Enter filter option: ")
        if userInput in filterOptions:
            filterValueType = userInput
            break
        else:
            print("Invalid Option")


    while True:
        print("Option 1 is a host IP/Single port number, or the start of a range of IPs/port numbers if Option 2 is entered after.")
        userInput = input('Enter filter option 1 ({}): '.format(filterValueType))
        if filterValueType in ['saddr','daddr','addr']:
            if validateIPv4(userInput):
                filterValueOption1 = userInput
                break
        if filterValueType in ['sport', 'dport', 'port']:
            if validatePort(userInput):
                filterValueOption1 = userInput
                break

        print('Invalid value.')

    while True:
        userInput = input('Enter filter option 2 ({}). (Leave blank to skip): '.format(filterValueType))
        if userInput == '':
            break
        if filterValueType in ['saddr','daddr','addr']:
            if validateIPv4(userInput):
                filterValueOption2 = userInput
                break
        if filterValueType in ['sport', 'dport', 'port']:
            if validatePort(userInput):
                filterValueOption2 = userInput
                break

print('**** Session Setup in progress ****')

device = {
    'device_type' : 'fortinet',
    'host' : HostIP,
    'username' : Username,
    'password' : Password
}

try:
    net_connect = ConnectHandler(**device,fast_cli=True)
    print('**** Session Setup completed, configuring the debug settings ****')

    for command in cmdListClearDebug:
        print("->#" + command)
        net_connect.send_command(command)

    filterIndex = cmdListEnableDebug.index('filter-placeholder')

    if filterValueOption2 != '':
        cmdListEnableDebug[filterIndex] = 'diagnose debug flow filter {0} {1} {2}'.format(filterValueType,filterValueOption1,filterValueOption2)
    else:
        cmdListEnableDebug[filterIndex] = 'diagnose debug flow filter {0} {1}'.format(filterValueType,filterValueOption1)

    for command in cmdListEnableDebug:
        print("->#" + command)
        net_connect.send_command(command)

    result = ""

    print('**** Trace started - Ctrl+C to stop ****')

    try:
        while True:
            time.sleep(0.1)
            output = net_connect.read_channel()
            if len(output) > 2:
                print(output)
                result += output
    except KeyboardInterrupt:
        pass

    print('**** Trace stopped ****')

    for command in cmdListClearDebug:
        net_connect.send_command(command)

    print('**** Disabled debugging  ****')

except(EOFError):
    print("SSH not enabled on: " + HostIP)
except netmiko.ssh_exception.NetMikoAuthenticationException:
    print("Authentication failed on: " + HostIP)
except Exception as e:
    print("Unhandled error occured on: " + HostIP + ": " + e)

now = datetime.datetime.now()
f = open("output-" + now.strftime("%d-%m-%Y_%H-%M-%S") + ".txt","w+")
f.write(result)
f.close()

print('**** Output written to file  ****')


convertLogToDict(result)
saveAsHTML(dataDict)



if useConfig == False:
    while True:
        saveChoice = input("Save used config to host.conf?(y/n): ")

        if saveChoice.lower() == 'y':
            saveConfig()
            break
        elif saveChoice.lower() == 'n':
            break