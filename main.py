import argparse
import datetime
import math
import shlex
import sys
import os


import openpyxl
from openpyxl.utils.dataframe import dataframe_to_rows
import pandas
import re
import socket
import struct

# 3*2 - int("11",2) << 1 = int("110",2)
# 3 / 2 mit 0.5 truncated (Ziffern nach dem Dezimalpunkt sind weggeworfen) - int("11",2) >> 1 = int("01",2)
# 0xf / 2 mit 0.5 truncated -> int("1111",2) >> 1  -> int("0111",2)
# 0xf / 2 = 0x7
# x >> y
# Returns x with the bits shifted to the right by y places. This is the same as //'ing x by 2**y.
def cidr_to_netmask(cidr):
  cidr = int(cidr)
  mask = (0xffffffff >> (32 - cidr)) << (32 - cidr) # wenn cidr=24, 32-cidr = 8
  #0xffffffff >> 8 = int("0000 0000 1111 1111 1111 1111 1111 1111")
  #0xffffff << 8 ->  int("0000 0000 1111 1111 1111 1111 1111 1111") << 8 = int("1111 1111 1111 1111 1111 1111 0000 0000")
  #int("0000 0000 1111 1111 1111 1111 1111 1111") << 8 = ˜int("0000 0000 1111 1111 1111 1111 1111 1111")=int("1111 1111 1111 1111 1111 1111 0000 0000")
  #~x
  #Returns the complement of x - the number you get by switching each 1 for a 0 and each 0 for a 1
  return integerToDecimalDottedQuad(mask)

def netmask_to_cidr(netmask):
    '''
    :param netmask: netmask ip addr (eg: 255.255.255.0)
    :return: equivalent cidr number to given netmask ip (eg: 24)
    '''
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def integerToDecimalDottedQuad(ip_int):
  return (str( (0xff000000 & ip_int) >> 24)   + '.' +
          str( (0x00ff0000 & ip_int) >> 16)   + '.' +
          str( (0x0000ff00 & ip_int) >> 8)    + '.' +
          str( (0x000000ff & ip_int)))

def makeIntegerMask(cidr):
    #return a mask of n bits as a long integer
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return mask

def decimalDottedQuadToInteger(dottedquad):
    #convert decimal dotted quad string to long integer"
    #@ is native, ! is big-endian, native didnt work" \
    #returned the octects reversed main.integerToDecimalDottedQuad(main.decimalDottedQuadToInteger('149.246.14.224'))"
    ip_as_int = struct.unpack('!i', socket.inet_aton(dottedquad))[0]
    if ip_as_int < 0:
        ip_as_int=ip_as_int + 2**32
    return ip_as_int

def old_decimalDottedQuadToInteger(dottedquad):
    #convert decimal dotted quad string to long integer"
    #@ is native, ! is big-endian, native didnt work" \
    #returned the octects reversed main.integerToDecimalDottedQuad(main.decimalDottedQuadToInteger('149.246.14.224'))"
    return struct.unpack('!i', socket.inet_aton(dottedquad))[0]


def isIntegerAddressInIntegerNetwork(ip,net):
   #Is an address in a network"
   return ip & net == net

def isPrefix(ipaddr):
    patternPrefix = re.compile('.*?([0-9]{1,3}[^\d]+[0-9]{1,3}[^\d]+[0-9]{1,3}[^\d]+[0-9]{1,3}).*$')
    resultPrefix = patternPrefix.match(ipaddr)
    #first digit that it starts with is [1-9]
    patternPrefixCommaSeparated = re.compile('[^\d]*?([1-9][0-9]{10,11}).*$')
    resultPrefixCommaSeparated = patternPrefixCommaSeparated.match(ipaddr)
    if resultPrefix or resultPrefixCommaSeparated:
        return True
    else:
        return False

def correctMatchedPrefix(ipaddr):

    patternPrefixCommaSeparated = re.compile('^\s*([1-9][0-9]{10,11})\s*$')
    resultPrefixCommaSeparated = patternPrefixCommaSeparated.match(ipaddr)

    if resultPrefixCommaSeparated:
        digits = [int(x) for x in str(resultPrefixCommaSeparated.group(1))]
        l=len(digits)
        fourthoctet  = [digits[l-3]*100, digits[l-2]*10, digits[l-1]]
        thirdoctet = [digits[l-x]*math.pow(10, x-4)  for x in range(6, 3, -1)]
        secondoctet  = [digits[l-x]*math.pow(10, x-7) for x in range(9, 6, -1)]
        firstoctet = [digits[l-x]*math.pow(10, x-10) for x in range(l, 9, -1)]
        ip = ".".join([str(int(sum(firstoctet))),str(int(sum(secondoctet))),str(int(sum(thirdoctet))),str(int(sum(fourthoctet)))])
        return ip




#if prefix is matched as an ip address like 147,12,33,2 or with any other separator between the octets
#then it returns it with dots between the octets 147.12.33.2



#returns true if IP range is an Office IP Range, returns false otherwise
def isOfficeClientRange(officeclientrange):
    patternOffice1 = re.compile('\s*yes\s*$',re.IGNORECASE)
    patternOffice2 = re.compile('\s*y\s*$',re.IGNORECASE)

    resultOffice1 = patternOffice1.match(officeclientrange)
    resultOffice2 = patternOffice2.match(officeclientrange)
    if resultOffice1 or resultOffice2:
        return True
    else:
        return False

def correctAndCheckMatchedMask(cidr):
    patternMask = re.compile('[^\d]*(\d+)[^\d]*$')
    resultMask = patternMask.match(cidr)
    mask = resultMask.group(1)
    mask = int(mask)
    if mask >= 8 and mask <= 32:
        return mask
    else:
        raise BaseException("Mask is less,equal to 16, mask is bigger,equal to 32")


def isMask(cidr):
    patternMask = re.compile('[^\d]*(\d+)[^\d]*$')
    resultMask = patternMask.match(cidr)
    if resultMask:
        return True
    else:
        return False

def get_cli_args():
    parser = argparse.ArgumentParser("Unpacking Quality Check xlsx")
    parser.add_argument(
        '--qualitycheck', dest="qualitycheck", type=str, required=True,
        help="Path of QualityCheck.xlsx"
    )
    #ToDo add command line argument for excel file
    args = parser.parse_args(shlex.split(" ".join(sys.argv[1:])))
    return args

#Sicherzustellen dass nur ein Regex stimmt mit dem Text überein
def test_matches(attachment):


    for index, row in attachment.iterrows():


        dict_raw_field = {"app_id": [], "tufin_id": row["Tufin ID"], "ips_field": row["IPs"]}
        # dict_raw_field["app_id"],dict_raw_field["tufin_id"],dict_raw_field["ips_field"]
        field = dict_raw_field["ips_field"]
        field_list=[]
        if (not pandas.isnull(field)) and field.find(";") != -1:
            field_list = field.split(";")
        elif (not pandas.isnull(field)) and field.find("\n") != -1:
            field_list = field.split("\n")

        for i in field_list:
            i=i.strip(u'\u200b')

            inner_matches = {"single": False, "cidr": False, "range": False, "commaseparated":False, "bindestrich":False}

            patternPrefix = re.compile('^\s*(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))\s*$')
            resultPrefix = patternPrefix.match(i)
            if resultPrefix:
                inner_matches["single"]=True

            patternPrefixCIDR = re.compile('^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/(\d+)\s*$')
            resultPrefixCIDR = patternPrefixCIDR.match(i)
            if resultPrefixCIDR:
                inner_matches["cidr"]=True

            patternPrefixRange = re.compile('^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.([0-9]{1,3})-(\d+)\s*$')
            resultPrefixRange = patternPrefixRange.match(i)
            if resultPrefixRange:
                inner_matches["range"]=True

            patternPrefixCommaSeparated = re.compile('^\s*([1-9][0-9]{10,11})\s*$')
            resultPrefixCommaSeparated = patternPrefixCommaSeparated.match(i)
            if resultPrefixCommaSeparated:
                ip_trsfrmd=correctMatchedPrefix(i)
                inner_matches["commaseparated"]=True

            patternBindestrich = re.compile('^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})-([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*$')
            resultBindestrich = patternBindestrich.match(i)
            if resultBindestrich:
                inner_matches["bindestrich"] = True
                start_ip_b=resultBindestrich.group(1)
                end_ip_b=resultBindestrich.group(2)
                #ToDo resultBindestrich.group(1), group(2)
                #ToDo if group(1) < 0: group(1)=group(1) + 2**32
                #ToDo for i in  range(quadToInt(group(1)),quadToInt(group(2))+1)

            if not any(inner_matches.values()) and not (i.find("Same as the App") != -1) and not len(i)==0 :
                print("no regex match for 'field'{}".format(i))

            numberofmatches=0
            for m in inner_matches.values():
                if m:
                    numberofmatches+=1
            if numberofmatches > 1:
                print("too many regex matches")

def get_processed_qc_as_list(attachment_qc):

    test_matches(attachment_qc)
    # use for capturing ip,ip/mask,ip.ip.ip.ip-ip
    list_dict_transformed = []
    for index, row in attachment_qc.iterrows():
        dict_raw_field = {"app_id": row["APP ID"], "tufin_id": row["Tufin ID"], "ips_field": row["Destination IPs"]}
        # dict_raw_field["app_id"],dict_raw_field["tufin_id"],dict_raw_field["ips_field"]

        field = dict_raw_field["ips_field"]
        field_list = []

        list_unpacked_ips = []

        if (not pandas.isnull(field)) and field.find(";") != -1:
            field_list = field.split(";")
        elif (not pandas.isnull(field)) and field.find("\n") != -1:
            field_list = field.split("\n")
        elif (not pandas.isnull(field)):
            field = field.strip(u'\u200b')
            patternPrefix = re.compile('^\s*(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))\s*$')
            resultPrefix = patternPrefix.match(field)
            if resultPrefix:
                prefix = resultPrefix.group(1)
                list_unpacked_ips.append(prefix)

        if len(field_list)==1:
            print("!!!field_list==1")





        for i in field_list:
            i = i.strip(u'\u200b')

            patternPrefix = re.compile('^\s*(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))\s*$')
            resultPrefix = patternPrefix.match(i)
            if resultPrefix:
                prefix = resultPrefix.group(1)
                list_unpacked_ips.append(prefix)

            patternPrefixCIDR = re.compile('^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/(\d+)\s*$')
            resultPrefixCIDR = patternPrefixCIDR.match(i)
            if resultPrefixCIDR:
                prefix2 = resultPrefixCIDR.group(1)
                cidr2 = correctAndCheckMatchedMask(resultPrefixCIDR.group(2))

                base = integerToDecimalDottedQuad(
                    decimalDottedQuadToInteger(prefix2) & makeIntegerMask(
                        cidr2))
                if base != prefix2:
                    print("Not a network Adresse (possible ip base %s)" % base)

                int_prefix_top = (~makeIntegerMask(
                    cidr2)) | decimalDottedQuadToInteger(prefix2)
                if int_prefix_top - 2 * 32 == -4117887025:
                    print("Test singed to unsigned conversion")
                    # ToDo breakpoint setzen, Werte die die for Schleife ausspuckt mit den erwarteten Ergebnisse zu vergleichen
                    # Modified
                    #    decimalDottedQuadToInteger()
                    # to convert signed integers to unsigned.
                    # Das Folgende ist redundant, überreichlich, ersetzt:
                    #   int_prefix_top == -4117887025:
                    #   if int_prefix_top < 0:
                    #      int_prefix_top = int_prefix_top + (2**32)

                prefix_top = integerToDecimalDottedQuad(int_prefix_top)
                print("netw.adrr.:{}".format(base))
                for j in range(decimalDottedQuadToInteger(base) + 1,
                               decimalDottedQuadToInteger(
                                       integerToDecimalDottedQuad(int_prefix_top)) + 1):
                    list_unpacked_ips.append(integerToDecimalDottedQuad(j))

            patternPrefixRange = re.compile('^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.([0-9]{1,3})-(\d+)\s*$')
            resultPrefixRange = patternPrefixRange.match(i)
            if resultPrefixRange:
                prefix3 = resultPrefixRange.group(1)
                fourthoctet3 = resultPrefixRange.group(2)
                fifthoctet3 = resultPrefixRange.group(3)

                start_ip = ".".join([prefix3, fourthoctet3])
                end_ip = ".".join([prefix3, fifthoctet3])
                for j in range(decimalDottedQuadToInteger(start_ip) + 1,
                               decimalDottedQuadToInteger(end_ip) + 1):
                    list_unpacked_ips.append(integerToDecimalDottedQuad(j))

            patternPrefixCommaSeparated = re.compile('^\s*([1-9][0-9]{10,11})\s*$')
            resultPrefixCommaSeparated = patternPrefixCommaSeparated.match(i)
            if resultPrefixCommaSeparated:
                ip_trsfrmd = correctMatchedPrefix(i)
                list_unpacked_ips.append(ip_trsfrmd)

            patternBindestrich = re.compile(
                '^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})-([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*$')
            resultBindestrich = patternBindestrich.match(i)
            if resultBindestrich:
                start_ip_b = resultBindestrich.group(1)
                end_ip_b = resultBindestrich.group(2)
                for j in range(decimalDottedQuadToInteger(start_ip_b),
                               decimalDottedQuadToInteger(start_ip_b) + 1):
                    list_unpacked_ips.append(integerToDecimalDottedQuad(j))

        for element in list_unpacked_ips:
            list_dict_transformed.append(
                #{"app_id": dict_raw_field["app_id"], "tufin_id": dict_raw_field["tufin_id"], "ip": element, "excel_row_line": (index + 2)}
                {"Change Type":row["Change Type"],"Tufin ID":row['Tufin ID'],"Last modify date":row["Last \nmodify\n date"],
                 "Last modified by Version":row["Last modified by Version"],"requested by":row["requested by"],"approved_by":row["approved by"],
                 "APP ID":row["APP ID"],"Source":row["Source"],"Destination FQDNs":row["Destination FQDNs"],
                 "Destination Info":row["Destination Info"],"Protocol type_port":row["Protocol type_port"],
                 "ACP Level":row['ACP Level'],"TSA expiration date":row["TSA expiration date"],"Application Requester":row["Application Requester"]
                    "Comment":row["Comment"]})

    return list_dict_transformed


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    filepath_qc = get_cli_args().qualitycheck
    if os.path.exists(filepath_qc):
        qc = pandas.read_excel(filepath_qc, sheet_name="white_Apps",
                                 index_col=None, engine='openpyxl')
    else:
        raise FileNotFoundError(filepath_qc)

    attachment_qc = pandas.read_excel(filepath_qc, index_col=None, dtype=str, engine='openpyxl')
    
    df_qc = pandas.DataFrame(get_processed_qc_as_list(attachment_qc))

    wb = openpyxl.Workbook()
    ws = wb.active

    for r in dataframe_to_rows(df_qc, index=False, header=True):
        ws.append(r)

    today = datetime.date.today()
    path_to_outfile = "./se_ruleset_unpacked" + today.strftime("%d%b%Y") + ".xlsx"
    wb.save(path_to_outfile)

    print("Done")