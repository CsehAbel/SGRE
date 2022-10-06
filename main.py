import argparse
import datetime
import math
import shlex
import sys
import os
from pathlib import Path

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
import file_operations


def cidr_to_netmask(cidr):
  cidr = int(cidr)
  mask = (0xffffffff >> (32 - cidr)) << (32 - cidr) # wenn cidr=24, 32-cidr = 8
  #0xffffffff >> 8 = int("0000 0000 1111 1111 1111 1111 1111 1111")
  #0xffffff << 8 ->  int("0000 0000 1111 1111 1111 1111 1111 1111") << 8 = int("1111 1111 1111 1111 1111 1111 0000 0000")
  #int("0000 0000 1111 1111 1111 1111 1111 1111") << 8 = ˜int("0000 0000 1111 1111 1111 1111 1111 1111")=int("1111 1111 1111 1111 1111 1111 0000 0000")
  #~x
  #Returns the complement of x - the number you get by switching each 1 for a 0 and each 0 for a 1
  return integer_to_ipaddress(mask)

def netmask_to_cidr(netmask):
    '''
    :param netmask: netmask ip addr (eg: 255.255.255.0)
    :return: equivalent cidr number to given netmask ip (eg: 24)
    '''
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def integer_to_ipaddress(ip_int):
  return (str( (0xff000000 & ip_int) >> 24)   + '.' +
          str( (0x00ff0000 & ip_int) >> 16)   + '.' +
          str( (0x0000ff00 & ip_int) >> 8)    + '.' +
          str( (0x000000ff & ip_int)))

def makeIntegerMask(cidr):
    #return a mask of n bits as a long integer
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return mask

def ipaddress_to_integer(dottedquad):
    #convert decimal dotted quad string to long integer"
    #@ is native, ! is big-endian, native didnt work" \
    #returned the octects reversed main.integerToDecimalDottedQuad(main.decimalDottedQuadToInteger('149.246.14.224'))"
    ip_as_int = struct.unpack('!i', socket.inet_aton(dottedquad))[0]
    if ip_as_int < 0:
        ip_as_int=ip_as_int + 2**32
    return ip_as_int

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
    return mask

def iprange_to_cidr(inet_start, inet_stop):
    #convert the first ip of the range to an integer
    start = ipaddress_to_integer(inet_start)
    #convert the last ip of the range to an integer
    stop = ipaddress_to_integer(inet_stop)
    #calculate the difference between the two integers
    # the number of bits needed to represent the difference subtracted from 32 is the cidr
    diff = stop - start
    #calculate the number of bits needed to represent the difference
    bits = math.ceil(math.log(diff, 2))
    #calculate the cidr
    cidr = 32 - bits
    return cidr

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

def parse_tsa_as_date(node1, candidate):
    head = node1
    tsa = ""
    while (head is not None):
        try:
            tsa = datetime.datetime.strptime(candidate, head.data)
        except:
            head = head.next
        else:
            break
    return tsa

# rewrite parse_tsa_as_date2(node1, candidate) as a recursive function
def parse_tsa_as_date2(node1, candidate):
    try:
        tsa = datetime.datetime.strptime(candidate, node1.data)
    except:
        if node1.next is not None:
            return parse_tsa_as_date2(node1.next, candidate)
        else:
            return None
    else:
        return node1


#class tree node
class Node:
    def __init__(self, data):
        self.data = data
        self.next = None

        def __str__(self):
            return self.data

        def __repr__(self):
            return self.data
#class tree
class Tree:
    def __init__(self):
        self.head = None
        self.tail = None
        self.size = 0

    def __str__(self):
        return str(self.head)

    def __repr__(self):
        return str(self.head)

    def add(self, data):
        node = Node(data)
        if self.head is None:
            self.head = node
            self.tail = node
        else:
            self.tail.next = node
            self.tail = node
        self.size += 1

    def __len__(self):
        return self.size



def get_processed_qc_as_list(filepath_qc):
    attachment_qc = pandas.read_excel(filepath_qc, index_col=None, sheet_name="white_Apps", dtype=str, engine='openpyxl')
    list_dict_transformed_outer= []
    # use for capturing ip,ip/mask,ip.ip.ip.ip-ip
    for index, row in attachment_qc.iterrows():

        # regex pattern for integer, match row[APP_ID] with pattern, if no match then print error
        pattern = re.compile('^\s*(\d+)\s*$')
        # result = pattern.match(row["APP ID"])
        # surrounding with try except block to catch errors
        try:
            result = pattern.match(row["APP ID"]) if not pandas.isnull(row["APP ID"]) else False
            if not result:
                # print error with index
                print("Error in row " + str(index) + " APP ID is not an integer:" + str(row["APP ID"]))
        except:
            print("row[APP ID] went to shit, please check APP ID: " + row["APP ID"])

        # check if AppName is not an empty string or empty, if empty then print error
        if not row["AppName"]:
            print("Error in AppName: " + row["AppName"] + " in row " + str(index))

        tsa = parse(row["TSA expiration date"])
        if tsa=="":
            print("{0}{1}{2}".format(index,row["TSA expiration date"],"not valid, tsa set to empty string"))

        #each field can contain multiple ips or ip ranges, separated by ; or \n
        #returns list of [start,end,cidr]
        field=row["Destination IPs"]
        list_unpacked_ips = process_ip_field_per_row(field)
        #for each element in list_unpacked_ips create a new dictinary, with single ip,[start,end,cidr] and
        #row values and tsa, and append to list_dict_transformed
        list_dict_transformed=create_excel_input(list_unpacked_ips, row, tsa)
        #append list_dict_transformed to list_dict_transformed_outer
        list_dict_transformed_outer.extend(list_dict_transformed)

    return list_dict_transformed_outer


def create_excel_input(list_unpacked_ips, row, tsa):
    list_dict_transformed = []
    for i in list_unpacked_ips:
        single_ips = map_range_to_single_ip(i[0], i[1])
        list_dict_transformed_inner = []
        for ip in single_ips:
            #check if i[2] is not type string
            if not isinstance(i[2], int):
                print("cidr is not a string: " + str(i[2]))
                raise TypeError
            dict_transformed = {"Destination IP": ip,
                                "Destination IP Start": i[0],
                                "Destination IP End": i[1],
                                "Destination IP CIDR": i[2],
                                "FQDNs": row["Destination FQDNs"],
                                "Protocol type port": row["Protocol type_port"],
                                "TSA": tsa,
                                # row["Application Name"],
                                "Applicaton Name": row["AppName"],
                                "APP ID": row["APP ID"],
                                "Change Type": row["Change Type"],
                                "Comment": row["Comment"]
                                }
            list_dict_transformed_inner.append(dict_transformed)
        list_dict_transformed.extend(list_dict_transformed_inner)
    return list_dict_transformed



def process_ip_field_per_row(field):
        field_list = []

        # create a list of start and end ip,cidr
        list_unpacked_ips = []

        if (not pandas.isnull(field)) and field.find(";") != -1:
            field_list = field.split(";")
        elif (not pandas.isnull(field)) and field.find("\n") != -1:
            field_list = field.split("\n")
        elif (not pandas.isnull(field)):
            field_list = []
            field_list.append(field)

        for i in field_list:
            #Sicherzustellen dass nur ein Regex mit dem Text übereinstimmt
            inner_matches = {"single": False, "cidr": False, "range": False, "commaseparated": False,
                             "bindestrich": False}

            i = i.strip(u'\u200b')

            patternPrefix = re.compile('^\s*(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))\s*$')
            resultPrefix = patternPrefix.match(i)
            if resultPrefix:
                inner_matches["single"] = True
                prefix = resultPrefix.group(1)
                #end ip is the same as start ip
                #cidr is 32
                list_unpacked_ips.append([prefix,prefix,32])

            patternPrefixCIDR = re.compile('^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/(\d+)\s*$')
            resultPrefixCIDR = patternPrefixCIDR.match(i)
            if resultPrefixCIDR:
                inner_matches["cidr"] = True
                prefix2 = resultPrefixCIDR.group(1)
                cidr2 = correctAndCheckMatchedMask(resultPrefixCIDR.group(2))
                base = integer_to_ipaddress(
                    ipaddress_to_integer(prefix2) & makeIntegerMask(
                        cidr2))
                if base != prefix2:
                    print("Not a network Adresse (possible ip base %s)" % base)

                int_prefix_top = (~makeIntegerMask(
                    cidr2)) | ipaddress_to_integer(prefix2)
                if int_prefix_top - 2 * 32 == -4117887025:
                    print("Test signed to unsigned conversion")
                    # ToDo breakpoint setzen, Werte die die for Schleife ausspuckt mit den erwarteten Ergebnisse zu vergleichen
                    # Modified
                    #    decimalDottedQuadToInteger()
                    # to convert signed integers to unsigned.
                    # Das Folgende ist redundant, überreichlich, ersetzt:
                    #   int_prefix_top == -4117887025:
                    #   if int_prefix_top < 0:
                    #      int_prefix_top = int_prefix_top + (2**32)
                prefix_top = integer_to_ipaddress(int_prefix_top)

                list_unpacked_ips.append([base,prefix_top,cidr2])

            patternPrefixRange = re.compile('^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.([0-9]{1,3})-(\d+)\s*$')
            resultPrefixRange = patternPrefixRange.match(i)
            if resultPrefixRange:
                inner_matches["range"] = True
                prefix3 = resultPrefixRange.group(1)
                fourthoctet3 = resultPrefixRange.group(2)
                fifthoctet3 = resultPrefixRange.group(3)

                start_ip = ".".join([prefix3, fourthoctet3])
                end_ip = ".".join([prefix3, fifthoctet3])
                list_unpacked_ips.append([start_ip,end_ip,iprange_to_cidr(start_ip,end_ip)])

            patternPrefixCommaSeparated = re.compile('^\s*([1-9][0-9]{10,11})\s*$')
            resultPrefixCommaSeparated = patternPrefixCommaSeparated.match(i)
            if resultPrefixCommaSeparated:
                inner_matches["commaseparated"] = True
                ip_trsfrmd = correctMatchedPrefix(i)
                list_unpacked_ips.append(ip_trsfrmd,ip_trsfrmd,32)

            patternBindestrich = re.compile(
                '^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})-([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*$')
            resultBindestrich = patternBindestrich.match(i)
            if resultBindestrich:
                inner_matches["bindestrich"] = True
                start_ip_b = resultBindestrich.group(1)
                end_ip_b = resultBindestrich.group(2)
                list_unpacked_ips.append([start_ip_b,end_ip_b,iprange_to_cidr(start_ip_b,end_ip_b)])

            if not any(inner_matches.values()) and not (i.find("Same as the App") != -1) and not len(i) == 0:
                print("no regex match for index:%s IPs:%s" % (i, field))

            numberofmatches = 0
            for m in inner_matches.values():
                if m:
                    numberofmatches += 1
            if numberofmatches > 1:
                print("too many regex matches")
                raise ValueError()

        return list_unpacked_ips

#used for resultBindestrich
#used for resultPrefixCIDR
#used for resultPrefixRange
# unpacks a range of ip addresses, start,end given as a string
def map_range_to_single_ip(start_ip,end_ip):
    list_unpacked_ips = []
    for j in range(ipaddress_to_integer(start_ip) + 1,
                ipaddress_to_integer(end_ip) + 1):
        list_unpacked_ips.append(integer_to_ipaddress(j))
    return list_unpacked_ips

# tries to parse the given string as a date
def parse(candidate):
    # initialize a tree
    tree = Tree()
    # add nodes to the tree
    tree.add("%Y-%m-%d")
    tree.add("%Y-%m-%d %H:%M:%S")
    tree.add("%Y-%m-%d %H:%M")
    tree.add("%Y-%m-%d %H:%M:%S.%f")
    # with slash instead of -
    tree.add("%Y/%m/%d")
    tree.add("%Y/%m/%d %H:%M:%S")
    tree.add("%Y/%m/%d %H:%M")
    # starting with days
    tree.add("%d-%b-%Y")
    tree.add("%d-%b-%Y %H:%M:%S")
    tree.add("%d-%m-%Y")
    tree.add("%d-%m-%Y %H:%M:%S")
    # with slash instead of -
    tree.add("%d/%b/%Y")
    tree.add("%d/%b/%Y %H:%M:%S")
    tree.add("%d/%m/%Y")
    tree.add("%d/%m/%Y %H:%M:%S")
    tsa = parse_tsa_as_date(tree.head, candidate)
    return tsa


def get_processed_qc_as_list2(pttrn_rlst):
    newest_rlst = file_operations.search_newest_in_folder(Path("./"), pttrn_rlst)
    print("Using " + newest_rlst.resolve().__str__())

    filepath_qc = newest_rlst.resolve().__str__()
    if os.path.exists(filepath_qc):
        ""==False
    else:
        raise FileNotFoundError(filepath_qc)

    return get_processed_qc_as_list(filepath_qc)


def save_to_xlsx(pttrn_rlst,path_to_outfile):
    cucc = get_processed_qc_as_list2(pttrn_rlst)
    df_qc = pandas.DataFrame(cucc)
    wb = openpyxl.Workbook()
    ws = wb.active
    for r in dataframe_to_rows(df_qc, index=False, header=True):
        try:
            ws.append(r)
        except Exception as e:
            print(e)
    today = datetime.date.today()
    wb.save(path_to_outfile % today.strftime("%d%b%Y"))
    print("Done")