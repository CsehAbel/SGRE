#!/home/scripts/ticket_automatisierung/bin/python3
import argparse
import math
import shlex
import sys
import os
import logging
from typing import List, Union

import pandas
import re
import socket
import struct
import exceptions
import uuid
from traceback import print_exc

from pytos.common.base_types import XML_List
from pytos.common.logging.logger import setup_loggers
from pytos.common.functions.config import Secure_Config_Parser
from pytos.securechange.helpers import Secure_Change_Helper, Secure_Change_API_Handler
from pytos.securechange.xml_objects.rest import Group_Change_Member_Object,Group_Change_Node,Step_Field_Multi_Group_Change
from pytos.common.definitions.xml_tags import Attributes

from pytos.securetrack.helpers import Secure_Track_Helper

from pytos.common.logging.definitions import COMMON_LOGGER_NAME

from os import listdir
from os.path import isfile, join



def get_cli_args():
    parser = argparse.ArgumentParser("Fill Ticket in SecureChange")
    parser.add_argument("--debug", action="store_true",
                        help="Print out logging information to STDOUT.")
    parser.add_argument('--id','-i',dest="id", type=str, required=True, help = 'Id of SecureChange Task/Ticket')
    parser.add_argument('--region','-r',dest="region", type=str, required=True, choices = ["EMEA","AAE","CHINA","LATAM","NAM"], help='region of site(EMEA,AAE,CHINA,LATAM,NAM)')
    #parser.add_argument('--country','-c',dest="country", type=str, required=True, help='Country Code of SecureChange Task/Ticket')
    #parser.add_argument('--sal_code','-s', dest="sal_code",type=str, required=True, help='Pay Attention to UNDERSCORE "_" SAL Code of SecureChange Task/Ticket')
    parser.add_argument(
        '--attachment',"--xlsx","--excel", dest="attachment", type=str, required=True,
        help="Path of FMO_IP_Ranges.xlsx"
        )
    #ToDo add command line argument for excel file

    args = parser.parse_args(shlex.split(" ".join(sys.argv[1:])))
    return args

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
        raise exceptions.MaskValueError("Mask is less,equal to 16, mask is bigger,equal to 32")


def isMask(cidr):
    patternMask = re.compile('[^\d]*(\d+)[^\d]*$')
    resultMask = patternMask.match(cidr)
    if resultMask:
        return True
    else:
        return False

#überprüft den Sheet-Name, wenn es einen Treffer gibt, dann For-Schleife Unterbrechung, liefer den Sheet-Name zurück
#wenn es keinen Treffer gibt, dann schreibt einen Nachricht in dem Logger und wirft eine Ausnahme
def findSheet(attachment):
    # Choosing sheet by iterating throught a python dict
    correctSheet = ""

    sheets = []
    for key in attachment:
        sheets.append(key)
    logger2.info("Found following sheets:")
    logger2.info(", ".join(sheets))

    patternSheetname = re.compile('.*?FMO_IP.*$')
    matches = []
    for key in sheets:
        resultSheetname = patternSheetname.match(key)
        if resultSheetname:
            matches.append(True)
            correctSheet = key
            logger2.info("Sheet name %s contains 'FMO_IP', further matches ignored" % key)
        else:
            matches.append(False)
    if not any(matches):
        logger2.error("No sheet name contains 'FMO_IP'")
        raise exceptions.SheetNameError("No sheet name contains 'FMO_IP'")
    else:
        return correctSheet

def isActionMoveToRed(action):
    patternMoveToRed = re.compile('.*?(move to red).*$', re.IGNORECASE)
    resultMoveToRed = patternMoveToRed.match(action)
    if resultMoveToRed:
        return True
    else:
        return False

def isActionRemove(action):
    patternRemove = re.compile('.*?(remove).*$', re.IGNORECASE)
    resultRemove = patternRemove.match(action)

    patternDelete = re.compile('.*?(delete).*$', re.IGNORECASE)
    resultDelete = patternDelete.match(action)
    if resultRemove or resultDelete:
        return True
    else:
        return False

def isActionStayInRed(action): #isActionStayAsIs(action):
    #patternStayAsIs = re.compile('.*?(stay as is).*$', re.IGNORECASE)
    #resultStayAsIs = patternStayAsIs.match(action)
    patternStayInRed = re.compile('.*?(stay in red).*$', re.IGNORECASE)
    resultStayInRed = patternStayInRed.match(action)
    if resultStayInRed:#resultStayAsIs or resultStayInRed:
        return True
    else:
        return False

def sniccomments(base,location):
    onlyfiles = [f for f in listdir(snic_export_path) if isfile(join(snic_export_path, f))]

    for f in range(onlyfiles.__len__()):
        print("[%d] %s" %(f,onlyfiles[f]))
    n1 = int(input('Which file contains the snic comments? '))

    snic_export = pandas.read_csv(join(snic_export_path, onlyfiles[n1]), sep=';', index_col=None, encoding = "ISO-8859-1")
    comment = "no snic record"
    snic_export_filtered = snic_export[snic_export["Location"] == location]
    matches=0
    for index,row in snic_export_filtered.iterrows(): #snic_export.iterrows():
        if row["IP-net-base"]==base :
            comment = row["Comment"]
            matches=matches+1
    if matches > 1:
        logger2.info("IP-net_base: %s found %d times in the snic_dump, comment choosen for IP-net_base is %d th value" % (base, matches, matches) )
    if comment == "no snic record":
        logger2.info("IP-net_base: %s not found, comment is '%s'" %(base,comment))
    if matches < 1:
        logger2.info("IP-net_base: %s not found, # of matches: %d " %(base,matches))
    return comment

def readxlsx():
    # 1) Inorder for it to not interpret the dtypes but rather pass all the contents of it's columns as they were originally in the file before, we could set this arg to str or object so that we don't mess up our data.(one such case would be leading zeros in numbers which would be lost otherwise)
    # pd.read_excel('file_name.xlsx', dtype=str)  # (or) dtype=object
    # 2) It even supports a dict mapping wherein the keys constitute the column names and values it's respective data type to be set especially when you want to alter the dtype for a subset of all the columns.
    # Assuming data types for `a` and `b` columns to be altered
    # pd.read_excel('file_name.xlsx', dtype={'a': np.float64, 'b': np.int32})
    filepath = get_cli_args().attachment
    if os.path.exists(filepath):
        attachment = pandas.read_excel(filepath, sheet_name=None,
                                       index_col=None, engine = 'openpyxl')
    else:
        logger2.error("FileNotFoundError %s" % filepath)
        raise FileNotFoundError(filepath)

    correctSheet = findSheet(attachment)
    attachment = attachment[correctSheet]


    attachment = pandas.read_excel(filepath, sheet_name=correctSheet,
                                   index_col=None, dtype=str, engine = 'openpyxl')

    #boundary for Existing and New Ranges exists?
    boundary=False
    boundaryIndex=None
    for index, row in attachment.iterrows():
        for cell in row:
            patternNew = re.compile('.*?(NEW RANGES in RED).*$', re.IGNORECASE)
            resultNew = patternNew.match(str(cell))
            if resultNew:
                boundary=True
                boundaryIndex=index
                #wont stop at 1st match, sets index to last "NEW Ranges in RED" found

    #hack for HANDLE WITH CARE! delete ranges
    boundary2=False
    boundaryIndex2=None
    for index, row in attachment.iterrows():
        for cell in row:
            patternDelete = re.compile('.*?(RANGES to be delete).*$', re.IGNORECASE)
            resultDelete = patternDelete.match(str(cell))
            if resultDelete:
                boundary2=True
                boundaryIndex2=index
            #wont stop at 1st match, sets index to last "Ranges to be delete" found

    if not boundary:
        logger2.error('Did not Found the Boundary-Text for separating Existing_to_be_Modified_Network_Objects and New_Ranges_in_Red: "new ranges in red"')
        raise exceptions.NoBoundaryError('Did not Found the Boundary-Text for separating Existing_to_be_Modified_Network_Objects and New_Ranges_in_Red: "new ranges in red"')

    attachmentExisting = pandas.read_excel(filepath,
                                           sheet_name=correctSheet,
                                           index_col=None, dtype=str, skipfooter=attachment.index.stop - (boundaryIndex-1), engine = 'openpyxl')

    if not boundary2:
        logger2.info("Did not find the Boundary-Text for separating 'NEW RANGES in RED' and 'to be deleted from SNIC' ranges, 'ranges to be delete'")
        boundaryIndex2 = 0
    #boundaryIndex+1 because if the first row is the boundary text, then the headers wont be recognized
    #header ACTION changes to NEW RANGES in RED
    attachmentNewRanges = pandas.read_excel(filepath,
                                           sheet_name=correctSheet,
                                           index_col=None, dtype=str, skiprows=(boundaryIndex+1), skipfooter=0 if not boundary2 else (attachment.index.stop - (boundaryIndex2-1)), engine = 'openpyxl')

    attachmentRemoveRanges = pandas.read_excel(filepath,
                                           sheet_name=correctSheet,
                                           index_col=None, dtype=str, skiprows=attachment.index.stop if not boundary2 else (boundaryIndex2+1), engine = 'openpyxl')


    list_addtolist: List[List[Union[str, int]]] = []

    for index, row in attachmentExisting.iterrows():
        logger2.info(index)
        logger2.info(", ".join([str(x) for x in [row['Office/Client Range'],row['ACTION'], row['Country'], row['Location'], row['IP-net-base'], row['IP-net-top'], row['CIDR'], row['Comment']]]))

        # ha nem mindegyik megfelelo akkor meg kell szakitani a beolvasast es hiba üzenetet kiirni
        # vagy csak akkor ha "move to red" es sorban van hiba? Egyenlore igy csinalom

        prefix_base = ""
        #prefix_top = ""
        mask = ""

        #überprüf ob die Zeile leer ist, ob all die Zellen "nan" beinhalten
        filled_cells=[]
        for cell in row:
            if pandas.isnull(cell):
                filled_cells.append(False)
            else:
                filled_cells.append(True)

        # statt im Fall isMask(row['CIDR'] einen Exception zu werfen reagieren wir später auf match_dict False Wert
        # Vorgehensweise im Fall eines Optionales-Wertes, man hält es absichtlich leer

        is_office=False
        if not pandas.isnull(row['Office/Client Range']) and isOfficeClientRange(row['Office/Client Range']):
            is_office=True

        if any(filled_cells):
            logger2.info("Row is not empty, processing row")

            if pandas.isnull(row['ACTION']):
                logger2.error("No value. Please fill ACTION field")
                raise exceptions.NoActionError("Please fill value")

            action = row['ACTION']

            if isActionMoveToRed(row['ACTION']) or isActionRemove(row['ACTION']) or isActionStayInRed(row['ACTION']):
                if isActionMoveToRed(row['ACTION']):
                    action="movetored"
                    logger2.info("Row marked as 'move to red'")
                if isActionRemove(row['ACTION']):
                    action="remove"
                    logger2.info("Row marked as 'remove'")
                #ToDo 'stay as is' can mean stay in blue too? how to differentiate between the two meanings of stay as is?
                if isActionStayInRed(row['ACTION']):
                    action = "stayinred"
                    logger2.info("Row marked as 'stay in red'")
            else:
                logger2.info("ACTION is neither move to red nor remove -> row skipped")
                continue

            if pandas.isnull(row['IP-net-base']):
                logger2.error("No Ip-Base.Please fill value!")
                raise exceptions.NoIpBaseError("Please fill value!")
            if isPrefix(row['IP-net-base']):
                prefix_base = correctMatchedPrefix(row['IP-net-base'])
            else:
                logger2.error("ipNetBase format not matched")
                raise exceptions.IpFormatError("ipNetBase format not matched")

            ''' fills prefix_top with decimaldottedQuad
            if pandas.isnull(row['IP-net-top']):
                logger2.error("No Ip-Top.Please fill value!")
                raise exceptions.NoIpTopError("Please fill value!")
            if isPrefix(row['IP-net-top']):
                prefix_top = correctMatchedPrefix(row['IP-net-top'])
            else:
                logger2.error("ipNetTop format not matched")
                raise exceptions.IpFormatError("ipNetTop format not matched")
            '''

            if pandas.isnull(row['CIDR']):
                logger2.error("Program execution aborted because of missing CIDR, fill CIDR and rerun script.")
                raise exceptions.NoCIDRError("Program execution aborted because of missing CIDR, fill CIDR and rerun script.")
            if isMask(row['CIDR']):
                mask = correctAndCheckMatchedMask(row['CIDR'])
            else:
                logger2.error("Program execution aborted because of wrong CIDR, fix CIDR and rerun script.")
                raise exceptions.MaskFormatError("Program execution aborted because of wrong CIDR, fix CIDR and rerun script.")

            #if prefix_base is not the network adress
            base = integerToDecimalDottedQuad(decimalDottedQuadToInteger(prefix_base) & makeIntegerMask(mask))
            if base != prefix_base:
                logger2.error("Not a network adress (possible ip base %s)" % base)
                raise exceptions.NotNetworkAdressError("Not a network adress (possible ip base %s)" % base)

            #fakultativ - kann leer sein
            if pandas.isnull(row['Comment']):
                comment = "No details provided"
            else:
                comment = row['Comment']

            if pandas.isnull(row['Location']):
                logger2.error("Program execution aborted because of missing Location/SAL-CODE.")
                raise exceptions.NoSALCodeError(
                    "Program execution aborted because of missing Location/SAL-CODE.")

            if pandas.isnull(row['Country']):
                logger2.error("Program execution aborted because of missing Country.")
                raise exceptions.NoCountryCodeError(
                    "Program execution aborted because of missing Country.")

            #fill a list with mask,prefixbase,prefixtop,
            #set status according to matchdict['actionMove'/'actionRemove]
            region_cli = get_cli_args().region
            #ToDo
            country_cli = row['Country'] #get_cli_args().country
            sal_code_cli = "_".join(row['Location'].split(" ")) #get_cli_args().sal_code
            list_addtolist.append({"is_office":is_office,"prefix_base": prefix_base, #"prefix_top": prefix_top,
                                   "mask": mask, "action": action, "comment":comment ,
                                   "region_cli": region_cli, "country_cli": country_cli, "sal_code": sal_code_cli})
        else:
            print("Empty, skipping row")

    # header ACTION changes to NEW RANGES in RED
    for index, row in attachmentNewRanges.iterrows():
        logger2.info(index)
        logger2.info(", ".join([str(x) for x in [row['Office/Client Range'],'NEW RANGE in RED', row['Country'], row['Location'], row['IP-net-base'], row['IP-net-top'], row['CIDR'], row['Comment']]]))

        # ha nem mindegyik megfelelo akkor meg kell szakitani a beolvasast es hiba üzenetet kiirni
        # vagy csak akkor ha "move to red" es sorban van hiba? Egyenlore igy csinalom

        prefix_base = ""
        #prefix_top = ""
        mask = ""

        # überprüf ob die Zeile leer ist, ob all die Zellen "nan" beinhalten
        filled_cells = []
        for cell in row:
            if pandas.isnull(cell):
                filled_cells.append(False)
            else:
                filled_cells.append(True)

        # statt im Fall isMask(row['CIDR'] einen Exception zu werfen reagieren wir später auf match_dict False Wert
        # Vorgehensweise im Fall eines Optionales-Wertes, man hält es absichtlich leer

        is_office = False
        if not pandas.isnull(row['Office/Client Range']) and isOfficeClientRange(row['Office/Client Range']):
            is_office = True

        if any(filled_cells):
            logger2.info("Row is not empty, processing row")

            #No Action Column
            action = "new"
            logger2.info("'new' range in red")

            if pandas.isnull(row['IP-net-base']):
                logger2.error("No Ip-Base.Please fill value!")
                raise exceptions.NoIpBaseError("Please fill value!")
            if isPrefix(row['IP-net-base']):
                prefix_base = correctMatchedPrefix(row['IP-net-base'])
            else:
                logger2.error("ipNetBase format not matched")
                raise exceptions.IpFormatError("ipNetBase format not matched")

            ''' fills prefix_top with decimaldottedQuad
            if pandas.isnull(row['IP-net-top']):
                logger2.error("No Ip-Top.Please fill value!")
                raise exceptions.NoIpTopError("Please fill value!")
            if isPrefix(row['IP-net-top']):
                prefix_top = correctMatchedPrefix(row['IP-net-top'])
            else:
                logger2.error("ipNetTop format not matched")
                raise exceptions.IpFormatError("ipNetTop format not matched")
            '''

            if pandas.isnull(row['CIDR']):
                logger2.error("Program execution aborted because of missing CIDR, fill CIDR and rerun script.")
                raise exceptions.NoCIDRError(
                    "Program execution aborted because of missing CIDR, fill CIDR and rerun script.")
            if isMask(row['CIDR']):
                mask = correctAndCheckMatchedMask(row['CIDR'])
            else:
                logger2.error("Program execution aborted because of wrong CIDR, fix CIDR and rerun script.")
                raise exceptions.MaskFormatError(
                    "Program execution aborted because of wrong CIDR, fix CIDR and rerun script.")

            # if prefix_base is not the network adress
            base = integerToDecimalDottedQuad(decimalDottedQuadToInteger(prefix_base) & makeIntegerMask(mask))
            if base != prefix_base:
                logger2.error("Not a network adress (possible ip base %s)" % base)
                raise exceptions.NotNetworkAdressError("Not a network adress (possible ip base %s)" % base)

            comment = sniccomments(base, row['Location'])
            '''if comment== "no snic record":
                if pandas.isnull(row['NEW RANGES in RED']):
                    comment = "No details provided"
                else:
                    comment = row['NEW RANGES in RED']
                    logger2.info("Comment for IP-net-base: %s taken from the excel column 'NEW RANGES in RED'" %base)
            '''

            if pandas.isnull(row['Location']):
                logger2.error("Program execution aborted because of missing Location/SAL-CODE.")
                raise exceptions.NoSALCodeError(
                    "Program execution aborted because of missing Location/SAL-CODE.")

            if pandas.isnull(row['Country']):
                logger2.error("Program execution aborted because of missing Country.")
                raise exceptions.NoCountryCodeError(
                    "Program execution aborted because of missing Country.")

            # fill a list with mask,prefixbase,prefixtop,
            # set status according to matchdict['actionMove'/'actionRemove]
            region_cli = get_cli_args().region
            country_cli = row['Country'] #get_cli_args().country
            sal_code_cli = "_".join(row['Location'].split(" ")) #get_cli_args().sal_code
            list_addtolist.append({"is_office": is_office, "prefix_base": prefix_base, #"prefix_top": prefix_top,
                                   "mask": mask, "action": action, "comment": comment,
                                   "region_cli": region_cli, "country_cli": country_cli, "sal_code": sal_code_cli})
        else:
            logger2.info("Empty, skipping row")

    for index, row in attachmentRemoveRanges.iterrows():
        logger2.info(index)
        logger2.info(", ".join([str(x) for x in ["delete",row['Country'], row['Location'], row['IP-net-base'], row['CIDR'],row['Comment']]]))

        # ha nem mindegyik megfelelo akkor meg kell szakitani a beolvasast es hiba üzenetet kiirni
        # vagy csak akkor ha "move to red" es sorban van hiba? Egyenlore igy csinalom

        prefix_base = ""
        #prefix_top = ""
        mask = ""

        #überprüf ob die Zeile leer ist, ob all die Zellen "nan" beinhalten
        filled_cells=[]
        cells=[row['Country'], row['Location'], row['IP-net-base'], row['CIDR'],row['Comment']]
        for number in range(0,cells.__len__()):
            if pandas.isnull(cells[number]):
                filled_cells.append(False)
            else:
                filled_cells.append(True)

        # statt im Fall isMask(row['CIDR'] einen Exception zu werfen reagieren wir später auf match_dict False Wert
        # Vorgehensweise im Fall eines Optionales-Wertes, man hält es absichtlich leer

        if any(filled_cells):
            logger2.info("Row is not empty, processing row")

            action="remove"
            logger2.info("Row marked as 'remove'")

            if pandas.isnull(row['IP-net-base']):
                logger2.error("No Ip-Base.Please fill value!")
                raise exceptions.NoIpBaseError("Please fill value!")
            if isPrefix(row['IP-net-base']):
                prefix_base = correctMatchedPrefix(row['IP-net-base'])
            else:
                logger2.error("ipNetBase format not matched")
                raise exceptions.IpFormatError("ipNetBase format not matched")

            ''' fills prefix_top with decimaldottedQuad
            if pandas.isnull(row['IP-net-top']):
                logger2.error("No Ip-Top.Please fill value!")
                raise exceptions.NoIpTopError("Please fill value!")
            if isPrefix(row['IP-net-top']):
                prefix_top = correctMatchedPrefix(row['IP-net-top'])
            else:
                logger2.error("ipNetTop format not matched")
                raise exceptions.IpFormatError("ipNetTop format not matched")
            '''

            if pandas.isnull(row['CIDR']):
                logger2.error("Program execution aborted because of missing CIDR, fill CIDR and rerun script.")
                raise exceptions.NoCIDRError(
                    "Program execution aborted because of missing CIDR, fill CIDR and rerun script.")
            if isMask(row['CIDR']):
                mask = correctAndCheckMatchedMask(row['CIDR'])
            else:
                logger2.error("Program execution aborted because of wrong CIDR, fix CIDR and rerun script.")
                raise exceptions.MaskFormatError(
                    "Program execution aborted because of wrong CIDR, fix CIDR and rerun script.")

            # if prefix_base is not the network adress
            base = integerToDecimalDottedQuad(decimalDottedQuadToInteger(prefix_base) & makeIntegerMask(mask))
            if base != prefix_base:
                logger2.error("Not a network adress (possible ip base %s)" % base)
                raise exceptions.NotNetworkAdressError("Not a network adress (possible ip base %s)" % base)

            #fakultativ - kann leer sein
            if pandas.isnull(row['Comment']):
                comment = "No details provided"
            else:
                comment = row['Comment']

            if pandas.isnull(row['Location']):
                logger2.error("Program execution aborted because of missing Location/SAL-CODE.")
                raise exceptions.NoSALCodeError(
                    "Program execution aborted because of missing Location/SAL-CODE.")

            if pandas.isnull(row['Country']):
                logger2.error("Program execution aborted because of missing Country.")
                raise exceptions.NoCountryCodeError(
                    "Program execution aborted because of missing Country.")

            #fill a list with mask,prefixbase,prefixtop,
            #set status according to matchdict['actionMove'/'actionRemove]
            region_cli = get_cli_args().region
            country_cli = row['Country'] #get_cli_args().country
            sal_code_cli = "_".join(row['Location'].split(" ")) #get_cli_args().sal_code
            list_addtolist.append({"is_office":is_office,"prefix_base": prefix_base, #"prefix_top": prefix_top,
                                   "mask": mask, "action": action, "comment":comment ,
                                   "region_cli": region_cli, "country_cli": country_cli, "sal_code": sal_code_cli})
        else:
            logger2.info("Empty, skipping row")

    return list_addtolist

def find_migrated_SNX_groups(OfficeOrSystems,OfficeNetworkObjects,SystemsNetworkObjects,domainid,groupName):
    if OfficeOrSystems=="Office":
        groupOfficeSearch = st_helper.get_network_objects_group_by_member_object_id(
            OfficeNetworkObjects.network_objects[0].id, domainid)

        for group in groupOfficeSearch.network_objects:
            if group.__class__.__name__ == "Group_Network_Object" and group.name == groupName:
                groupOfficeSearchResult = group
                return groupOfficeSearchResult
        raise ValueError("no returned search result")
    elif OfficeOrSystems=="Systems":
        groupSystemsSearch = st_helper.get_network_objects_group_by_member_object_id(
            SystemsNetworkObjects.network_objects[0].id, domainid)

        for group in groupSystemsSearch.network_objects:
            if group.__class__.__name__ == "Group_Network_Object" and group.name == groupName:
                groupSystemsSearchResult = group
                return groupSystemsSearchResult
        raise ValueError("no returned search result")
    else:
        raise ValueError("parameter to choose the group based on which REGION_migrated_SNX_Office/Systems will be instantiated doesnt match neither 'Office' nor 'Systems' ")

def main(list_readxlsx):
    cli_args = get_cli_args()

    id_cli = get_cli_args().id
    region_cli = get_cli_args().region
    #country_cli = get_cli_args().country
    #sal_code_cli = get_cli_args().sal_code

    ticket=sc_helper.get_ticket_by_id(id_cli)
    if ticket.domain_name!='Siemens-Energy-CO':
        logger2.error("ticket's domain name is not Siemens-Energy-CO")
        raise ValueError("ticket's domain name is not Siemens-Energy-CO")
    if ticket.status!="In Progress":
        logger2.error("ticket's status is not 'In Progress'")
        raise ValueError("ticket's status is not 'In Progress'")

    #iterate through inside Step_Task.fields Step_Field_Multi_Group_Change.name="Add Networks to be migrated"
    ticket_step=ticket.get_step_by_name("Site Migration Design")
    step_task=ticket_step.get_task_by_index(0)

    if not step_task.is_assigned:
        logger2.error("Ticket is not assigned or ticket is waiting to be assigned")
        raise ValueError("Ticket is not assigned or ticket is waiting to be assigned")

    field = step_task.get_field_list_by_type(Attributes.FIELD_TYPE_MULTI_GROUP_CHANGE)[0]

    device_name="CST-P-SAG-Energy"
    deviceid = st_helper.get_device_id_by_name(device_name)

    #get_network_objects_for_device
    #add group[0] Systems, group[1] Office to field + 'Added'/'Removed' -> put_field(field)
    domains = st_helper.get_domains()
    domainfound=False
    for domain in domains:
        if domain.name=="Siemens-Energy-CO":
            domainfound=True
            domainid=domain.id

    OfficeNetworkObjects = st_helper.get_network_objects_for_device(deviceid, "group",
                                                           {"name": "%s_migrated_SNX_Office" % region_cli})
    SystemsNetworkObjects = st_helper.get_network_objects_for_device(deviceid, "group",
                                                           {"name": "%s_migrated_SNX_Systems" % region_cli})

    group_migrated_SNX_Office = find_migrated_SNX_groups("Office",OfficeNetworkObjects,
                                                       SystemsNetworkObjects,domainid,"%s_migrated_SNX_Office" % region_cli)

    group_migrated_SNX_Systems = find_migrated_SNX_groups("Systems", OfficeNetworkObjects,
                                                         SystemsNetworkObjects,domainid,"%s_migrated_SNX_Systems" % region_cli)


    GrpChgNode_Systems = Group_Change_Node(group_migrated_SNX_Systems.name, device_name, [], "NOT_SUPPORTED", "1","UPDATE")
    GrpChgNode_Systems.set_parent_node(field)

    GrpChgNode_Office = Group_Change_Node(group_migrated_SNX_Office.name, device_name, [], "NOT_SUPPORTED", "1","UPDATE")
    GrpChgNode_Office.set_parent_node(field)

    #ToDo use parameter list_readxlsx to add to the List of SecureTrack Objects
    #ToDo first create GrpChgMemberObjects, modifying "to be removed" along the way, then add "new","movetored","stayasis"
    #ToDo _attribs = {'type': 'Object'} instead 'Network' or 'Host', uid will be same as name maybe {} necessary


    list_Office_GrpChgMemberObject_From_Subnet_Netw_Obj = \
        GrpChgMemberObject_From_Subnet_Netw_Obj(OfficeNetworkObjects,True, device_name, list_readxlsx)

    # creating GrpChgMemberObject from SecureTrack Objects
    list_Systems_GrpChgMemberObject_From_Subnet_Netw_Obj = \
        GrpChgMemberObject_From_Subnet_Netw_Obj(SystemsNetworkObjects, False, device_name, list_readxlsx)


    #ToDo create Group_Change_Node for Office

    # Recognize number of already added group change nodes
    # be able to use existing added group change nodes to add network object to
    # for now it will try to add the two new groups and only add network objects     to the new groups

    #ToDo members to be filled with list_GrpChgMemb......, check members attributes
    # _xml_tag = 'members' to GrpChgNode.members, first parameter above has set it already
    #ToDo Office and Systems need to be separated from list_GrpChgMemb to be added to 2 different Group_Change_Node-s

    #ToDo members to be filled with list_GrpChgMemb......, check members attributes
    # _xml_tag = 'members' to GrpChgNode.members, first parameter has set it already
    GrpChgNode_Systems.members = XML_List('members',list_Systems_GrpChgMemberObject_From_Subnet_Netw_Obj)
    GrpChgNode_Office.members = XML_List('members',list_Office_GrpChgMemberObject_From_Subnet_Netw_Obj)
    #ToDo search for newly added ip range in ticket or field, check id - Skip adding the id
    #ToDo chechk for duplicate ip network adress, mask before adding,ask Andre, Paulo!

    #ToDo GrpChgNode should be added to field, should it check for whether it is already added
    #ToDo whether Region_migrated_SNX_Office/Systems is already added, if yes, then select those GrpChgNode
    #ToDo to be added as _parent_node to the members._list_data elements
    field.group_changes.append(GrpChgNode_Systems)
    field.group_changes.append(GrpChgNode_Office)
    #ToDo check field object name for field Add  Networks to be migrated
    sc_helper.put_field(field)
    logger2.info("Ticket filled with the Systems, Office lists")
    logger2.info("Ticket filled with the Systems, Office lists")
    #st_helper.get_member_network_objects_for_group_network_object
    #Create group change node and member list from groupSystems,groupOffice

    #Registered steps
    #try blockba beletenni, except Exception
    #ticketids = sc_helper.get_ticket_ids_by_status("In Progress")
    #ticket_handler = Secure_Change_API_Handler(ticket)
    #ticket_handler.register_step(dst_step_name, copy_field, ticket)
    #ticket_handler.run()

def GrpChgMemberObject_From_Subnet_Netw_Obj(Subnet_Netw_Obj,is_office,device_name,list_readxlsx):
    # AllNetworkObjects = st_helper.get_network_objects_for_device(deviceid)
    # setting id for new network object = get highest id from AllNetworkObjects + 1
    '''maxId_Subnet_Netw_Obj=0
    for obj in AllNetworkObjects.network_objects:
        if obj.id > maxId_Subnet_Netw_Obj:
            maxId_Subnet_Netw_Obj=obj.id
    '''
    # increment = 0 not needed
    #ToDo "to be remove" Zeilen bei der Erstellung von grpchgmemberobejct-e anzupassen(status auf DELETED zu ändern)
    list_GrpChgMemberObject_From_Subnet_Netw_Obj = []
    list_Conflicts = []
    for obj in Subnet_Netw_Obj.network_objects:
        if obj.__class__.__name__ == "Subnet_Network_Object":
            # increment = increment + 1 not needed
            # Group_Change_Member_Object(..,attr_type,...)
            # ‘If the subnet or host object already exists on the firewall, use “Object” for @type, but if it’s new (needs to be created in addition to adding to the group) then use “NETWORK” or “HOST” for the @type field.’
            #ToDo compare GrpChgMemberObj id with ticketExample OR check which obj would
            # we find if we take an id from ticketExample and compare it with
            # the result from st_helper.get_network_object_by_device_and_object_id
            # check uid
            base = integerToDecimalDottedQuad(decimalDottedQuadToInteger(obj.ip) & makeIntegerMask(netmask_to_cidr(obj.netmask)))
            if base != obj.ip:
                logger2.info("Existing SecureTrack Obj ip is not a network adress (possible ip base %s)" % base)
                #raise exceptions.NotNetworkAdressError("Existing SecureTrack Obj ip is not a network adress (possible ip base %s)" % base)

            #Durchlaufen von readxlsx, um eine Zeile zu finden, die mit dem obj.ip übereinstimmt und "remove" ist.
            isResult=False
            for dicti  in list_readxlsx:
                if dicti["action"]=="remove"  and dicti["prefix_base"]==obj.ip:
                    if netmask_to_cidr(obj.netmask)!=dicti["mask"]:
                        #ToDo ask team whether it should be a warning or an error
                        logger2.info("prefix_base to be removed:%s matches existing object but "
                              "net mask of 'to be removed' range %s is not equal "
                              "to net mask of existing object %s(%s)" %(obj.ip,dicti["mask"],netmask_to_cidr(obj.netmask),obj.netmask))
                    if dicti["is_office"]!=is_office:
                        #ToDo complete Exception message
                        logger2.info("The row %s which is 'to be deleted' is marked as '%s' range"
                                                               "in the excel, yet it is part of %s" %(dicti["prefix_base"],"Office" if dicti["is_office"] else "Systems", "Office" if is_office else "Systems"))
                    isResult=True

            #Durchlaufen von readxlsx, um von readxlsx nur die Zeilen hinzuzufügen, die sich noch nicht im SecureTrack
            #befinden
            #Wenn es ein Konflikt gibt, das sollte nicht als Ausnahme/Fehler behandelt werden, weil
            #wenn wir ein 'stayinred' Band überprüfen, dann ist es schon zu erwarten, das es schon im SecureTrack drin ist.

            for dicti in list_readxlsx:
                if dicti["prefix_base"] == obj.ip and (dicti["action"] == "new" or dicti["action"] == "movetored" or\
                        dicti["action"] == "stayinred"):
                    if netmask_to_cidr(obj.netmask) != dicti["mask"]:
                        #ToDo ask team whether it should be a warning or an error
                        logger2.info("prefix_base to be added:%s matches existing object but "
                              "net mask of '%s' range %s is not equal "
                              "to net mask of existing object %s(%s)" % (obj.ip, dicti["action"], dicti["mask"],netmask_to_cidr(obj.netmask) ,obj.netmask))
                    #Es bedeutet, dass es ein 'stayinred','movetored','new' in der Excel gibt,
                    # dessen Maske ist nicht das Gleiche wie im SecureTrack.
                    #Soll COFW darüber informiert werden, dass 'movetored' und 'new´ schon im SecureTrack vorhanden ist?
                    if dicti["is_office"] != is_office:
                        #ToDo complete Exception message
                        logger2.info("The prefix %s which is '%s' , is already in SecureTrack part of %s, but it is marked as '%s' range"
                                                               "in the excel" %(dicti["prefix_base"],dicti["action"],"Office" if is_office else "Systems","Office" if dicti["is_office"] else "Systems"))
                    list_Conflicts.append(dicti)
                    logger2.info("Range from the Excel %s %s already added to %s, existing range in SecureTrack %s (%s)%s" %(dicti["prefix_base"],dicti["mask"],
                                                                                "Office" if is_office else "Systems",obj.ip,netmask_to_cidr(obj.netmask),obj.netmask))

            status = 'NOT_CHANGED'
            if isResult:
                status = "DELETED"

            #ToDo check if obj.netmask is in decimaldottedquad format is
            gcmo1 = Group_Change_Member_Object(obj.name, obj.id,
                                                          "Network", "%s/%s" % (obj.ip, obj.netmask), device_name, 1,
                                                          status,
                                                          obj.comment, "Object", obj.uid, "EXISTING_NOT_EDITED")
            gcmo1.set_parent_node(Subnet_Netw_Obj)
            list_GrpChgMemberObject_From_Subnet_Netw_Obj.append(gcmo1)

    #ToDo add nach dem Sammeln der Konflikten, die Einträge die nicht in der Konflikt-Liste drin sind
    # readxlsx durchlaufen und die "new","movetored","stayasis" Einträge
    # als grpchgmemberobj zu list_GrpChgMemberObject_From_Subnet_Netw_Obj hinzufügen
    for dicti in list_readxlsx:
        if dicti not in list_Conflicts and (dicti["action"] == "new" or dicti["action"] == "movetored" or \
                                               dicti["action"] == "stayinred"):
            name = "%s_%s_%s_%s_%s" % (
            dicti["region_cli"], dicti["country_cli"], dicti["sal_code"], dicti["prefix_base"], dicti["mask"])
            gcmo2 = \
                Group_Change_Member_Object(name, None, 'Network',
                                           "%s/%s" % (dicti["prefix_base"], cidr_to_netmask(dicti["mask"])),
                                           device_name, 1, 'ADDED', dicti["comment"], "NETWORK", name, "NEW")


            if is_office == True :
                #Wenn Zeile in readxlsx als Office markiert ist,
                # und Systems Subnet_Network_Object-e sind gerade von SecureTrack abgefragt
                if dicti["is_office"] == True:
                    list_GrpChgMemberObject_From_Subnet_Netw_Obj.append(gcmo2)
                #elif dicti["is_office"]==False <-solche Zeilen werden in diesem Fall nicht der Office Gruppe hinzugefügt
            elif is_office == False:
                if dicti["is_office"] == False:
                    list_GrpChgMemberObject_From_Subnet_Netw_Obj.append(gcmo2)

    return list_GrpChgMemberObject_From_Subnet_Netw_Obj

if __name__ == '__main__':
    log_file_path = "/home/scripts/"
    log_file_name = "pytos_logger.log"
    log_file2 = '/home/scripts/readxlsx.log'
    config_file_path = "/home/scripts/pythonProject1/pytos.conf"
    snic_export_path = "/home/scripts/snic/"

    sc_helper = Secure_Change_Helper("cofw.siemens.com", ("abel.kecse.ext@siemens.com", "snackFacedown2019!"))
    st_helper = Secure_Track_Helper("cofw-track.siemens.com", ("COOB-SiAT_Kecse", "n7chHHaPzDAP?R=8"))

    logger = logging.getLogger(COMMON_LOGGER_NAME)
    conf = Secure_Config_Parser(config_file_path=config_file_path)
    setup_loggers(conf.dict("log_levels"), log_file_path, log_file_name, log_to_stdout=True)  # cli_args.debug)

    logger2 = logging.getLogger(__name__)
    logger2.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s:%(name)s:%(message)s')
    file_handler = logging.FileHandler(log_file2)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger2.addHandler(file_handler)
    logger2.addHandler(stream_handler)

    logger2.info("Script called.")

    list_addtoList = readxlsx()
    main(list_addtoList)
    #ToDo pass readxlsx to main()
    #ToDo use the attachment from previous field
    #ToDo add uuid as subject, {"type":"NETWORK"}