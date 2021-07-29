import argparse
import datetime
import math
import shlex
import sys
import os
import logging
from typing import List, Union
import json

import openpyxl
from openpyxl.utils.dataframe import dataframe_to_rows
import pandas
import re
import socket
import struct
import uuid
from traceback import print_exc
from openpyxl.styles import Alignment

import ticket_automatisierung

def get_cli_args():
    parser = argparse.ArgumentParser("Collecting details for CYS Report")
    parser.add_argument(
        '--sgre', dest="sgre", type=str, required=True,
        help="Path of SC-Report_CYS.xlsx"
        )
    parser.add_argument(
        '--qualitycheck', dest="qualitycheck", type=str, required=True,
        help="Path of SC-Report_CYS.xlsx"
    )
    #ToDo add command line argument for excel file
    args = parser.parse_args(shlex.split(" ".join(sys.argv[1:])))
    return args

#Sicherzustellen dass nur ein Regex stimmt mit dem Text überein
def test_matches(attachment):


    for index, row in attachment.iterrows():


        dict_raw_field = {"app_id": [], "tufin_id": row["Tufin ID"], "ips_field": row["Ips"]}
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
                ip_trsfrmd=ticket_automatisierung.correctMatchedPrefix(i)
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
        dict_raw_field = {"app_id": row["APP ID"], "tufin_id": row["Tufin ID"], "ips_field": row["Ips"]}
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
                cidr2 = ticket_automatisierung.correctAndCheckMatchedMask(resultPrefixCIDR.group(2))

                base = ticket_automatisierung.integerToDecimalDottedQuad(
                    ticket_automatisierung.decimalDottedQuadToInteger(prefix2) & ticket_automatisierung.makeIntegerMask(
                        cidr2))
                if base != prefix2:
                    print("Not a network Adresse (possible ip base %s)" % base)

                int_prefix_top = (~ticket_automatisierung.makeIntegerMask(
                    cidr2)) | ticket_automatisierung.decimalDottedQuadToInteger(prefix2)
                if int_prefix_top - 2 * 32 == -4117887025:
                    print("Test singed to unsigned conversion")
                    # ToDo breakpoint setzen, Werte die die for Schleife ausspuckt mit den erwarteten Ergebnisse zu vergleichen
                    # Modified
                    #    ticket_automatisierung.decimalDottedQuadToInteger()
                    # to convert signed integers to unsigned.
                    # Das Folgende ist redundant, überreichlich, ersetzt:
                    #   int_prefix_top == -4117887025:
                    #   if int_prefix_top < 0:
                    #      int_prefix_top = int_prefix_top + (2**32)

                prefix_top = ticket_automatisierung.integerToDecimalDottedQuad(int_prefix_top)
                print("netw.adrr.:{}".format(base))
                for j in range(ticket_automatisierung.decimalDottedQuadToInteger(base) + 1,
                               ticket_automatisierung.decimalDottedQuadToInteger(
                                       ticket_automatisierung.integerToDecimalDottedQuad(int_prefix_top)) + 1):
                    list_unpacked_ips.append(ticket_automatisierung.integerToDecimalDottedQuad(j))

            patternPrefixRange = re.compile('^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.([0-9]{1,3})-(\d+)\s*$')
            resultPrefixRange = patternPrefixRange.match(i)
            if resultPrefixRange:
                prefix3 = resultPrefixRange.group(1)
                fourthoctet3 = resultPrefixRange.group(2)
                fifthoctet3 = resultPrefixRange.group(3)

                start_ip = ".".join([prefix3, fourthoctet3])
                end_ip = ".".join([prefix3, fifthoctet3])
                for j in range(ticket_automatisierung.decimalDottedQuadToInteger(start_ip) + 1,
                               ticket_automatisierung.decimalDottedQuadToInteger(end_ip) + 1):
                    list_unpacked_ips.append(ticket_automatisierung.integerToDecimalDottedQuad(j))

            patternPrefixCommaSeparated = re.compile('^\s*([1-9][0-9]{10,11})\s*$')
            resultPrefixCommaSeparated = patternPrefixCommaSeparated.match(i)
            if resultPrefixCommaSeparated:
                ip_trsfrmd = ticket_automatisierung.correctMatchedPrefix(i)
                list_unpacked_ips.append(ip_trsfrmd)

            patternBindestrich = re.compile(
                '^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})-([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*$')
            resultBindestrich = patternBindestrich.match(i)
            if resultBindestrich:
                start_ip_b = resultBindestrich.group(1)
                end_ip_b = resultBindestrich.group(2)
                for j in range(ticket_automatisierung.decimalDottedQuadToInteger(start_ip_b),
                               ticket_automatisierung.decimalDottedQuadToInteger(start_ip_b) + 1):
                    list_unpacked_ips.append(ticket_automatisierung.integerToDecimalDottedQuad(j))

        for element in list_unpacked_ips:
            list_dict_transformed.append(
                {"app_id": dict_raw_field["app_id"], "tufin_id": dict_raw_field["tufin_id"], "ip": element, "excel_row_line": (index + 2)})

    return list_dict_transformed

'''def get_processed_sgre_as_list(attachment_sgre):
    
    list_dict = []
    for index, row in attachment_sgre.iterrows():
        #find \t([^\t]+)\t
        #replace "\)row\("\1"\), row\("
'''

def write_duplicates_to_xlsx(df_qc):
    list_duplicated = []
    dplctd = df_qc.index.duplicated(keep='first')
    for i in range(len(dplctd)):
        if dplctd[i]:
            list_duplicated.append({"ignored": "ignored", "unpacked_ip": df_qc.iloc[[i]].index[0],
                                    "excel_row_line": df_qc.iloc[[i]].excel_row_line.values[0]})

    df_duplicates = pandas.DataFrame(list_duplicated)

    wb = openpyxl.Workbook()
    ws = wb.active

    for r in dataframe_to_rows(df_duplicates, index=True, header=True):
        ws.append(r)

    today = datetime.date.today()
    path_to_outfile = "./QualityCheck_duplicates_" + today.strftime("%d%b%Y") + ".xlsx"
    wb.save(path_to_outfile)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    filepath_qc = get_cli_args().qualitycheck
    if os.path.exists(filepath_qc):
        sgre = pandas.read_excel(filepath_qc, sheet_name=None,
                                 index_col=None, engine='openpyxl')
    else:
        raise FileNotFoundError(filepath_qc)

    attachment_qc = pandas.read_excel(filepath_qc, index_col=None, dtype=str, engine='openpyxl')
    
    df_qc = pandas.DataFrame(get_processed_qc_as_list(attachment_qc))
    #ToDo df_qc.iloc[[i]] gibt die Reihe zurück wie bekommt man die einzelne Felder z.B. ip,excel_row_line,app_id_tufin_id
    df_qc.set_index('ip', inplace=True)#, verify_integrity=True)

    write_duplicates_to_xlsx(df_qc)

    #df_qc.drop_duplicates("ip",inplace=True)

    filepath_sgre = get_cli_args().sgre
    if os.path.exists(filepath_sgre):
        sgre = pandas.read_excel(filepath_sgre, sheet_name=None,
                                 index_col=None, engine='openpyxl')
    else:
        raise FileNotFoundError(filepath_sgre)

    attachment_sgre = pandas.read_excel(filepath_sgre, index_col=None, dtype=str, engine='openpyxl')
    attachment_sgre.set_index('ip',verify_integrity=True,inplace=True)

    df_joined=attachment_sgre.join(df_qc,lsuffix='_caller', rsuffix='_other')
    df_grouped = df_joined.groupby(by=df_joined.index)
    list_to_df=[]
    for name,group in df_grouped:
        app_ids="no match"
        app_ids = ",".join([g for g in group.app_id.values if not pandas.isnull(g)])
        tufin_ids = "no match"
        tufin_ids = ",".join([h for h in group.tufin_id.values if not pandas.isnull(h)])
        excel_row_lines = "no match"
        excel_row_lines = ",".join([("%g" %j) for j in group.excel_row_line.values if not pandas.isnull(j)])
        #find ,([^,]+),
        #replace [0],group.\1[0],group.
        #omit group.wuser[0],group.APP ID[0]
        first_values_from_group=[group.dns[0],group.c[0],group.l[0],group.sys_type[0],group.corpflag[0],group.info_extra[0],group["info"].values[0],group.mac[0],group.macprovider[0],group.hostname[0],group.domain[0],group.host_dn[0],group.managedby[0],group.managedbygid[0],group.managed_by_mail[0],group.os[0],group.description[0],group.region[0],group.last_modified[0],group.owner[0],group.snic_comment[0],group.ip_cidr[0]]
        first_values_from_group.insert(0,excel_row_lines)
        first_values_from_group.insert(0,tufin_ids)
        first_values_from_group.insert(0,app_ids)
        first_values_from_group.insert(0,name)
        list_to_df.append(first_values_from_group)
    column_list = ["ip","app_ids","tufin_ids","excel_row_lines", "dns", "c", "l", "sys_type", "corpflag", "info_extra", "info", "mac", "macprovider",
                   "hostname", "domain", "host_dn", "managedby", "managedbygid", "managed_by_mail", "os", "description",
                   "region", "last_modified", "owner", "snic_comment", "ip_cidr"]

    #packing the app_ids inside a field

    packed_group_df = pandas.DataFrame(data=list_to_df,columns=column_list)

    wb = openpyxl.Workbook()
    ws = wb.active

    for r in dataframe_to_rows(packed_group_df, index=True, header=True):
        ws.append(r)

    today = datetime.date.today()
    path_to_outfile = "./QualityCh_SGRE_b_targets_joined" + today.strftime("%d%b%Y") + ".xlsx"
    wb.save(path_to_outfile)

    print("Done")