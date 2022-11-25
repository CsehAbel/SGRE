import argparse
import datetime
import logging
import math

from sqlalchemy.dialects.mysql import INTEGER

import ip_utils
import secrets
import shlex
import sys

import openpyxl
import pandas
import re
import socket
import struct
from sqlalchemy import Table, Column, create_engine, MetaData, Integer, String, DateTime, Date

#setup two loggers with different file handlers
def setup_logger(name, log_file, level=logging.INFO):
    """Function setup as many loggers as you want"""

    handler = logging.FileHandler(log_file)
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger

def get_cli_args():
    parser = argparse.ArgumentParser("Unpacking Quality Check xlsx")
    parser.add_argument(
        '--qualitycheck', dest="qualitycheck", type=str, required=True,
        help="Path of QualityCheck.xlsx"
    )
    # ToDo add command line argument for excel file
    args = parser.parse_args(shlex.split(" ".join(sys.argv[1:])))
    return args


def parse_tsa_as_date(node1, candidate):
    head = node1
    tsa = datetime.datetime.max.date()
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


# class tree node
class Node:
    def __init__(self, data):
        self.data = data
        self.next = None

        def __str__(self):
            return self.data

        def __repr__(self):
            return self.data


# class tree
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
    attachment_qc = pandas.read_excel(filepath_qc, index_col=None, sheet_name="QualityCheck", dtype=str,
                                      engine='openpyxl')
    list_dict_transformed_outer = []
    list_dict_outer=[]

    for index, row in attachment_qc.iterrows():
        pattern = re.compile('^\s*([^\s]{32})\s*$') 
        try:
            result = pattern.match(row["app_id"]) if not pandas.isnull(row["app_id"]) else False
            if not result or pandas.isnull(row["app_id"]):
                # print error with index
                logging.getLogger("appid").log(level=logging.WARNING,msg="Error in row " + str(index) + ": APP ID is not an integer:" + str(row["app_id"]))
        except:
            logging.getLogger("appid").log(level=logging.ERROR,msg="Error in row " + str(index) + ": APP ID is baad:" + str(row["app_id"]))

        #check if AppName is not an empty string or empty, if empty then print error
        if not row["app_name"]:
            logging.getLogger("appname").log(level=logging.INFO,msg="Error in row " + str(index) + ": AppName is empty:" + str(row["app_name"]))

        tsa = parse(row["tsa"])
        if tsa == datetime.datetime.max.date():
            logging.getLogger("tsa").log(level=logging.INFO,msg="Error in row " + str(index) + ": TSA expiration date is not a date:" + str(row["tsa"]))

        # each field can contain multiple ips or ip ranges, separated by ; or \n
        # returns list of [start,end,cidr]
        field = row["ip"]
        list_unpacked_ips = process_ip_field_per_row(field)
        # for each element in list_unpacked_ips create a new dictinary, with [start,end,cidr] and
        # row values and tsa, and append to list_dict_transformed
        list_dict= create_dictionary_asis(list_unpacked_ips, row, tsa)
        # append list_dict to list_dict_outer
        list_dict_outer.extend(list_dict)
        # for each element in list_unpacked_ips create a new dictinary, with single ip,[start,end,cidr] and
        # row values and tsa, and append to list_dict_transformed
        #list_dict_transformed = create_dictionary(list_unpacked_ips, row, tsa)
        # append list_dict_transformed to list_dict_transformed_outer
        #list_dict_transformed_outer.extend(list_dict_transformed)

    #return list_dict_transformed_outer
    return list_dict_outer


# ToDO do an assert to count rows in the database table
def dict_to_sql(list_unpacked_ips,db_name):
    sqlEngine = create_engine(
        'mysql+pymysql://%s:%s@%s/%s' % (secrets.mysql_u, secrets.mysql_pw, "127.0.0.1", db_name),
        pool_recycle=3600)
    metadata_obj = MetaData()
    ruleset_table = drop_and_create_ruleset_table(metadata_obj, sqlEngine)

    conn = sqlEngine.connect()

    insert_to_ruleset(conn, ruleset_table, list_unpacked_ips)
    print("ruleset insert done!")


def drop_and_create_ruleset_table(metadata_obj, sql_engine):
    ruleset_table = Table('ruleset', metadata_obj,
                        Column('id', Integer, primary_key=True),
                        Column('start', String(15), nullable=False),
                        Column('end', String(15), nullable=False),
                        Column('start_int', INTEGER(unsigned=True), nullable=False),
                        Column('end_int', INTEGER(unsigned=True), nullable=False),
                        Column('cidr', Integer, nullable=False),
                        Column('fqdns', String(255), nullable=True),
                        Column('tsa', Date, nullable=True),
                        Column('app_name', String(255), nullable=True),
                        #Column('app_id', Integer, nullable=True)
                        #'(pymysql.err.DataError) (1265, "Data truncated for column \'app_id\' at row 457")'
                        Column('app_id', String(255), nullable=True)
                        )

    ruleset_table.drop(sql_engine, checkfirst=True)
    ruleset_table.create(sql_engine, checkfirst=False)
    return ruleset_table

def insert_to_ruleset(conn, table, list_unpacked_ips):
    slices = to_slices(1000, list_unpacked_ips)
    # for each slice of 1000 rows insert into the eagle table
    for s in slices:
        # try to insert the slice into the eagle table
        try:
            # check if the dictionaries in the slice have values where pandas.isnull() is True
            # if so, replace with None
            for d in s:
                for k, v in d.items():
                    if pandas.isnull(v):
                        d[k] = None
            conn.execute(table.insert().values(s))
        except Exception as e:
            logging.getLogger("insert_ruleset").log(level=logging.INFO,msg=e)


def to_slices(divisor, systems_ips):
    length = len(systems_ips)
    quotient, rest = divmod(length, divisor)
    slices = []  # [[list[0],...list[999]],]
    lower_bound = 0
    for i in range(quotient + 1):
        upper_bound = (i + 1) * divisor
        if upper_bound < length:
            slices.append(systems_ips[slice(lower_bound, upper_bound, 1)])
        else:
            slices.append(systems_ips[slice(lower_bound, length, 1)])
        lower_bound = upper_bound
    return slices

def create_dictionary(list_unpacked_ips, row, tsa):
    list_dict_transformed = []
    for i in list_unpacked_ips:
        single_ips = map_range_to_single_ip(i["start"], i["end"])
        list_dict_transformed_inner = []
        for ip in single_ips:
            # check if i["cidr"] is not type string
            if not isinstance(i["cidr"], int):
                print("cidr is not a string: " + str(i["cidr"]))
                raise TypeError

            truncate_fqdns = str(row["fqdns"])[:254] if row["fqdns"] else None
            dict_transformed = {"ip": ip,
                                "start": i["start"],
                                "end": i["end"],
                                "start_int": i["start_int"],
                                "end_int": i["end_int"],
                                "cidr": i["cidr"],
                                "fqdns": truncate_fqdns,
                                "tsa": tsa,
                                "app_name": row["app_name"],
                                "app_id": row["app_id"]
                                }
            list_dict_transformed_inner.append(dict_transformed)
        list_dict_transformed.extend(list_dict_transformed_inner)
    return list_dict_transformed

def create_dictionary_asis(list_unpacked_ips, row, tsa):
    list_dict = []
    for i in list_unpacked_ips:

        # check if i["cidr"] is not type string
        if not isinstance(i["cidr"], int):
            print("cidr is not a string: " + str(i["cidr"]))
            raise TypeError

        truncate_fqdns = str(row["fqdns"])[:254] if row["fqdns"] else None
        dict_transformed = {
                            "start": i["start"],
                            "end": i["end"],
                            "start_int": i["start_int"],
                            "end_int": i["end_int"],
                            "cidr": i["cidr"],
                            "fqdns": truncate_fqdns,
                            "tsa": tsa,
                            "app_name": row["app_name"],
                            "app_id": row["app_id"]
                            }
        list_dict.append(dict_transformed)
    return list_dict


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
        # Sicherzustellen dass nur ein Regex mit dem Text übereinstimmt
        inner_matches = {"single": False, "cidr": False, "range": False, "commaseparated": False,
                         "bindestrich": False}

        i = i.strip(u'\u200b')

        patternPrefix = re.compile('^\s*(([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}))\s*$')
        resultPrefix = patternPrefix.match(i)
        if resultPrefix:
            inner_matches["single"] = True
            prefix = resultPrefix.group(1)
            # end ip is the same as start ip
            # cidr is 32
            list_unpacked_ips.append({"start":prefix,"end":prefix,"cidr":32,
                                      "start_int":ip_utils.ip2int(prefix),"end_int":ip_utils.ip2int(prefix)})

        patternPrefixCIDR = re.compile('^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/(\d+)\s*$')
        resultPrefixCIDR = patternPrefixCIDR.match(i)
        if resultPrefixCIDR:
            inner_matches["cidr"] = True
            prefix2 = resultPrefixCIDR.group(1)
            cidr2 = ip_utils.correctAndCheckMatchedMask(resultPrefixCIDR.group(2))
            base,prefix_top=ip_utils.base_cidr_to_range(prefix2,cidr2)
            list_unpacked_ips.append({"start":base,"end":prefix_top,"cidr":cidr2,
                                      "start_int":ip_utils.ip2int(base),"end_int":ip_utils.ip2int(prefix_top)})

        patternPrefixRange = re.compile('^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.([0-9]{1,3})-(\d+)\s*$')
        resultPrefixRange = patternPrefixRange.match(i)
        if resultPrefixRange:
            inner_matches["range"] = True
            prefix3 = resultPrefixRange.group(1)
            fourthoctet3 = resultPrefixRange.group(2)
            fifthoctet3 = resultPrefixRange.group(3)

            start_ip = ".".join([prefix3, fourthoctet3])
            end_ip = ".".join([prefix3, fifthoctet3])
            list_unpacked_ips.append({"start":start_ip,"end":end_ip,"cidr":ip_utils.iprange_to_cidr(start_ip, end_ip),
                                        "start_int":ip_utils.ip2int(start_ip),"end_int":ip_utils.ip2int(end_ip)})

        patternPrefixCommaSeparated = re.compile('^\s*([1-9][0-9]{10,11})\s*$')
        resultPrefixCommaSeparated = patternPrefixCommaSeparated.match(i)
        if resultPrefixCommaSeparated:
            inner_matches["commaseparated"] = True
            ip_trsfrmd = ip_utils.correctMatchedPrefix(i)
            list_unpacked_ips.append({"start":ip_trsfrmd,"end":ip_trsfrmd,"cidr":32,
                                        "start_int":ip_utils.ip2int(ip_trsfrmd),"end_int":ip_utils.ip2int(ip_trsfrmd)})

        patternBindestrich = re.compile(
            '^\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})-([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*$')
        resultBindestrich = patternBindestrich.match(i)
        if resultBindestrich:
            inner_matches["bindestrich"] = True
            start_ip_b = resultBindestrich.group(1)
            end_ip_b = resultBindestrich.group(2)
            list_unpacked_ips.append({"start":start_ip_b,"end":end_ip_b,"cidr":ip_utils.iprange_to_cidr(start_ip_b, end_ip_b),
                                        "start_int":ip_utils.ip2int(start_ip_b),"end_int":ip_utils.ip2int(end_ip_b)})

        if not any(inner_matches.values()) and not (i.find("Same as the App") != -1) and not len(i) == 0:
            logging.getLogger("parseip").log(level=logging.INFO, msg="no regex match for element:%s IPs:%s" % (i, field))

        numberofmatches = 0
        for m in inner_matches.values():
            if m:
                numberofmatches += 1
        if numberofmatches > 1:
            print("too many regex matches")
            raise ValueError()

    return list_unpacked_ips


# used for resultBindestrich
# used for resultPrefixCIDR
# used for resultPrefixRange
# unpacks a range of ip addresses, start,end given as a string
def map_range_to_single_ip(start_ip, end_ip):
    list_unpacked_ips = []
    for j in range(ip_utils.ip2int(start_ip),
                   ip_utils.ip2int(end_ip) + 1):
        list_unpacked_ips.append(ip_utils.int2ip(j))
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


def save_to_xlsx(list_dict_transformed_outer, path_to_save):
    wb = openpyxl.Workbook()
    ws = wb.active

    fieldnames=list_dict_transformed_outer[0].keys()
    #create a generator from fieldnames
    fieldnames_gen = (field for field in fieldnames)
    ws.append(fieldnames_gen)
    for r in list_dict_transformed_outer:
        try:
            values=(r[k] for k in fieldnames)
            ws.append(values)
        except Exception as e:
            logging.getLogger("logger_excel").log(logging.ERROR, "error in save_to_xlsx: %s\n record: %s" %(e,r))
    today = datetime.date.today()
    wb.save(path_to_save % today.strftime("%d%b%Y"))
    print("Done")
