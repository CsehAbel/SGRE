import datetime

import mysql.connector
from mysql.connector import errorcode
from os import listdir
from os.path import isfile, join
from mysql.connector.constants import ClientFlag
import secrets


def usedb(cursor,DB_NAME):
  try:
    cursor.execute("USE {}".format(DB_NAME))
  except mysql.connector.Error as err:
    print("Database {} does not exists.".format(DB_NAME))
    if err.errno == errorcode.ER_BAD_DB_ERROR:
      print(err)
      exit(1)
    else:
      print(err)
      exit(1)

def get_row_count(db_name,table):
    config = {
        'user': secrets.mysql_u,
        'password': secrets.mysql_pw,
        'host': '127.0.0.1',
        'database': db_name,
        'raise_on_warnings': True,
        'allow_local_infile': True
    }

    cnx = mysql.connector.connect(**config)
    cursor = cnx.cursor()

    usedb(cursor,db_name)

    #store "count_rows" in a variable
    count_rows = "SELECT COUNT(*) FROM "+table+";"
    rows=0
    #try to execute the query, return the number of rows in darwin_white_apps table
    try:
        cursor.execute(count_rows)
        #store the result in a variable containing an integer
        rows = cursor.fetchone()[0]
    except mysql.connector.Error as err:
        print(err.msg)
    else:
        #print the number of rows in table
        print("Table {} has {} rows.".format(table,rows))


    cnx.commit()
    cursor.close()
    cnx.close()

    return rows