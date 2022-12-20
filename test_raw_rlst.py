import logging
import re
from pathlib import Path
from unittest import TestCase

import file_operations_raw_rlst
import sql_statements
import unpack_raw_rlst


class TestMain(TestCase):
    db_name = "DARWIN_DB"

    # remove raw QualityCheck
    
    def test_remove_raw(self):
        pttrn = re.compile("^QualityCheck.+\.xlsx$")
        file_operations_raw_rlst.remove_files_in_dir(pttrn=pttrn, dir="files")
    
    # remove unpacked QualityCheck
    def test_remove_unpacked(self):
        pttrn = re.compile("^darwin_whitelist_unpacked_.+\.xlsx$")
        file_operations_raw_rlst.remove_files_in_dir(pttrn=pttrn, dir="files")

    def test_copy_raw_to_local_dir(self):
        dir=Path("/mnt/c/UserData/z004a6nh/Documents/OneDrive - Siemens AG/Darwin/")
        pttrn = re.compile("^QualityCheck.+\.xlsx$")
        file_operations_raw_rlst.copy_raw_to_local_dir(dir=dir, pttrn=pttrn, dst=Path("files"))

    def test_save_to_xlsx(self):
        logger_insert_ruleset = unpack_raw_rlst.setup_logger(name="insert_ruleset", log_file="logs/insert_ruleset.log",
                                                             level=logging.ERROR)
        logger_excel = unpack_raw_rlst.setup_logger(name="logger_excel", log_file="logs/save_to_xlsx.log",
                                                    level=logging.ERROR)
        logger_appid= unpack_raw_rlst.setup_logger(name="appid", log_file="logs/appid.log",level=logging.ERROR)
        logger_appname = unpack_raw_rlst.setup_logger(name="appname", log_file="logs/appname.log",level=logging.ERROR)
        logger_parseip = unpack_raw_rlst.setup_logger(name="parseip", log_file="logs/parseip.log",level=logging.ERROR)
        logger_tsa = unpack_raw_rlst.setup_logger(name="tsa", log_file="logs/tsa.log",level=logging.ERROR)
        path_to_save = "./darwin_whitelist_unpacked_%s.xlsx"
        pttrn_rlst = re.compile("^QualityCheck.+\.xlsx$")
        filepath_qc = file_operations_raw_rlst.search_newest_in_folder(dir=Path("./"), pttrn=pttrn_rlst)
        print("Using " + filepath_qc.resolve().__str__())
        list_dict_transformed_outer = unpack_raw_rlst.get_processed_qc_as_list(filepath_qc=filepath_qc)
        unpack_raw_rlst.save_to_xlsx(list_dict_transformed_outer=list_dict_transformed_outer, path_to_save=path_to_save)
        # assert that logs/save_to_xlsx.log is empty
        self.assertTrue(Path("logs/save_to_xlsx.log").stat().st_size == 0)

    # remove raw QualityCheck
    def test_save_to_sql(self):
        pttrn_logs = re.compile("^.*\.log$")
        file_operations_raw_rlst.remove_files_in_dir(pttrn_logs,Path("./logs"))
        logger_insert_ruleset = unpack_raw_rlst.setup_logger(name="insert_ruleset", log_file="logs/insert_ruleset.log",
                                                             level=logging.INFO)
        logger_excel = unpack_raw_rlst.setup_logger(name="logger_excel", log_file="logs/save_to_xlsx.log",
                                                    level=logging.INFO)
        logger_appid = unpack_raw_rlst.setup_logger(name="appid", log_file="logs/appid.log", level=logging.INFO)
        logger_appname = unpack_raw_rlst.setup_logger(name="appname", log_file="logs/appname.log", level=logging.INFO)
        logger_parseip = unpack_raw_rlst.setup_logger(name="parseip", log_file="logs/parseip.log", level=logging.INFO)
        logger_tsa = unpack_raw_rlst.setup_logger(name="tsa", log_file="logs/tsa.log", level=logging.INFO)
        row1=sql_statements.get_row_count(table="ruleset",db_name=self.__class__.db_name)
        pttrn_rlst = re.compile("^QualityCheck.+\.xlsx$")
        filepath_qc=file_operations_raw_rlst.search_newest_in_folder(dir=Path("files"), pttrn=pttrn_rlst)
        print("Using " + filepath_qc.resolve().__str__())
        list_dict_transformed_outer = unpack_raw_rlst.get_processed_qc_as_list(filepath_qc=filepath_qc)
        unpack_raw_rlst.dict_to_sql(list_unpacked_ips=list_dict_transformed_outer)
        row2=sql_statements.get_row_count(table="ruleset",db_name=self.__class__.db_name)
        self.assertTrue(row1<row2)
        # assert  that logs/insert_ruleset.log is empty
        self.assertTrue(Path("logs/insert_ruleset.log").stat().st_size == 0)
