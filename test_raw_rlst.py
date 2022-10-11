import re
from pathlib import Path
from unittest import TestCase

import file_operations_raw_rlst
import sql_statements
import unpack_raw_rlst


class TestMain(TestCase):
    db_name = "CSV_DB"

    # remove raw se_ruleset
    def test_remove_raw(self):
        pttrn_rlst = re.compile("^.+se_ruleset.+\.xlsx$")
        file_operations_raw_rlst.remove_files_in_project_dir(
            pttrn_ruleset=pttrn_rlst)

    #remove unpacked se_ruleset
    def test_remove_unpacked(self):
        pttrn_output = re.compile("se_ruleset_unpacked.\d{2}[A-Za-z]{3}\d{4}\.xlsx$")
        file_operations_raw_rlst.remove_files_in_project_dir(
            pttrn_ruleset=pttrn_output)

    def test_copy_raw_to_local_dir(self):
        file_operations_raw_rlst.copy_raw_to_local_dir()

    def test_save_to_xlsx(self):
        path_to_save = "./se_ruleset_unpacked_%s.xlsx"
        pttrn_rlst = re.compile("^.+se_ruleset.+\.xlsx$")
        filepath_qc=file_operations_raw_rlst.search_newest_in_folder(dir="./", pttrn=pttrn_rlst)
        print("Using " + filepath_qc.resolve().__str__())
        list_dict_transformed_outer = unpack_raw_rlst.get_processed_qc_as_list(filepath_qc=filepath_qc)
        unpack_raw_rlst.save_to_xlsx(list_dict_transformed_outer=list_dict_transformed_outer, path_to_save=path_to_save)

    def test_save_to_sql(self):
        row1=sql_statements.get_row_count(table="ruleset",db_name=self.__class__.db_name)
        pttrn_rlst = re.compile("^.+se_ruleset.+\.xlsx$")
        filepath_qc=file_operations_raw_rlst.search_newest_in_folder(dir=Path("./"), pttrn=pttrn_rlst)
        print("Using " + filepath_qc.resolve().__str__())
        list_dict_transformed_outer = unpack_raw_rlst.get_processed_qc_as_list(filepath_qc=filepath_qc)
        unpack_raw_rlst.dict_to_sql(list_unpacked_ips=list_dict_transformed_outer)
        row2=sql_statements.get_row_count(table="ruleset",db_name=self.__class__.db_name)
        self.assertTrue(row1<row2)