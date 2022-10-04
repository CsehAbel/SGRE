import re
from unittest import TestCase

import file_operations
import main


class TestMain(TestCase):

    # remove raw se_ruleset
    def test_remove_raw(self):
        pttrn_rlst = re.compile("^.+se_ruleset.+\.xlsx$")
        file_operations.remove_files_in_project_dir(
            pttrn_ruleset=pttrn_rlst)

    #remove unpacked se_ruleset
    def test_remove_unpacked(self):
        pttrn_output = re.compile("se_ruleset_unpacked.\d{2}[A-Za-z]{3}\d{4}\.xlsx$")
        file_operations.remove_files_in_project_dir(
            pttrn_ruleset=pttrn_output)

    def test_copy_raw_to_local_dir(self):
        file_operations.copy_raw_to_local_dir()

    def test_save_to_xlsx(self):
        path_to_outfile = "./se_ruleset_unpacked_%s.xlsx"
        pttrn_rlst = re.compile("^.+se_ruleset.+\.xlsx$")
        main.save_to_xlsx(pttrn_rlst, path_to_outfile)