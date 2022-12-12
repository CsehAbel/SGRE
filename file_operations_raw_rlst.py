import datetime
from pathlib import Path
from tarfile import TarFile
import re
import shutil

project_dir=Path("./")

def delete_hits(dir):
    hits_folder=Path(project_dir/dir)
    b_exists = hits_folder.exists()
    b_is_dir = hits_folder.is_dir()
    if b_exists and b_is_dir:
        for child in hits_folder.iterdir():
            unlink_file(child.resolve().__str__(),child.name,child)
            print("%s unlinked" %child.resolve().__str__())

def search_newest_in_folder(dir, pttrn):
    b_exists = dir.exists()
    b_is_dir = dir.is_dir()
    stats = []
    if b_exists and b_is_dir:
        for child in dir.iterdir():
            res = pttrn.match(child.name)
            if res:
                stats.append(child)
    newest_tar_gz = max(stats, key=lambda x: x.stat().st_mtime)
    return newest_tar_gz

def unlink_file(to_be_unlinked_file):
    try:
        to_be_unlinked_file.unlink()
        print("%s unlinked" % to_be_unlinked_file.name)
    except FileNotFoundError:
        print("%s not found" % to_be_unlinked_file.name)
    exists_still = to_be_unlinked_file.is_file()
    if exists_still:
        raise RuntimeError("files %s to be deleted still exists" % to_be_unlinked_file.name)

def rename_darwin_transform_json():
    source=Path("new_transform.json")
    if not source.exists():
        print(source.name + " not in dir, nothing to be rename\n")
    else:
        dtm=datetime.datetime.now()
        d_m=dtm.strftime("%d_%m")
        target_string=("%s_new_transform.json" %d_m)
        target = Path(target_string)
        if not target.exists():
            source.rename(target_string)
            print(source.name+"\n renamed to \n"+target.name)

def one_file_found_in_folder(filepath_list, project_dir, pttrn_snic):
    for x in project_dir.iterdir():
        if pttrn_snic.match(x.name):
            filepath_list.append(x.resolve().__str__())
    if filepath_list.__len__() != 1:
        raise ValueError(project_dir.name+": more than one file matching "+pttrn_snic.pattern)

def remove_files_in_project_dir(pttrn_ruleset):
    remove_files_in_dir(pttrn_ruleset,project_dir)

def remove_files_in_dir(pttrn,dir):
    for x in dir.iterdir():
        if pttrn.match(x.name):
            unlink_file(x)
            print("%s unlinked" %x.resolve().__str__())

def copy_raw_to_local_dir():
    seruleset_dir = Path("/mnt/c/UserData/z004a6nh/Documents/OneDrive - Siemens AG/Darwin/")
    pttrn_rlst = re.compile("^QualityCheck.+\.xlsx$")
    newest_rlst = search_newest_in_folder(seruleset_dir, pttrn_rlst)
    shutil.copy(src=newest_rlst,
                dst=Path("./") / newest_rlst.name)
    print(newest_rlst.name + " copied to project_dir.")