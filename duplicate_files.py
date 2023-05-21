from datetime import datetime
from logging.handlers import RotatingFileHandler

import hashlib
import logging
import os
import re
import sqlite3

ALGORITHM_TO_USE = "sha1"


def function_root_dir(pathlike: str):
    parts = os.path.abspath(pathlike).split(os.sep)
    front = parts[0]
    back = os.sep.join(parts[1:])
    return front + os.sep, back


def function_new_filename(
    pathlike: str,
    *args: str,
    filetype_alt: str | None = None,
    makedirs: bool = False,
    no_of_digits: int = 3,
):
    assert type(pathlike) is str
    try:
        assert type(filetype_alt) is str, "is not String."
    except AssertionError as ae:
        if str(ae) == "is not String.":
            assert filetype_alt is None, "should be either None or String."
        else:
            raise ae
    assert type(makedirs) is bool
    assert type(no_of_digits) is int
    assert 0 < no_of_digits < 8

    pathlike = os.path.abspath(pathlike)
    parent, filename = os.path.split(pathlike)
    filename_, filetype = os.path.splitext(filename)
    if filetype_alt:
        filetype = filetype_alt
    for arg in args:
        parent = os.path.join(parent, arg)
    filecounter = 1
    if regex := re.match("^(?P<filename_>.+)\ \((?P<filecounter>\d+)\)$", filename_):
        filename_ = regex.group("filename_").strip()
    if makedirs:
        if not os.path.exists(parent):
            os.makedirs(parent)
    newfile = os.path.abspath(os.path.join(parent, filename_ + filetype))
    while os.path.exists(newfile):
        newfile = os.path.join(
            parent,
            f"{filename_} ({str(filecounter).zfill(no_of_digits)}){filetype}",
        )
        if filecounter > (10**no_of_digits) - 1:
            raise FileExistsError(newfile)
        filecounter += 1
    return newfile


def function_cipher(pathlike: str, chunk_size=32768):
    algorithm = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha224": hashlib.sha224(),
        "sha256": hashlib.sha256(),
        "sha384": hashlib.sha384(),
        "sha512": hashlib.sha512(),
        "sha3_224": hashlib.sha3_224(),
        "sha3_384": hashlib.sha3_384(),
        "sha3_512": hashlib.sha3_512(),
        "sha3_256": hashlib.sha3_256(),
    }
    code = algorithm.get(ALGORITHM_TO_USE, hashlib.sha1())
    with open(pathlike, "rb") as handler:
        buffer = handler.read(chunk_size)
        while 0 < len(buffer):
            code.update(buffer)
            buffer = handler.read(chunk_size)
        handler.close()
    return code.hexdigest()


def function_cipher_partial(pathlike: str, chunk_size=32768):
    algorithm = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha224": hashlib.sha224(),
        "sha256": hashlib.sha256(),
        "sha384": hashlib.sha384(),
        "sha512": hashlib.sha512(),
        "sha3_224": hashlib.sha3_224(),
        "sha3_256": hashlib.sha3_256(),
        "sha3_384": hashlib.sha3_384(),
        "sha3_512": hashlib.sha3_512(),
    }
    code = algorithm.get(ALGORITHM_TO_USE, hashlib.sha1())
    with open(pathlike, "rb") as handler:
        buffer = handler.read(chunk_size)
        code.update(buffer)
        handler.close()
    return code.hexdigest()


def function_scan(pathlike: str):
    for root, _, files in os.walk(os.path.abspath(pathlike)):
        print(root)
        for filename in filter(
            lambda filename: filename.lower().casefold() != "desktop.ini",
            files,
        ):
            yield os.path.join(root, filename)


def function_duplicate_files(*from_folders, remove_files: bool = False):
    global ALGORITHM_TO_USE
    ALGORITHM_TO_USE = "sha3_512"
    app_data = os.path.join(os.path.dirname(__file__), "AppData")
    if not os.path.exists(app_data):
        os.makedirs(app_data)

    logFile = os.sep.join((app_data, datetime.now().strftime("%Y%m%d %H%M%S %f") + ".txt"))
    logger = logging.getLogger("log")
    logger.setLevel(logging.INFO)
    loggerFormat = logging.Formatter("%(message)s")
    loggerHandler = RotatingFileHandler(
        logFile,
        maxBytes=10 * 1024 * 1024,
        backupCount=20,
        mode="W",
        encoding="UTF-8",
    )
    loggerHandler.setLevel(logging.INFO)
    loggerHandler.setFormatter(loggerFormat)
    logger.addHandler(loggerHandler)

    logger.info("*" * 120)
    logger.info(datetime.now().strftime("%Y-%m-%d %H:%M:%S - %f").center(120))
    logger.info("*" * 120)

    connection = sqlite3.connect(os.sep.join((app_data, "database.sqlite3")))
    cursor = connection.cursor()

    connection.create_function("security_full", 2, function_cipher)
    connection.create_function("security_part", 2, function_cipher_partial)

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS FILESTORE (
        ID           INTEGER PRIMARY KEY,
        FILEPATH     TEXT    UNIQUE,
        FILENAME     TEXT,
        FILELOCATION TEXT,
        FILENAME_    TEXT,
        FILETYPE     TEXT,
        FILESIZE     INTEGER DEFAULT -1,
        CTIME        INTEGER DEFAULT -1,
        ATIME        INTEGER DEFAULT -1,
        MTIME        INTEGER DEFAULT -1,
        HASH_FULL    TEXT,
        HASH_PART    TEXT
    );
    DELETE FROM FILESTORE;
    """)
    sql_insert = """
    INSERT INTO FILESTORE (
                              FILEPATH,
                              FILENAME,
                              FILELOCATION,
                              FILENAME_,
                              FILETYPE,
                              FILESIZE,
                              CTIME,
                              MTIME,
                              ATIME
                          )
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);"""
    for folder in from_folders:
        for filepath in function_scan(folder):
            parent_dir, filename = os.path.split(filepath)
            filename_, filetype = os.path.splitext(filename)
            try:
                stat = os.stat(filepath)
                filesize = stat.st_size
                ctime = min(stat.st_ctime_ns, stat.st_mtime_ns)
                mtime = max(stat.st_ctime_ns, stat.st_mtime_ns)
                atime = stat.st_atime_ns
                cursor.execute(
                    sql_insert,
                    (
                        filepath,
                        filename,
                        parent_dir,
                        filename_,
                        filetype,
                        filesize,
                        ctime,
                        mtime,
                        atime,
                    ),
                )
            except Exception as e:
                logger.exception(e)
        connection.commit()

    sql_update = """
    WITH SAMEFILESIZE (
        FILESIZE
    )
    AS (
        SELECT FILESIZE
          FROM FILESTORE
         GROUP BY FILESIZE
        HAVING COUNT(FILESIZE) > 1
    )
    UPDATE FILESTORE
       SET HASH_PART = security_part(FILESTORE.FILEPATH, 8192)
     WHERE FILESIZE IN (
        SELECT FILESIZE
          FROM SAMEFILESIZE
    );
    WITH SAMEHASHPART (
        HASH_PART
    )
    AS (
        SELECT HASH_PART
          FROM FILESTORE
         WHERE HASH_PART IS NOT NULL
         GROUP BY HASH_PART
        HAVING COUNT(HASH_PART) > 1
    )
    UPDATE FILESTORE
       SET HASH_FULL = security_full(FILESTORE.FILEPATH, 8192)
     WHERE HASH_PART IN (
        SELECT HASH_PART
          FROM SAMEHASHPART
    );"""
    cursor.executescript(sql_update)

    connection.commit()

    limit, offset = 100, 0
    sql_select_same_key = """
    WITH FULLHASH (
        FILECOUNT,
        HASH_FULL
    )
    AS (
        SELECT COUNT( * ),
               HASH_FULL
          FROM FILESTORE
         WHERE HASH_FULL IS NOT NULL
         GROUP BY HASH_FULL
        HAVING 1 < COUNT(HASH_FULL)
    )
    SELECT FILECOUNT,
           HASH_FULL
      FROM FULLHASH
     ORDER BY FILECOUNT DESC
     LIMIT ? OFFSET ?;"""
    sql_select_files = """
    SELECT FILEPATH,
           FILENAME,
           FILELOCATION,
           FILENAME_,
           FILETYPE,
           FILESIZE,
           CTIME,
           MTIME,
           ATIME
      FROM FILESTORE
     WHERE HASH_FULL = ?
     ORDER BY CTIME,
              MTIME;
"""
    cursor.execute(sql_select_same_key, (limit, offset))
    same_key_buffer = cursor.fetchmany(limit)
    while 0 < len(same_key_buffer):
        for filecount, hash_full in same_key_buffer:
            logger.info(f"{filecount:5d} : {hash_full}".center(120))
            cursor.execute(sql_select_files, (hash_full,))
            file_buffer = cursor.fetchmany(limit)
            i = -1
            while 0 < len(file_buffer):
                for (
                    filepath,
                    filename,
                    filelocation,
                    filename_,
                    filetype,
                    filesize,
                    ctime,
                    mtime,
                    atime,
                ) in file_buffer:
                    i += 1
                    if i == 0:
                        logger.info(f"└┐ ♥ {filepath}")
                        continue
                    else:
                        f, b = function_root_dir(filepath)
                        bin_path = os.path.join(f, "♥", b)
                        string = " │ ♡"
                        if i % 4 == 1:
                            string = " │ ♡"
                        if i % 4 == 2:
                            string = "┌┘ ♡"
                        if i % 4 == 3:
                            string = "│  ♡"
                        if i % 4 == 0:
                            string = "└┐ ♡"
                        logger.info(f"{string} {bin_path}")
                        if remove_files:
                            os.renames(filepath, function_new_filename(bin_path))
                file_buffer = cursor.fetchmany(limit)
            if 0 < i:
                logger.info("")
        offset += limit
        cursor.execute(sql_select_same_key, (limit, offset))
        same_key_buffer = cursor.fetchmany(limit)

    connection.commit()
    connection.execute("vacuum;")
    connection.commit()
    connection.close()


if __name__ == "__main__":
    function_duplicate_files(
        os.path.join(os.environ.get("Userprofile", r"C:\users\Public"), "Downloads"),
        remove_files=True,
    )
    pass
