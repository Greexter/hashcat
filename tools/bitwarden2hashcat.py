"""Utility to extract Bitwarden hash for hashcat from Google Chrome / Firefox / Desktop local data"""

#
# Based on bitwarden2john.py https://github.com/willstruggle/john/blob/master/bitwarden2john.py
#
# Various data locations are documented here: https://bitwarden.com/help/data-storage/#on-your-local-machine
#
# Author: https://github.com/Greexter
# License: MIT
#

import os
import argparse
import sys
import base64
import traceback
from enum import Enum

try:
    import json
    assert json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        print("Please install json module which is currently not installed.\n", file=sys.stderr)
        sys.exit(-1)


# Using precoded key values defined here for firefox DB
encoded_key_dict = {
     "kdfIterations": "0legJufsbujpot",
     "userEmail": "0vtfsFnbjm",
     "pinProtectedKey": "0qjoQspufdufeLfz",
     "keyHash": "0lfzIbti"
}


class Mode(Enum):
    PASS_HASH   = 'password'
    PIN         = 'pin'

    def __str__(self):
        return self.value


def litedb_get_value(data, name):
    value = data.split(name + b'\x00\x02Value\x00')[1]
    len = int.from_bytes(value[0:3], byteorder="little")
    return value[4:(len + 3)].decode()


def process_litedb(path, mode):
    # Due to no support for LiteDB in python, values are extracted manually
    with open(path, "rb") as litedb:
        data = litedb.read()
        
        if (mode == Mode.PASS_HASH):
            key_hash = litedb_get_value(data, b'keyHash').strip("\"")
            email = litedb_get_value(data, b'userEmail').strip("\"")
            iterations = int(litedb_get_value(data, b'kdfIterations'))
            return [(email, key_hash, iterations)]
        elif (mode == Mode.PIN):
            email = litedb_get_value(data, b'userEmail').strip("\"")
            iterations = int(litedb_get_value(data, b'kdfIterations'))
            pin_protected_key = litedb_get_value(data, b'pinProtectedKey').strip("\"")
            (iv, enc_data, mac) = pin_protected_key[2:].split('|')
            return [(iterations, email, iv, enc_data, mac)]
        else:
            raise NotImplementedError()


def process_sqlite(path, mode):
    try:
        import snappy
    except ImportError:
        print("Please install python-snappy module.\n", file=sys.stderr)
        sys.exit(-1)
    try:
        import sqlite3
    except ImportError:
        print("Please install sqlite3 module.\n", file=sys.stderr)
        sys.exit(-1)

    conn = sqlite3.connect(path)
    cur = conn.cursor()
    data = cur.execute('SELECT * FROM object_data')
    fetched = data.fetchall()

    # Uses undocumented nonstandard data format
    # Probably can break in the future

    parsed = {}
    for row in fetched:
        name_str = row[1].decode()
        if(name_str == encoded_key_dict["kdfIterations"]):
            parsed["kdfIterations"] = int.from_bytes(row[4].split(b'\xFF')[1][0:3], "little")
        elif(name_str == encoded_key_dict["keyHash"] and mode == Mode.PASS_HASH):
            parsed["keyHash"] = row[4].split(b'\xFF\xFF')[1].split(b'\x00')[0].strip(b'\x00').decode()
        elif(name_str == encoded_key_dict["userEmail"]):
            parsed["userEmail"] = row[4].split(b'\xFF\xFF')[1].decode()
        elif(name_str == encoded_key_dict["pinProtectedKey"] and mode == Mode.PIN):
            pin_protected_key = row[4].split(b"\xFF\xFF")[1].strip(b"\x00").decode()
            (iv, enc_data, mac) = pin_protected_key[3:].split('|')
            parsed["iv"] = iv
            parsed["enc_data"] = enc_data
            parsed["mac"] = mac

    if(len(parsed.keys()) == 3 and mode == Mode.PASS_HASH):
        return [(parsed["userEmail"], parsed["keyHash"], parsed["kdfIterations"])]
    elif(len(parsed.keys()) == 5 and mode == Mode.PIN):
        return [(parsed["kdfIterations"], parsed["userEmail"], parsed["iv"], parsed["enc_data"], parsed["mac"])]

    # Failed to parse all, try new format
    # Iterate all retrieved rows and try extracting by force
    out = []
    for x in fetched:
        try:
            decompressed = snappy.decompress(x[4])

            if (mode == Mode.PASS_HASH):
                key_hash = decompressed.split(b"keyHash")[1][9:53].decode()
                email = decompressed.split(b"email")[1][11:].split(b'\x00')[0].decode()
                iterations = int.from_bytes(decompressed.split(b"kdfIterations")[1][3:7], byteorder="little")

                out.append((email, key_hash, iterations))
            else:
                pin_protected_key = decompressed.split(b"pinProtected")[1].split(b"encrypted")[1]\
                    .split(b"\xFF\xFF")[1].split(b"\x00\x00")[0].decode()
                email = decompressed.split(b"email")[1][11:].split(b'\x00')[0].decode()
                iterations = int.from_bytes(decompressed.split(b"kdfIterations")[1][3:7], byteorder="little")
                (iv, data, mac) = pin_protected_key[3:].split('|')

                out.append((iterations, email, iv, data, mac))
        except(Exception):
            pass

    return out


def process_leveldb(path, mode):
    try:
        import leveldb
    except ImportError:
        print("Please install the leveldb module for full functionality!\n", file=sys.stderr)
        sys.exit(-1)

    db = leveldb.LevelDB(path, create_if_missing=False)

    try:
        out = []
        acc_ids = db.Get(b'authenticatedAccounts')
        acc_ids = json.loads(acc_ids)
        for id in acc_ids:
            auth_acc_data = db.Get(id.strip('"').encode())
            out.append(extract_json_profile(json.loads(auth_acc_data)))
        return out

    except(KeyError):
        # support for older Bitwarden versions (before account switch implementation)
        # data is stored in different format
        print("Failed to extract data, trying old format.", file=sys.stderr)
        if (mode == Mode.PASS_HASH):
            email = db.Get(b'userEmail')\
                .decode('utf-8')\
                .strip('"')
            key_hash = db.Get(b'keyHash')\
                .decode("ascii").strip('"')
            iterations = int(db.Get(b'kdfIterations').decode("ascii"))
            return [(email, key_hash, iterations)]
        else:
            raise NotImplementedError()


def process_json(data, mode):
    data = json.loads(data)

    try:
        out = []
        accIds = data["authenticatedAccounts"]
        for id in accIds:
            try:
                auth_acc_data = data[id.strip('"')]
                out.append(extract_json_profile(auth_acc_data, mode))
            except(KeyError):
                print("[error] Account id %s is missing required value, extraction is not possible for this mode. You may want to try different mode." % id, file=sys.stderr)
        return out
    except(KeyError):
        print("Failed to extract data, trying old format.", file=sys.stderr)
        if (mode == Mode.PASS_HASH):
            email = data["rememberedEmail"]
            hash = data["keyHash"]
            iterations = data["kdfIterations"]

            return [(email, hash, iterations)]
        elif (mode == Mode.PIN):
            email = data["userEmail"]
            iterations = data["kdfIterations"]
            pinProtectedKey = data["pinProtectedKey"]
            (iv, data, mac) = pinProtectedKey[2:].split('|')
            return [(iterations, email, iv, data, mac)] 
            
        else:
            raise NotImplementedError("This mode is not supported.")


def extract_json_profile(data, mode):
    profile = data["profile"]
    if (mode == Mode.PASS_HASH):
        email = profile["email"]
        iterations = profile["kdfIterations"]
        hash = profile["keyHash"]
        return email, hash, iterations
    elif (mode == Mode.PIN):
        settings = data["settings"]
        email = profile["email"]
        iterations = profile["kdfIterations"]
        pin_protected_key = settings["pinProtected"]["encrypted"]
        (iv, data, mac) = pin_protected_key[2:].split('|')
        return iterations, email, iv, data, mac 
    else:
        raise NotImplementedError()


def process_file(filename, mode, legacy = False):
    try:
        if os.path.isdir(filename):
            # Chromium based
            data = process_leveldb(filename, mode)
        elif filename.endswith(".sqlite"):
            # Firefox
            data = process_sqlite(filename, mode)
        elif filename.endswith(".json"):
            # json - Desktop 
            with open(filename, "rb") as f:
                data = f.read()
                data = process_json(data, mode)
        elif filename.endswith(".db"):
            # litedb - android
            data = process_litedb(filename, mode)
        else:
            print("[error] Unknown storage. Don't know how to extract data.", file=sys.stderr)
            sys.exit(-1)
    except (ValueError, KeyError):
        traceback.print_exc()
        print("[error] Missing values, user is probably logged out.", file=sys.stderr)
        return
    except:
        traceback.print_exc()
        return
    
    if(len(data) == 0):
        print("No values could be found. User is probably logged out.")
        return

    if (mode == Mode.PASS_HASH):
        iterations2 = 1 if legacy else 2
        for entry in data:
            if len(entry) != 3:
                print("[error] %s could not be parsed properly!\nUser is probably logged out." % filename, file=sys.stderr)
                continue
            print("$bitwarden$2*%d*%d*%s*%s" %
                (entry[2], iterations2, base64.b64encode(entry[0].encode("ascii")).decode("ascii"), entry[1]))
    elif (mode == Mode.PIN):
            for entry in data:
                if len(entry) != 5:
                    print("[error] %s could not be parsed properly!\nUser is probably logged out or PIN lock is not set." % filename, file=sys.stderr)
                    continue
                print(f"$bitwardenpin$1*{entry[0]}*{base64.b64encode(entry[1].encode()).decode()}*{entry[2]}*{entry[3]}*{entry[4]}")
    else:
        raise NotImplementedError()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", type=str, nargs="+")
    parser.add_argument("--legacy", action="store_true",
                        help="Used for older versions of Bitwarden (before static iteration count had been changed).")
    parser.add_argument("--mode", type=Mode, default=Mode.PASS_HASH, choices=list(Mode),
                        help="Choose which data to extract.")

    args = parser.parse_args()

    for p in args.paths:
        process_file(p, args.mode, args.legacy)
