import re
import sys

from passlib.hash import sha512_crypt

DEF_ROUNDS = 5000


def parse_crypt_line(cr_line: str):
    p_cr_pass = cr_line.split("$", 3)
    if len(p_cr_pass) < 3:
        return None, None, None
    _, alg, salt, passwd = p_cr_pass
    return alg, salt, passwd


def brute_passwd(dict_file, cr_line):
    alg, salt, passwd = parse_crypt_line(cr_line)
    if not passwd:
        return None
    r_match = re.match(r".*rounds=(\d*)", salt)
    rounds = r_match.group(1) if r_match else DEF_ROUNDS

    with open(dict_file, 'r') as df:
        for line in df.readlines():
            open_pass = line.strip()
            exp_pass = sha512_crypt.hash(open_pass, salt=salt, rounds=rounds)
            if exp_pass == cr_line:
                return open_pass
    return None


def parse_shadow(shadow_file):
    result = dict()

    with open(shadow_file, 'r') as sf:
        for line in sf.readlines():
            p_line = line.split(":")
            if len(p_line) < 2:
                continue
            user, cr_pass = p_line[:2]
            if not all(parse_crypt_line(cr_pass)):
                continue
            result[user] = cr_pass

    return result


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <shadow_file> <dictionary>")
        exit(0)
    shadow = sys.argv[1]
    dictionary = sys.argv[2]

    shadow_data = parse_shadow(shadow)
    for user, cr_pass in shadow_data.items():
        found_pass = brute_passwd(dictionary, cr_pass)
        if found_pass:
            print(f"[+] Found password for {user}: {found_pass}")
            continue


if __name__ == "__main__":
    main()
