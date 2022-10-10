import requests
import hashlib
import sys


def query_hibp_api(head_hash: str) -> list:
    url = f"https://api.pwnedpasswords.com/range/{head_hash}"
    try:
        res = requests.get(url)
    except requests.exceptions.ConnectionError:
        sys.exit("Connection Error.")

    # Tuple comprehension of lists having tail_hash and leak_count
    t_leaks = (line.split(":") for line in res.text.splitlines())
    return t_leaks if t_leaks else []


def get_pswd_leak_count(password: str) -> int:
    # Generate SHA1 hash. As per API, send first 5 hashcharacters of password
    hash_of_password = hashlib.sha1(password.encode()).hexdigest().upper()
    first_5_char, rest_char = hash_of_password[:5], hash_of_password[5:]
    tail_leaks = query_hibp_api(first_5_char)

    # Loop through the tuple of lists, looking for a match of tail hash
    for tail_hash, leak_ctr in tail_leaks:
        if tail_hash == rest_char:
            return int(leak_ctr)
    return 0


def main():
    if (len(sys.argv) == 1):
        sys.exit('Too few command-line arguments! Enter some passwords to check after filename.')

    for pswd in sys.argv[1:]:
        leak_count = get_pswd_leak_count(pswd)
        if leak_count:
            print(f"'{pswd}' has been in a breach {leak_count} times. Suggest changing password!")
        else:
            print(f"'{pswd}' has not been in any breach. Well done!")


if __name__ == "__main__":
    main()
