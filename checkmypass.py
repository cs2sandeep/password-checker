import requests
import hashlib
import sys


def query_hibp_api(head_hash: str) -> list:
    url = f"https://api.pwnedpasswords.com/range/{head_hash}"
    try:
        res = requests.get(url)
    except requests.exceptions.ConnectionError:
        sys.exit("Connection Error.")

    # See response data format and make a list by splitting on \r\n
    list_of_breaches = res.text.split(sep="\r\n")

    # List comprehension of tuples having tail_hash and leak_count
    t_leaks = [tuple(breach.split(":")) for breach in list_of_breaches]
    if t_leaks:
        return t_leaks
    return []


def get_pswd_leak_count(password: str) -> int:
    # Generate SHA1 hash. As per API, send first 5 hashcharacters of password
    hash_of_password = hashlib.sha1(password.encode()).hexdigest()
    first_5_char, rest_char = hash_of_password[:5], hash_of_password[5:]
    tail_leaks = query_hibp_api(first_5_char.upper())

    # Loop through the list of tuples, looking for a match of tail hash
    for tail_hash, leak_ctr in tail_leaks:
        if tail_hash == rest_char.upper():
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
