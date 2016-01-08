from hashlib import md5
from os.path import exists
from requests import get
from os.path import split as extract
from json import loads as parseJSON
import argparse

QUERY_API = 'http://md5cracker.org/api/api.cracker.php?database=%s&hash=%s'
QUERY_VENDOR = ['md5cracker.org', 'tmto', 'md5.net', 'md5online.net', 'md5.my-addr.com',
                'md5decryption.com', 'md5crack', 'authsecu', 'netmd5crack', 'md5pass',
                'i337.net']

def generate_hash(plain):
    hash = md5()
    hash.update(plain)

    return hash.hexdigest()

def query_hash_plain(hash):
    plain_text = ''

    print 'Cracking hash %s...' % hash

    for vendor in QUERY_VENDOR:
        url = QUERY_API % (vendor, hash)
        res = get(url)

        if res.status_code == 200:
            result = parseJSON(res.content)

            if result['status']:
                plain_text = result['result']
                print 'Hash Found!! Plain: %s' % plain_text
                break

    return plain_text

def treat_as_file(input, typePrefix, processCallback):
    for f in input:
        if not exists(f):
            print "Skip input file %s which is doesn't exists" % f
            continue;

        result = dict()
        with open(f, "r") as handle:
            for line in handle:
                content = line.strip()
                if content == '': continue

                r = processCallback(content)
                if r != '': result[content] = r

        if len(result) == 0:
            return False

        path, name = extract(f)
        name = typePrefix + "_" + name

        output = "%s/%s" % (path, name) if path != '' else name

        with open(output, "w") as handle:
            # Duplicate for speed
            if typePrefix == "hash":
                for hash,plain in result.items():
                    handle.write("%s:%s\n" % (plain, hash))
            elif typePrefix == "plain":
                for hash,plain in result.items():
                    handle.write("%s:%s\n" % (hash, plain))

def treat_as_raw(input, typePrefix, processCallback):
    result = dict()

    for content in input:
        result[content] = processCallback(content)

    if len(result) > 0:
        if typePrefix == "hash":
            for hash,plain in result.items():
                print "%s:%s" % (plain, hash)
        elif typePrefix == "plain":
            for hash,plain in result.items():
                print "%s:%s" % (hash, plain)


def main():
    parser = argparse.ArgumentParser(description='MD5 Prepare')
    group = parser.add_argument_group('MD5 Hash Operation')
    group.add_argument('-q', dest="query", action="store_true",
                    help="Crack the MD5 hash on the online website.")
    group.add_argument('-c', dest="create", action="store_true",
                    help="Generate the MD5 hash from the local file.")
    group.add_argument('-i', nargs='+', dest='input', metavar="FILE",
                    default=None,
                    help='Specify the input files which are include the plain text or hash.')
    group.add_argument('-r', nargs="+", dest="raw", metavar="RAW",
                    default=None,
                    help='Specify the MD5 hash or plain text instead of the local file.')

    args = parser.parse_args()
    # No input file
    if args.input == None and args.raw == None:
        args.print_help()
    # Input mode: 0. file 1. hash
    mode = 0 if args.input != None else 1

    if mode == 0 and args.query:
        treat_as_file(args.input, "plain", query_hash_plain)
    elif mode == 0 and args.create:
        treat_as_file(args.input, "hash", generate_hash)
    elif mode == 1 and args.query:
        treat_as_raw(args.raw, "plain", query_hash_plain)
    elif mode == 1 and args.create:
        treat_as_raw(args.raw, "hash", generate_hash)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
