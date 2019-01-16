#!/usr/bin/python3
# Get global and per wiki rights for a user
try:
    import requests
except ImportError:
    print('Install requests3 library')
import getpass
import sys
import json

def main():
    user = sys.argv[1]

    req = 'https://meta.wikimedia.org/w/api.php?action=query&format=json&meta=globaluserinfo&guiuser={}&guiprop=groups%7Crights%7Cmerged'
    req_user = req.format(user)
    r = requests.get(req_user)
    results = json.loads(r.content.decode('utf-8'))
    if '-v' in sys.argv:
        print(results)
    else:
        global_groups = ','.join(results['query']['globaluserinfo']['groups'])
        print('global: {}'.format(global_groups))
        wikis =  results['query']['globaluserinfo']['merged']

    wap = {}
    for w in wikis:
        if 'groups' in w:
            wiki = w['wiki']
            rights = ','.join(w['groups'])
            print("{}: {}".format(wiki, rights))

if __name__ == '__main__':
    main()
