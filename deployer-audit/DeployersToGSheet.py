#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Tool to audit Wikimedia deployers
Author: sbassett@wikimedia.org
License: Apache 2.0
Uses: github.com (for raw data.yaml file), google sheets API
"""
import argparse
import datetime
import pickle
import os
import re
import requests
import sys
import urllib.parse
import yaml
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from dotenv import load_dotenv

""" constants """
load_dotenv()
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']
GET_RANGE = "Deployers Audit!A2:G"
WRITE_RANGE = "Deployers Audit!A2"
ADMIN_DATA_FILE = os.getenv('DTG_ADMIN_DATA_FILE')
SPREADSHEET_ID = os.getenv('DTG_GOOGLE_SHEET_ID')
SAL_URL_BASE = os.getenv('DTG_SAL_URL_BASE')
SAL_YEARS_PREV = os.getenv('DTG_SAL_YEARS_PREV')
NO_DEPLOYS = 'No deploys last 2 years'


def main():
    """ cli args/control """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--phab', action='store_true',
                        default=False,
                        help='Optionally print Phab-formatted\
                        table to stdout')
    parser.add_argument('-n', '--nodeploys', action='store_true',
                        default=False,
                        help='Only print "no deploy" users for\
                        Phab-formatted table')
    args, unknown = parser.parse_known_args()

    """ process Google Sheets API creds """
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    """ If there are no (valid) credentials available, let the user log in. """
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        """ Save the credentials for the next run """
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('sheets', 'v4', credentials=creds)

    """ get and process admin.yaml """
    resp = requests.get(ADMIN_DATA_FILE)
    if resp.status_code != 200:
        print("Response Error, status code = {}".format(resp.status_code))
        sys.exit(1)
    else:
        deployers_from_yaml = []
        data = yaml.safe_load(resp.text)
        if isinstance(data, dict):
            deployers_from_yaml = data['groups']['deployment']['members']
            deployers_from_yaml.sort()

    """ try to find last deployed data for a deployer
        wikitech:index.php?title=Server_admin_log/Archives&action=raw
        wikitech:index.php?title=Server_admin_log&action=raw
        search back dates for user - pattern: 'nn:nn {user}:' """
    full_log_text = ''
    deployers_last_deploy = {}

    """ current last deploy data from sal """
    current_url = ''.join([SAL_URL_BASE, 'Server%20Admin%20Log&action=raw'])
    resp = requests.get(current_url)
    if resp.status_code != 200:
        print("Response Error, status code = {}".format(resp.status_code))
        sys.exit(1)
    else:
        full_log_text = ''.join([full_log_text, resp.text])

    """ historic last deploy data from sal """
    historic_url = ''.join([SAL_URL_BASE,
                           'Server_admin_log/Archives&action=raw'])
    resp = requests.get(historic_url)
    if resp.status_code != 200:
        print("Response Error, status code = {}".format(resp.status_code))
        sys.exit(1)
    else:
        years = [datetime.datetime.now().year,
                 datetime.datetime.now().year - int(SAL_YEARS_PREV)]
        for year in years:
            for line in resp.text.split('\n'):
                pat = ''.join([r'\[\[(.+)\|', str(year), r'.+'])
                found = re.findall(pat, line)
                if found:
                    for archive in found:
                        archive_url = ''.join([SAL_URL_BASE,
                                               urllib.parse.quote(archive),
                                               '&action=raw'])
                        aresp = requests.get(archive_url)
                        if aresp.status_code != 200:
                            print("Response Error, status code = {}".format(
                                  resp.status_code))
                            sys.exit(1)
                        else:
                            full_log_text = ''.join([full_log_text,
                                                     aresp.text])

    """ process last deploy data """
    for dep in deployers_from_yaml:
        for line in full_log_text.split('\n'):
            pat_date = r'==\s*(\d{4}\-\d{2}\-\d{2})\s*=='
            found_date = re.match(pat_date, line)
            if 'current_last_deploy_date' not in locals():
                current_last_deploy_date = NO_DEPLOYS
            if found_date and len(found_date.groups(0)) > 0:
                current_last_deploy_date = found_date.groups(0)[0]
                continue
            pat_dep = ''.join([r'(\*\s?\d\d\:\d\d\s+)(', str(dep), r')'])
            if re.search(pat_dep, line, re.I):
                if ((dep in deployers_last_deploy and
                     deployers_last_deploy[dep] <
                     current_last_deploy_date) or
                        dep not in deployers_last_deploy):
                    deployers_last_deploy[dep] = current_last_deploy_date
                    continue
        if dep not in deployers_last_deploy:
            deployers_last_deploy[dep] = NO_DEPLOYS

    """ get current data from Google Sheet """
    sheet = service.spreadsheets()
    result = sheet.values().get(spreadsheetId=SPREADSHEET_ID,
                                range=GET_RANGE).execute()
    deployers_from_sheet_data = result.get('values', [])

    """ update and sync all data thus far """
    deployers_all = []
    deployers_from_sheet = []
    deployers_to_write_to_sheet = []
    for dep in deployers_from_sheet_data:
        if(isinstance(dep, list) and len(dep) > 0 and isinstance(dep[0], str)):
            deployers_from_sheet.append(dep[0])

    deployers_all = list(set().union(
        deployers_from_sheet,
        deployers_from_yaml)
    )
    deployers_all.sort()

    update_time = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M')

    for dep in deployers_all:
        if(len(deployers_from_sheet_data) > 0):
            dep_found = False
            dep_last_deploy = deployers_last_deploy[dep] if\
                dep in deployers_last_deploy else NO_DEPLOYS
            for dep_data in deployers_from_sheet_data:
                if(isinstance(dep_data, list) and
                   isinstance(dep, str) and
                   dep == dep_data[0]):
                    if len(dep_data) == 1:
                        dep_data.append("")
                    if len(dep_data) == 2:
                        dep_data.append("0")
                    if len(dep_data) == 3:
                        dep_data.append("0")
                    if len(dep_data) == 4:
                        dep_data.append("0")
                    if len(dep_data) == 5:
                        dep_data.append("")
                    elif(len(dep_data[5]) == 0 or
                         dep_data[5] != dep_last_deploy):
                        dep_data[5] = dep_last_deploy
                    if len(dep_data) == 6:
                        dep_data.append(update_time)
                    else:
                        dep_data[6] = update_time
                    dep_data.pop(0)
                    deployers_to_write_to_sheet.append([dep] + dep_data)
                    dep_found = True
            if(dep_found is False):
                deployers_to_write_to_sheet.append(
                    [dep, "", "0", "0", "0", dep_last_deploy, update_time])

    """ write updated data to Google Sheet """
    result2 = sheet.values().update(
        spreadsheetId=SPREADSHEET_ID,
        range=WRITE_RANGE,
        body={"range": WRITE_RANGE,
              "values": deployers_to_write_to_sheet,
              "majorDimension": "ROWS"},
        valueInputOption="RAW").execute()

    print('Google sheet has been updated.')

    """ optionally format output as Phab table """
    if(args.phab):
        print('\n| Shell username | Name | WMF | WMDE | \
              WMF Legal NDA? | Last Deployed | Date Updated')
        print('| --- | --- | --- | --- | --- | --- | ---')
        for row in deployers_to_write_to_sheet:
            if(args.nodeploys and row[5] == NO_DEPLOYS):
                print('|', ' | '.join(row))
            elif(not args.nodeploys):
                print('|', ' | '.join(row))


""" call main """
if __name__ == '__main__':
    main()
