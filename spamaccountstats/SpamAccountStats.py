#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" Basic statistics tool for Wikimedia spam account creation data
Author: sbassett@wikimedia.org
License: Apache 2.0
Uses: Mediawiki API (per project), Logstash API, stopforumspam.org
API and data files
"""

import argparse
import csv
import hashlib
import json
import os
import re
import requests
import sys
import time
import urllib.parse
import zlib

from datetime import datetime, timedelta
from dotenv import load_dotenv
from lxml import etree


class SpamAccountStats():
    """ Class to generate basic spam account creation stats """

    def __init__(self, project, date_range, raw_stats, sfs_api):
        """ constructor """
        self.project = project
        self.project_prefix = project.split('.')[0]
        self.project_type = project.split('.')[1]
        self.project_db_name = None
        self.date_range = date_range
        self.date_start = None
        self.date_end = None
        self.raw_stats = raw_stats
        self.sfs_api = sfs_api

        load_dotenv()
        self.def_proto = os.getenv('DEF_PROTO')
        self.def_suf = os.getenv('DEF_SUF')
        self.def_cache_path = os.getenv('DEF_CACHE_PATH')
        self.def_cache_time = float(eval(os.getenv('DEF_CACHE_TIME')))
        self.def_report_path = os.getenv('DEF_REPORT_PATH')

        self.sm_api_url = ''.join([self.def_proto,
                                  os.getenv('SITE_MATRIX_API_URL')])
        self.ac_api_url = os.getenv('ACCT_CREATE_API_URL')
        self.uc_api_url = os.getenv('USER_CONTRIB_API_URL')

        self.sfs_api_url = os.getenv('SFS_API_URL')
        self.sfs_ipv46_7_url = os.getenv('SFS_IPV46_7_URL')
        self.sfs_ipv46_30_url = os.getenv('SFS_IPV46_30_URL')
        self.sfs_ipv46_90_url = os.getenv('SFS_IPV46_90_URL')
        self.sfs_ipv46_180_url = os.getenv('SFS_IPV46_180_URL')
        self.sfs_ipv46_365_url = os.getenv('SFS_IPV46_365_URL')

        self.ls_api_url = os.getenv('LOGSTASH_API_URL')
        self.ls_ldap_user = os.getenv("LOGSTASH_LDAP_USER")
        self.ls_ldap_password = os.getenv("LOGSTASH_LDAP_PASSWORD")
        self.ls_num_results = int(os.getenv("LOGSTASH_NUM_RESULTS"))
        self.ls_max_hist_days = int(os.getenv('LOGSTASH_MAX_HIST_DAYS'))
        self.ls_long_timeout = int(os.getenv('LOGSTASH_LONG_TIMEOUT'))

        self.build_cache([
            [self.sm_api_url, 'text'],
            [self.sfs_ipv46_7_url, 'gz'],
            [self.sfs_ipv46_30_url, 'gz'],
            [self.sfs_ipv46_90_url, 'gz'],
            [self.sfs_ipv46_180_url, 'gz'],
            [self.sfs_ipv46_365_url, 'gz']
        ])

        if(self.validate_project_via_site_matrix() and
           self.validate_and_process_request_date_range()):

            new_acct_data = []
            new_acct_data = self.get_account_create_api_data()

            user_ip_data = []
            user_ip_data = self.search_users_within_logstash(
                new_acct_data
            )

            stats_list = []
            stats_list = [
                new_acct_data,
                user_ip_data,
                self.search_users_and_ips_within_sfs_api(user_ip_data),
                self.search_users_and_ips_within_sfs_files(user_ip_data),
                self.get_users_contributions(user_ip_data)
            ]
            self.generate_all_stats(stats_list)

        else:
            print("ERROR: the project or date range appears invalid.")
            sys.exit(1)

    def build_cache(self, file_urls):
        """ simple disk cache: build for a few needed files """
        if (isinstance(file_urls, list)):
            for f in file_urls:
                self.check_cache(f[0], f[1])

    def check_cache(self, file_url, file_type='text'):
        """ check cache, make if not exist, refresh if necessary,
            return full file path """
        if not os.path.exists(self.def_cache_path):
            os.makedirs(self.def_cache_path)

        hash_file_name = hashlib.sha1(
                             bytes(file_url, encoding="utf-8")
                         ).hexdigest()
        hash_file_path = ''.join([self.def_cache_path, '/', hash_file_name])
        if (not os.path.isfile(hash_file_path) or
                os.path.getmtime(hash_file_path) <
                (time.time() - self.def_cache_time)):
            resp = requests.get(file_url)
            if resp.status_code != 200:
                print("Response Error, status code = {}".format(
                      resp.status_code))
                sys.exit(1)
            else:
                if file_type == 'gz':
                    data = str(zlib.decompress(resp.content,
                               zlib.MAX_WBITS | 32))
                    with open(hash_file_path, 'w') as f:
                        f.write(data)
                        f.close()
                else:
                    with open(hash_file_path, 'w') as f:
                        f.write(resp.text)
                        f.close()

        return hash_file_path

    def get_cache_file(self, file_url):
        """ get cached file data, if it exists """
        file_path = self.check_cache(file_url)
        data = None
        with open(file_path, 'r') as f:
            data = f.read()
        return data

    def validate_project_via_site_matrix(self):
        """ validate arg: project is valid within site matrix api"""
        return_val = False

        """ beta support """
        beta = (self.project.split('.')[2] if
                len(self.project.split('.')) > 2 else '')
        if len(beta) > 0:
            print('Error: *.beta.wmflabs.org sites currently unsupported.')
            sys.exit(1)

        sm_api_json = {}
        resp = self.get_cache_file(self.sm_api_url)
        sm_api_json = json.loads(resp)['sitematrix']

        for item in sm_api_json:
            if (isinstance(sm_api_json[item], dict) and
                    len(sm_api_json[item]['code']) and
                    sm_api_json[item]['code'] == self.project_prefix and
                    isinstance(sm_api_json[item]['site'], list) and
                    len(sm_api_json[item]['site'])):
                for index in range(len(sm_api_json[item]['site'])):
                    if (sm_api_json[item]['site'][index]['url'].find(
                            ''.join([self.project, self.def_suf])) > -1):
                        self.project_db_name = \
                            sm_api_json[item]['site'][index]['dbname']
                        return_val = True
            elif (isinstance(sm_api_json[item], list)):
                for specials in sm_api_json[item]:
                    if (isinstance(specials, dict) and
                            'code' in specials.keys() and
                            'url' in specials.keys() and
                            'dbname' in specials.keys()):
                        if (specials['url'].find(
                                ''.join([self.project, self.def_suf])) > -1):
                            self.project_db_name = specials['dbname']
                            return_val = True
        return return_val

    def validate_and_process_request_date_range(self):
        """ validate arg: validate stats request dates """
        """ supported: XYd, XYh, YYYY-MM-DD, YYYY-MM-DD-YYYY-MM-DD, """
        """ YYYY-MM-DDTHH:MM:SSZ, YYYY-MM-DDTHH:MM:SSZ-YYYY-MM-DDTHH:MM:SSZ """
        check_value = False
        ucnow = datetime.utcnow()
        uc30dago = ucnow - timedelta(days=self.ls_max_hist_days)

        m = re.match(r'^(\d{1,2})([d])$', self.date_range)
        if (m is not None and m.group(1) is not None and
                m.group(2) is not None):
            self.date_start = ''.join([(ucnow -
                                      timedelta(days=int(m.group(1)))).replace(
                                          microsecond=0).isoformat(), 'Z'])
            self.date_end = ''.join(
                [ucnow.replace(microsecond=0).isoformat(), 'Z']
            )
            check_value = True

        if (check_value is False):
            m = re.match(r'^(0?[1-9]|1[0-9]|2[0-5])([h])$', self.date_range)
            if (m is not None and m.group(1) is not None and
                    m.group(2) is not None):
                self.date_start = ''.join([(ucnow -
                                          timedelta(
                                              hours=int(m.group(1)))).replace(
                                              microsecond=0).isoformat(), 'Z'])
                self.date_end = ''.join([ucnow.replace(
                                        microsecond=0).isoformat(), 'Z'])
                check_value = True

        if (check_value is False):
            m = re.match(r'^(\d{4}\-\d{2}\-\d{2})(\-\d{4}\-\d{2}\-\d{2})?$',
                         self.date_range)
            time_start_slug = 'T00:00:00Z'
            time_end_slug = 'T11:59:59Z'
            if (m is not None and m.group(1) is not None):
                self.date_start = ''.join([m.group(1), time_start_slug])
                if (m.group(2) is not None):
                    self.date_end = ''.join([m.group(2)[1:], time_end_slug])
                else:
                    self.date_end = ''.join([
                        ucnow.replace(microsecond=0).isoformat(),
                        time_end_slug
                    ])
                check_value = True

        if (check_value is False):
            m = re.match(r'^(\d{4}\-\d{2}\-\d{2}T\d{2}:\d{2}:\d{2}Z)'
                         r'(\-\d{4}\-\d{2}\-\d{2}T\d{2}:\d{2}:\d{2}Z)?$',
                         self.date_range)
            if (m is not None and m.group(1) is not None):
                self.date_start = m.group(1)
                if (m.group(2) is not None):
                    self.date_end = m.group(2)[1:]
                else:
                    self.date_end = ucnow.replace(microsecond=0).isoformat()
                check_value = True

        if (check_value is False):
            print('Invalid date argument supplied.')
            sys.exit(1)

        if (self.date_end > self.date_start):
            tmp = self.date_end
            self.date_end = self.date_start
            self.date_start = tmp

        if self.date_end < uc30dago.isoformat():
            print(''.join([
                "Date Error: start date cannot be more than ",
                str(self.ls_max_hist_days),
                " days ago."]))
            sys.exit(1)

        return check_value

    def get_account_create_api_data(self):
        """ get account create data from a project's action api """
        resp_continue = ''
        url = ''.join([self.def_proto, self.project, self.def_suf,
                      self.ac_api_url, '&lestart={}&leend={}']).format(
                      self.date_start,
                      self.date_end)

        ac_api_json = {}
        resp = requests.get(url)

        if resp.status_code != 200:
            print("Response Error, status code = {}".format(resp.status_code))
            sys.exit(1)
        else:
            if (isinstance(resp.json(), dict) and
                    'continue' in resp.json().keys() and
                    'lecontinue' in resp.json()['continue'].keys()):
                resp_continue = resp.json()['continue']['lecontinue']

            ac_api_json = resp.json()['query']['logevents']

            while resp_continue != '':
                url = ''.join([url, '&lecontinue=', resp_continue])
                resp = requests.get(url)
                if resp.status_code != 200:
                    print("Response Error, Acct Create, "
                          "status code = {}".format(
                              resp.status_code))
                    sys.exit(1)
                else:
                    if (isinstance(resp.json(), dict) and
                            'continue' in resp.json().keys() and
                            'lecontinue' in resp.json()['continue'].keys()):
                        resp_continue = resp.json()['continue']['lecontinue']
                    else:
                        resp_continue = ''

                    ac_api_json = ac_api_json + \
                        resp.json()['query']['logevents']

        """ deal with hidden/suppressed users or potentially bad API data """
        for i, user in enumerate(ac_api_json):
            if isinstance(user, dict) and 'user' not in user.keys():
                del ac_api_json[i]

        return ac_api_json

    def get_users_contributions(self, user_data):
        """ get a list of user's contributions from a project's action api,
            expects user_data[0] to be wiki username """
        uc_api_count = {}
        for u in user_data:
            url = ''.join([self.def_proto, self.project, self.def_suf,
                          self.uc_api_url, '{}']).format(
                              u[0]
                          )
            resp = requests.get(url)

            if resp.status_code != 200:
                print("Response Error, User Contribs, "
                      "status code = {}".format(resp.status_code))
                sys.exit(1)
            else:
                if (isinstance(resp.json(), dict)):
                    uc_api_count[u[0]] = len(
                        resp.json()['query']['usercontribs'])

        return uc_api_count

    def search_users_within_logstash(self, user_data):
        """ search a list of users via self.search_user_within_logstash"""
        user_ip_results = []
        user_ls_ip_data = []
        for user in user_data:
            if (isinstance(user, dict) and 'user' in user.keys()):
                user_ls_all_projects = False
                user_ls_ip_data = self.search_user_within_logstash(
                    user['user'])

                """ wider search if resources permit """
                if(len(user_ls_ip_data) < 1):
                    user_ls_ip_data = self.search_user_within_logstash(
                        user['user'], True
                    )
                    user_ls_all_projects = True

                user_ip_results.append([user['user']] +
                                       [str(user_ls_all_projects)] +
                                       user_ls_ip_data)

        return user_ip_results

    def search_user_within_logstash(self, user_identifier, all_projects=False):
        """ search a Wiki usernames in logstash,
            return list of public IPs """
        user_ips = []
        query = ''.join(['"', user_identifier, '"'])
        if (all_projects is False):
            query = ''.join([query, ' AND wiki=', self.project_db_name])

        if self.ls_ldap_user is None or self.ls_ldap_password is None:
            print("You need to set LDAP_USER and LDAP_PASS")
            sys.exit(1)

        url = self.ls_api_url.format(
                  self.ls_num_results, urllib.parse.quote(query)
              )

        resp = requests.get(url, auth=requests.auth.HTTPBasicAuth(
            self.ls_ldap_user,
            self.ls_ldap_password),
            timeout=self.ls_long_timeout)
        if resp.status_code != 200:
            print("Response Error, Logstash IPs, code = {}, reason = {}, \
                  url ={}, headers = {}".format(
                      resp.status_code,
                      resp.reason,
                      url,
                      str(resp.headers)))
            sys.exit(1)

        data = str(resp.json())

        # stackoverflow.com/questions/33453057/regex-to-only-match-public-ipv4-address
        ipv4sre = re.findall(r'((\d{1,3})(?<!10)\.(\d{1,3})'
                             r'(?<!192\.168)(?<!172\.(1[6-9]|2\d|3'
                             r'[0-1]))\.(\d{1,3})\.(\d{1,3}))',
                             data)
        ipv4s = []
        for ip in ipv4sre:
            if len(ip) > 0 and ip[0] not in ipv4s:
                ipv4s.append(ip[0])

        # stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
        ipv6sre = re.findall(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}'
                             r'|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
                             r'|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4})'
                             r'{1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]'
                             r'{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-'
                             r'fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0'
                             r'-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-'
                             r'fA-F]{1,4}){1,6})|::(ffff(:0{1,4}){0,1}:){0,1}'
                             r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.)'
                             r'{3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
                             r'|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1'
                             r'{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]'
                             r'|1{0,1}[0-9]){0,1}[0-9]))', data)
        ipv6s = []
        for ip in ipv6sre:
            if len(ip) > 0 and ip[0] not in ipv6s:
                ipv6s.append(ip[0])

        user_ips = ipv4s + ipv6s
        return user_ips

    def search_users_and_ips_within_sfs_api(self, user_ip_data):
        """ search a dict of user-associated IPs within StopForumSpam api,
            return dict of user name and IPs found within SFS API  """
        user_ips_sfs_api = {}
        if(self.sfs_api is True):
            for u in user_ip_data:
                ips_in_sfs = []
                if(len(u) > 1):
                    for i in range(2, len(u)):
                        resp = requests.get(''.join(
                                   [self.sfs_api_url, '{}']).format(u[i]))
                        if resp.status_code == 200:
                            print("Response Error, SFS API, status code = {}"
                                  .format(resp.status_code))
                            sys.exit(1)
                        root = etree.fromstring(resp.content)
                        for appears in root.findall("appears"):
                            if (appears.text == 'yes'):
                                ips_in_sfs.append(u[i])
                if(len(ips_in_sfs) > 0):
                    user_ips_sfs_api[u[0]] = ips_in_sfs

        return user_ips_sfs_api

    def search_users_and_ips_within_sfs_files(self, user_ip_data):
        """ search a dict of user IPs within StopForumSpam data files,
            return dict of user name and IPs found within SFS files  """
        user_ips_sfs_files = {}
        sfs_files = [
            [self.sfs_ipv46_7_url, '7'],
            [self.sfs_ipv46_30_url, '30'],
            [self.sfs_ipv46_90_url, '90'],
            [self.sfs_ipv46_180_url, '180'],
            [self.sfs_ipv46_365_url, '365']
        ]

        for f in sfs_files:
            cf_data = self.get_cache_file(f[0])
            for u in user_ip_data:
                ips_in_sfs = {}
                ips_in_sfs[f[1]] = []

                for j in range(2, len(u)):
                    if u[j] in cf_data:
                        ips_in_sfs[f[1]].append(u[j])

                if(len(ips_in_sfs[f[1]]) > 0):
                    if u[0] not in user_ips_sfs_files.keys():
                        user_ips_sfs_files[u[0]] = []
                    user_ips_sfs_files[u[0]].append(ips_in_sfs)

        return user_ips_sfs_files

    def generate_all_stats(self, stats_list):
        """ generate statistical data upon collected information
            data:
            stats_list[0]
            stats_list[1] = user ip [user, all_ls, ip...]
            stats_list[2] = sfs api {user: [ips...]}
            stats_list[3] = sfs files {user: [{'file_days': [ips...]}]}
            stats_list[4] = user contribs {user: num_contribs}

            Project:
            Date Range:
            Number of Account Creations:
            Number of New Users w/ IP Data in Logstash:
            Number of New Users w/ SFS Entries:
            Percent New Users Likely Spammy:

            User | Contribs | Num IPs LS | All Projects LS |
            SFS API | SFS 7 | SFS 30 | SFS 90 | SFS 180 | SFS 365
        """
        if(not isinstance(stats_list, list) or len(stats_list[0]) < 1):
            print(''.join(['No user data found for time period: ',
                           self.date_end,
                           ' - ',
                           self.date_start]))
            sys.exit(1)

        if (len(stats_list) != 5):
            print("Invalid stats_list list provided - expected length of 5.")
            sys.exit(1)

        if not os.path.exists(self.def_report_path):
            os.makedirs(self.def_report_path)

        csv_file_name = ''.join([
            self.def_report_path,
            '/',
            datetime.utcnow().strftime('%Y-%m-%d-%f'),
            '.csv'
        ])

        with open(csv_file_name, 'w') as csvfile:
            reportwriter = csv.writer(
                csvfile,
                'unix'
            )
            if self.raw_stats is False:
                reportwriter.writerow(['Project', self.project])
                reportwriter.writerow(['Date Range', ''.join([
                    self.date_start,
                    ' - ',
                    self.date_end])
                ])
                new_acct_count = len(stats_list[0])
                reportwriter.writerow(['Num Acct Creations',
                                       new_acct_count])
                user_ips_in_ls_count = len(stats_list[1])
                reportwriter.writerow(['Num Users IP Data In LS',
                                       user_ips_in_ls_count])
                num_users_ips_sfs_count = max(len(stats_list[2]),
                                              len(stats_list[3]))
                reportwriter.writerow(['Num Users SFS Entries',
                                       num_users_ips_sfs_count])
                if user_ips_in_ls_count > 0 and num_users_ips_sfs_count > 0:
                    percent_spammy = round((num_users_ips_sfs_count /
                                           user_ips_in_ls_count) * 100)
                else:
                    percent_spammy = 0
                reportwriter.writerow(['Percent Likely Spammy',
                                      ''.join([str(percent_spammy), '%'])])
                reportwriter.writerow(['', ''])
            # regular user stats
            csv_user_row_headers = ['User', 'Contribs', 'Num IPs LS',
                                    'All Projects LS', 'SFS API', 'SFS 7',
                                    'SFS 30', 'SFS 90', 'SFS 180', 'SFS 365']
            if(self.sfs_api is False):
                csv_user_row_headers.remove('SFS API')

            reportwriter.writerow(csv_user_row_headers)

            for u in stats_list[0]:
                un = u['user'] if len(u['user']) > 0 else 'NO USER'

                ips_in_ls_count = 0
                ips_beyond_project = False
                for uls in stats_list[1]:
                    if uls[0] == un:
                        ips_in_ls_count = len(uls) - 2
                        ips_beyond_project = uls[1]

                sfs_7_day_count = 0
                sfs_30_day_count = 0
                sfs_90_day_count = 0
                sfs_180_day_count = 0
                sfs_365_day_count = 0
                for i in stats_list[3]:
                    if un == i:
                        for j in stats_list[3][i]:
                            if '7' in j.keys():
                                sfs_7_day_count = len(j['7'])
                            if '30' in j.keys():
                                sfs_30_day_count = len(j['30'])
                            if '90' in j.keys():
                                sfs_90_day_count = len(j['90'])
                            if '180' in j.keys():
                                sfs_180_day_count = len(j['180'])
                            if '365' in j.keys():
                                sfs_365_day_count = len(j['365'])

                csv_user_data = [
                    un,
                    stats_list[4][un] if un in stats_list[4].keys() else 0,
                    ips_in_ls_count,
                    ips_beyond_project,
                    len(stats_list[2][un]) if (
                        un in stats_list[2].keys()) else 0,
                    sfs_7_day_count,
                    sfs_30_day_count,
                    sfs_90_day_count,
                    sfs_180_day_count,
                    sfs_365_day_count
                ]
                if(self.sfs_api is False):
                    del csv_user_data[4]

                reportwriter.writerow(csv_user_data)


""" cli args/control """
parser = argparse.ArgumentParser()
parser.add_argument('project', help='A valid Wikimedia project \
                    (e.g. en.wikipedia)',
                    type=str)
parser.add_argument('-d', '--date', default='30d',
                    help='A date interval for the request: \
                    [see validate_request_date_range() for examples]',
                    type=str)
parser.add_argument('-r', '--raw', action='store_true',
                    default=False,
                    help='Do not include stats header/summary')
parser.add_argument('--sfsapi', action='store_true',
                    default=False,
                    help='Gather data from the SFS API')
args, unknown = parser.parse_known_args()

""" Instantiate and send """
gt = SpamAccountStats(
    args.project,
    args.date,
    args.raw,
    args.sfsapi
)
