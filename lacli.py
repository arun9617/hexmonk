#!/usr/bin/env python
###############################################################################
# File              : lacli.py
# Description       : Script to provide log information
# Auther            : Chandra Shekhar Mahto
# Date              : 20-Mar-2020
# version           : 1.13
# Python version    : 2.7 or higher
# Notes             : This script is designed to
# History
#
# Date		    Comments				        By
# ------------	-------------------------------------------	------------
# 06-May-2020	before Release        				shekhar
# 08-May-2020   Remove child request program from main program
# 15-Jun-2020   Child process will be run parallel   shekhar
# 17-Jun-2020   ver(1.11 ) '_' will be allowed
#               in ticket number
# 23-Jun-2020   Added wls cluster
###############################################################################
import sys
import os
import re
from datetime import datetime, timedelta
import time
import socket
import getpass
import platform
import argparse
import threading
# from collections import OrderedDict

# script version
__version__ = 1.12
# base dir
base_dir = os.path.dirname(__file__)
class_dir = os.path.join(base_dir, 'py')
# default start time will be n hour before
default_hour = 24
timezone = time.strftime('%Z')
require_hostname = 'sacchoria'
require_username = 'mc_admin'
# assuming user will go via menu
is_cmdline = False
#######
# conf file information : start
# in this python version, OrderedDict is not working properly so used list.
list_main_menu = [
                    ['p2t', 'p2t.conf'],
                    ['patch', 'patching.conf'],
                    ['update', 'update.conf'],
                    ['provision', 'provision.conf'],
                    ['apps [fa, bi, ohs, idm]', 'list_appslog_option'],
                    ['wls_cluster', 'list_cluster_option'],
                    ['db [db, rman]', 'list_db_option'],
                    ['os [apps, db, infra]', 'list_os_option']
                ]

list_appslog_option = [
                        ['fa', 'apps.fa.conf'],
                        ['idm', 'apps.idm.conf'],
                        ['bi', 'apps.bi.conf'],
                        ['ohs', 'apps.ohs.conf'],
                        ['all', 'apps.all.conf']
                    ]

list_cluster_option = [
                        ['AdminServer', 'wls_cluster.AdminServer.conf'],
                        ['ESS_SOA', 'wls_cluster.ESS_SOACluster.conf'],
                        ['MW', 'wls_cluster.MWCluster.conf'],
                        ['SEMSearch', 'wls_cluster.SEMSearchCluster.conf'],
                        ['Service', 'wls_cluster.ServiceCluster.conf'],
                        ['SharedServices', 'wls_cluster.SharedServicesCluster.conf'],
                        ['Singleton', 'wls_cluster.SingletonCluster.conf'],
                        ['SupplyPlanningEngine', 'wls_cluster.SupplyPlanningEngineCluster.conf'],
                        ['UI', 'wls_cluster.UICluster.conf'],
                        ['bi', 'wls_cluster.bi_cluster.conf'],
                        ['bip', 'wls_cluster.bip_cluster.conf'],
                        ['ods', 'wls_cluster.cluster_ods.conf'],
                        ['oam', 'wls_cluster.oam_cluster.conf']
                    ]

list_db_option = [
                    ['db', 'db.db.conf'],
                    ['rman', 'db.rman.conf'],
                    ['all', 'db.all.conf']
                ]

list_os_option = [
                    ['apps', 'os.apps.conf'],
                    ['db', 'os.db.conf'],
                    ['infra', 'os.infra.conf'],
                    ['all', 'os.all.conf']
                ]

# conf file information : end


def check_prereq():
    # checking python version
    try:
        py_version = float(platform.python_version()[:3])
        if py_version < 2.7:
            print('Python version should be greater than 2.7')
            sys.exit(1)
        if py_version >= 3.0:
            raw_input = input
    except SystemExit:
        sys.exit(1)
    except Exception:
        print('Error : \n{0}'.format(sys.exc_info()))
        sys.exit(1)

    # validate if script is running form sachoria server
    if not re.match(require_hostname, socket.gethostname()):
        print('Current server : {0}\nFAILED: Script has to run from {1} server'
              .format(socket.gethostname(), require_hostname))
        sys.exit(1)

    # validate if script is running from mc_admin user
    if getpass.getuser() != require_username:
        print('Current user : {0}\nFAILED : Script has to run from {1} user.'
              .format(getpass.getuser(), require_username))
        sys.exit(1)


def validate_ticket(ticket_no='', max_len=15):
    ''' Function to validate ticket number
    Parameter:
        ticket_no: Ticket number
        max_len: maximum length of ticket_no
    Return:
        True/False : True then valid ticket else False
        Default: False
    '''
    try:
        ticket_no = ticket_no.strip()
        if ticket_no == '':
            log.debug('Ticket# is blank')
            return ''

        re_result = re.findall(r'[(\w)-]+', ticket_no)
        if re_result:
            if ticket_no.startswith('-') or ticket_no.endswith('-') \
                    or ticket_no.startswith('_') or ticket_no.endswith('_') \
                    or len(re.findall('-', ticket_no)) > 1 \
                    or len(re.findall('_', ticket_no)) > 1 \
                    or re.search(r'_-|-_', ticket_no) \
                    or (len(ticket_no) != len(re_result[0])) \
                    or len(ticket_no) > max_len:
                print('''FAILED : invalid ticket number
                      \rHelp-
                      \r\t1. ticket should contains alphanumeric, '_', '-'
                      \r\t2. maximum length of the ticket should be 15 char
                      ''')
                return False
            else:
                log.debug('ticket number :{0}'.format(ticket_no))
                return ticket_no
        else:
            log.debug('Unable to parse ticket# {0}'.format(ticket_no))
            return False
    except Exception:
        return False

    return False


def get_cmd_config(all_conf, cmd_list=[], menu_list=[]):
    '''Function to return config file
    Parameter :
        all_conf : all_config file for multi option choice
        cmd_list : list of config file got from command line
        menu_list : list of option files from menu options
    Return:
        config_files : required config files
    '''
    try:
        config_files = [x[1] for x in menu_list for y in cmd_list if y in x]
        option = all_conf.split('.')[0]
        if len(config_files) != len(cmd_list):
            print('ERROR: {0} option is incorrect.'.format(option))
            raise
        if all_conf in config_files:
            config_files = [all_conf]
    except Exception as e:
        print('failed list config files line#{0} {1} {2}'.format(
                        sys.exc_info()[-1].tb_lineno, type(e).__name__, e))
        sys.exit(1)
    else:
        return config_files

# checking command line paramenter : start


def read_cmd_prameter():
    global is_cmdline
    # global pod_list

    script_usages = '''{0} [-h] [--t T] [--pod POD]
      [--p2t | --patch | --update | --provision | --db db,rman,all
      | --apps fa,bi,idm,ohs,all | --os apps,db,infra,all
      | --wls_cluster cluster_name]
      [--st ST] [--et ET] [--err [ERR]] [--zip]
      [--debug]

      {0} --listpod
    '''.format(sys.argv[0])
    parser = argparse.ArgumentParser(description='Script will help you to navigate logfiles for troubleshooting',
                                     usage=script_usages)
    main_group = parser.add_mutually_exclusive_group()
    main_group.add_argument('-v', '--version', action='store_true',
                            help='show script version')
    main_group.add_argument('--listpod', action='store_true',
                            help='List all available fusion pods')
    main_group.add_argument('--pod', type=lambda x: str(x).split(','),
                            help='POD name where script will run eg; pod1,pod2')

    group = parser.add_mutually_exclusive_group()
    parser.add_argument('--t', help='Reference Ticket number [jira/SR/Bug]')
    group.add_argument('--p2t', action='store_const', const='p2t.conf',
                       help='P2T activity')
    group.add_argument('--patch', action='store_const', const='patching.conf',
                       help='Patching ')
    group.add_argument('--update', action='store_const', const='update.conf',
                       help='Update')
    group.add_argument('--provision', action='store_const',
                       const='provision.conf', help='provision')
    group.add_argument('--db', type=lambda x: str(x).split(','), nargs='?',
                       const='all', help='database {db, rman, all}')
    group.add_argument('--apps', type=lambda x: str(x).split(','), nargs='?',
                       const='all', help='apps logs can have mulitple choice with comma separated {fa,bi,idm,ohs,all} ')
    group.add_argument('--os', type=lambda x: str(x).split(','), nargs='?', const='all',
                       help='OS logs can have mulitple choice with comma separated {apps,db,infra,all} ')
    group.add_argument('--wls_cluster', type=lambda x: str(x).split(','), nargs='?', const='AdminServer',
                       help='weblogic cluster logs can have mulitple choice with comma separated {AdminServer,ESS_SOA,bi etc} ')
    parser.add_argument('--st', help='start time  in DDMMYYYY24HHMM')
    parser.add_argument('--et', help='End time DDMMYYYY24HHMM')
    parser.add_argument('--err', help='Error code that need to be search. If more than one word then use double quote eg "help me". It is not case sensitive')
    parser.add_argument('--zip', action='store_true',
                        help='Zip files which got from output')
    parser.add_argument('--debug', action='store_true',
                        help='run script in debug mode. Suggested only for troubleshooting')

    user_args = parser.parse_args()
    # show script version
    if user_args.version:
        print('''----script version----
              \rlacli: {0}
              \rlogmaster: {1}
              \rchildrequest: {2}'''
              .format(__version__, user1.__version__,
                      ChildRequest().__version__))
        sys.exit(0)

    total_list = [x for x in vars(user_args) if vars(user_args)[x]]
    # return if no command line input got
    if total_list == [] or ('listpod' in total_list and len(total_list) == 1):
        return user_args.t, user_args.pod, [], user_args.st, user_args.et, user_args.err, user_args.zip, user_args.listpod, user_args.debug
    elif 'listpod' in total_list and len(total_list) > 1:
        print('listpod should not run along with any other options.')
        sys.exit(1)
    elif 'pod' in total_list and len(total_list) >= 1:
        is_cmdline = True
        if not user_args.apps:
            user_args.apps = ['fa']
        if not user_args.err:
            user_args.err = '__skip_error_code__'
        if not user_args.t:
            user_args.t = ''
    else:
        print('You must provide POD to execute in command line.')
        sys.exit(1)

    # construct config_file
    config_files = [x for x in [user_args.p2t, user_args.patch,
                                user_args.update, user_args.provision] if x]
    if config_files == []:
        if user_args.os:
            config_files = get_cmd_config('os.all.conf', user_args.os,
                                          list_os_option)
        elif user_args.db:
            config_files = get_cmd_config('db.all.conf', user_args.db,
                                          list_db_option)
        elif user_args.wls_cluster:
            config_files = get_cmd_config('wls_cluster.AdminServer.conf',
                                          user_args.wls_cluster,
                                          list_cluster_option)
        else:
            config_files = get_cmd_config('apps.all.conf',
                                          user_args.apps, list_appslog_option)

    return user_args.t, user_args.pod, config_files, user_args.st, user_args.et, user_args.err, user_args.zip,  user_args.listpod, user_args.debug
# checking command line paramenter : end


def print_listpod():
    '''print list of pods '''
    print('getting POD details. Please wait...')
    user1.pod_list = user1.get_pod_list(refresh=True)
    for x in user1.pod_list:
        print(x)
    sys.exit(0)
    # return True


def validate_user_pod(user_pods):
    ''' validate user pod '''
    refresh_pod = False
    for x in user_pods:
        if x not in user1.pod_list:
            print('WARNING : {0} is not valid pod'.format(x))
            print('Refreshing POD list once again. Please wait ..')
            refresh_pod = True
            break

    if refresh_pod:
        user1.pod_list = user1.get_pod_list(refresh=True)

        for x in user_pods:
            if x not in user1.pod_list:
                print('ERROR : {0} is not valid pod'.format(x))
                sys.exit(1)
    return True

# pod menu : start


def podname_menu():
    '''function to validate user input for POD '''
    exit_script = False
    while True:
        print('List of available POD :')
        user_pod = []
        counter = 1
        for t_pod_list in user1.pod_list:
            print('{0}\t{1}'.format(counter, t_pod_list))
            counter = counter + 1

        if counter == 1:
            print('No evironment found !!!')
            sys.exit(1)
        try:
            print('{0}\texit from script'.format(counter))
            user_pod = raw_input('Enter POD default[{0}]:'.format(counter))
            if str(user_pod).strip() == '':
                exit_script = True
                break
            else:
                user_pod = str(user_pod).split(',')
                user_pod = [int(x) for x in user_pod if int(x)]

            try:
                if counter in user_pod and len(user_pod) > 1:
                    print('exit should not be used along with other input')
                    raise
                if counter in user_pod:
                    exit_script = True
                    break
                user_pod = [user1.pod_list[int(x)-1]
                            for x in user_pod if int(x)]

                break
            except Exception:
                raise
        except KeyboardInterrupt:
            sys.exit(1)
        except Exception:
            print('Invalid input. Retry once again.')
            log.debug('Invalid input. Retry once again. Error :-\n{0}'
                          .format(sys.exc_info()))

    if exit_script:
        sys.exit(0)
    return user_pod
#  pod menu : stop

# return config from user input used by menu : start


def get_config(list_opts, counter=1, multiSelect=False):
    '''function to return log config files (.conf)
    Parameter :
        list_opts : list of menu option defined
        counter : counter for tracking menu count
        multiSelect : True if multi selected is allowed else False
    Return :
        config_files : list of log config files (.conf)
    '''
    config_files = []
    try:
        user_choice = raw_input('Enter your choice [{0}] :'.format(counter))
        if str(user_choice).strip() == '':
            sys.exit(0)
        if multiSelect:
            user_choice = [int(x) for x in str(user_choice).split(',')
                           if int(x)]
        else:
            user_choice = int(user_choice)
            user_choice = [int(x) for x in str(user_choice).split(',')
                           if int(x)]
    except SystemExit:
        sys.exit(1)
    except Exception:
        log.warning('Invalid choice. Error:- {0}'.format(sys.exc_info()))
        print('Invalid choice. Please retry')
        return config_files
    # return blank list

    # check if back or exit option used: start
    if len(user_choice) > 1:
        if counter in user_choice or counter - 1 in user_choice:
            print('Back or exit not allowed with other options. Please retry!')
            return config_files

    if counter in user_choice:
        sys.exit(0)
    if counter - 1 in user_choice:
        config_files.append('back_menu')
        return config_files
    # check if back or exit option used: ebd
    # return user config files : start
    try:
        log.debug('Counter value : {0} user_input : {1}'
                      .format(counter, user_choice))
        config_files = [list_opts[x-1][1] for x in user_choice
                        if list_opts[x-1]]
        return config_files
    except SystemExit:
        sys.exit(1)
    except Exception:
        log.warning('Invalid choice. Please retry . {0}'
                        .format(sys.exc_info()))
        # return blank list
        return config_files

    return config_files
# return config from user input used by menu : end

# main menu : start


def main_menu(podname_list):
    ''' takes parameter of pod_name and return pod name
    and task file name to be executed '''
    configfile_list = []
    # loop through and return pod name and required config file
    while True:
        print('='*50 + '\n' + str(podname_list) + '\n' + '='*50)
        # print main menu list : start
        counter = 1
        for x in list_main_menu:
            print('{0}  {1}'.format(counter, x[0]))
            counter = counter + 1

        print('{0}  Return to previous menu'.format(counter))
        counter = counter + 1
        print('{0}  exit from script'.format(counter))
        # print main menu list : end

        configfile_list = get_config(list_main_menu, counter,
                                     multiSelect=False)
        if configfile_list == []:
            continue
        elif configfile_list[0] == 'back_menu':
            podname_list = podname_menu()
            continue
        elif not re.search(r'\.conf', configfile_list[0]):
            if configfile_list[0] == 'list_appslog_option':
                list_options = list_appslog_option
            elif configfile_list[0] == 'list_db_option':
                list_options = list_db_option
            elif configfile_list[0] == 'list_cluster_option':
                list_options = list_cluster_option
            elif configfile_list[0] == 'list_os_option':
                list_options = list_os_option
            else:
                continue

            podname_list, configfile_list = sub_menu(podname_list,
                                                     list_options)
            if configfile_list[0] == 'back_menu':
                continue
            else:
                return podname_list, configfile_list
        else:
            return podname_list, configfile_list
# main menu: end


# logic for os_menu: stat


def sub_menu(podname_list, list_options):
    ''' Function used on sub menu
    Parameter :
        podname_list : list of pods
        list_options : list of sub menu options
    Return:
        podname_list : list of pods
        configfile_list : list of log config files
    '''
    while True:
        counter = 1
        print('='*50 + '\n' + str(podname_list) + '\n' + '='*50)
        for x in list_options:
            print('{0}  {1}'.format(counter, x[0]))
            counter = counter + 1
        print('{0}  return to previous menu'.format(counter))
        counter = counter + 1
        print('{0}  exit from script'.format(counter))
        # print appslog menu list: end
        configfile_list = get_config(list_options, counter,
                                     multiSelect=True)

        if configfile_list == []:
            continue
        else:
            t_config_list = [x for x in configfile_list
                             if re.search(r'all.conf', x)]
            if t_config_list != []:
                configfile_list = t_config_list

            return podname_list, configfile_list


def input_datetime(p_comment='start', p_cmdline_time='',
                   p_start_time=datetime.now(), reverse_check=False):
    '''user input for start time and end time . reverse_check=True
        then it will check if p_start_time should be future date
        from input_date return will be valid datetime
        input_datetime(default=current time, reverse_check = default False)'''

    while True:
        # check if time is coming from command line: start
        if p_cmdline_time != '':
            log.debug('Cmd line: {0} time:{1}'.format(p_comment,
                                                      p_cmdline_time))
            try:
                try:
                    p_cmdline_time = datetime.strptime(p_cmdline_time, '%d%m%Y%H%M')
                except:
                    p_cmdline_time = datetime.strptime(p_cmdline_time, '%d%m%Y')
                p_cmdline_time = datetime.strftime(p_cmdline_time, '%d-%b-%Y %H:%M')
                p_cmdline_time = user1.validate_date(p_cmdline_time,
                                                     p_start_time,
                                                     reverse_check)
                if p_cmdline_time:
                    log.debug('Return value:{0}'.format(p_cmdline_time))
                    return p_cmdline_time
                else:
                    raise
            except Exception:
                log.error('Error on command line {0} time: {1}\nError: {2}'
                          .format(p_comment, p_cmdline_time, sys.exc_info()))
                print('Error on command line {0} time. Format is wrong'
                      .format(p_comment))
                sys.exit(1)
        # check if time is coming from command line: end
        # currrent time
        current_time = datetime.now()
        if p_comment == 'start':
            current_time = current_time - timedelta(hours=default_hour)
        # format time on dd-mon-yyyy HH:MM
        current_time_format = current_time.strftime('%d-%b-%Y %H:%M')
        try:
            user_input_time = raw_input('Enter {0} time [{1}] Default [{2}]:'
                                        .format(p_comment, timezone,
                                                current_time_format))
            # if input is blank
            if user_input_time.strip() == '':
                user_input_time = current_time_format
            try:
                user_input_time = datetime.strptime(user_input_time, '%d-%b-%Y')
                user_input_time = datetime.strftime(user_input_time, '%d-%b-%Y %H:%M')
            except:
                pass
            log.debug('User input value: {0}'.format(user_input_time))
            user_input_time = user1.validate_date(user_input_time,
                                                  p_start_time,
                                                  reverse_check)
            if user_input_time:
                log.debug('Return value:{0}'.format(user_input_time))
                return user_input_time
        except KeyboardInterrupt:
            sys.exit(1)
        except Exception:
            log.critical(sys.exc_info())
            print('Invalid Input. Please retry')
# validate user input datetime: start


if __name__ == '__main__':
    # os.system('clear')
    # system pre-check
    check_prereq()

    # import logmaster class: star
    if os.path.isdir(class_dir):
        try:
            sys.path.append(class_dir)
            from logmaster import LogMaster
            from childrequest import ChildRequest
            user1 = LogMaster()
            # import logger module
            logger_py = os.path.join(class_dir, 'logger.py')

            return_ticket_no, pod_name_list, return_config_file, start_time, \
                end_time, error_code, zip_require, provide_listpod, \
                debug_require = read_cmd_prameter()

            if os.path.isfile(logger_py):
                import logger
                if debug_require:
                    user1.log_level = 10

                # create empty file and give 777 permision
                open(user1.master_logging_file, mode='w').close()
                os.chmod(user1.master_logging_file, 0o777)

                log = logger.get_log_writter(user1.master_logging_file,
                                             user1.log_level)
                user1.setLogging()
            else:
                print('failed: {0} not exists'.format(logger_py))
                sys.exit(1)

        except Exception as e:
            print('failed to load master class line#{0} {1} {2}'.format(
                            sys.exc_info()[-1].tb_lineno, type(e).__name__, e))
            sys.exit(1)

        # check permission of files
        user1.check_permission()
        # check if required config file exists or not
        user1.check_conf_permission(list_main_menu, list_appslog_option,
                                    list_db_option, list_cluster_option,
                                    list_os_option)
    else:
        log.critical('Class directory does not exists {0}'.format(class_dir))
        sys.exit(1)
    # import logmaster class: end
    # start clearnup
    threading.Thread(target=user1.cleanup_logdir).start()

    log.debug('Return value from argparser Ticket:{0} podname: {1}  config_file:{2} start_time:{3} end_time:{4} Error_code:{5} Zip require: {6} '.format(return_ticket_no, pod_name_list, return_config_file, start_time, end_time, error_code, zip_require))

    # setting child debug file
    try:
        open(user1.logging_file, 'w').close()
        os.chmod(user1.logging_file, 0o777)
    except Exception:
        log.error('not able to create child debug file:{0} {1}'
                  .format(user1.logging_file, sys.exc_info()))
        sys.exit(1)

    log.debug('Master debug: {0} child_debug:{1}'
              .format(user1.master_logging_file, user1.logging_file))

    # validate ticket_no
    if return_ticket_no is not None:
        return_ticket_no = validate_ticket(return_ticket_no)
        # if return False then exit from script
        if return_ticket_no or return_ticket_no == '':
            user1.ticket_no = return_ticket_no
        else:
            print('Failed ticket is not valid {0}'.format(return_ticket_no))
            sys.exit(1)

    if provide_listpod:
        print_listpod()
    # get pod list
    print('getting POD details. Please wait...')
    user1.pod_list = user1.get_pod_list()

    if pod_name_list:
        validate_user_pod(pod_name_list)
    if zip_require:
        user1.zip_require = zip_require

    if is_cmdline is False:
        # jira input and validation: start
        while True:
            try:
                user1.ticket_no = raw_input('Enter Reference ticket#:').strip()
            except KeyboardInterrupt:
                sys.exit(1)
            except Exception:
                user1.ticket_no = ''
                print('Tracking ticket is null')
                break
            else:
                user1.ticket_no = validate_ticket(user1.ticket_no)
                if user1.ticket_no or user1.ticket_no == '':
                    break

        # taking pod name from user: start
        pod_name_list = podname_menu()
    # getting unique pod list
    pod_name_list = list(set(pod_name_list))
    ####
    while True:
        if is_cmdline is False:
            # returning confing files
            pod_name_list, return_config_file = main_menu(pod_name_list)

            # start and end time: start
            start_time = input_datetime()
            end_time = input_datetime(p_comment='End', p_start_time=start_time,
                                      reverse_check=True)

            try:
                error_code = raw_input('Enter error string if any:')
                if str(error_code).strip() == '':
                    error_code = '__skip_error_code__'
            except KeyboardInterrupt:
                sys.exit(1)
            except Exception:
                error_code = '__skip_error_code__'

            while True:
                try:
                    zip_require = raw_input('Do you want to zip file {y/n} [n]:')
                    zip_require = zip_require.strip()
                    if zip_require == '':
                        user1.zip_require = False
                        break
                    if re.match('yes|YES|Y|y|Yes', zip_require):
                        user1.zip_require = True
                        break
                    elif re.match('No|n|NO|no', zip_require):
                        user1.zip_require = False
                        break
                    else:
                        print('Invalid choice. Please retry')
                except KeyboardInterrupt:
                    sys.exit(1)
                except:
                    print('Invalid choice . {0}'.format(sys.exc_info()[1]))

            log.debug('POD name: {0} \n start_time: {1} \n end_time:{2} \n error_code: {3} \n config_file:{4}'.format(pod_name_list, start_time, end_time, error_code, return_config_file))

        else:
            if start_time is None:
                start_time = datetime.now() - timedelta(hours=default_hour)
            else:
                start_time = input_datetime(p_cmdline_time=start_time)

            if end_time is None:
                end_time = datetime.now()
                end_time = datetime.strftime(end_time, '%d%m%Y%H%M')
            end_time = input_datetime(p_comment='End', p_cmdline_time=end_time,
                                      p_start_time=start_time,
                                      reverse_check=True)

        if len(pod_name_list) > 1 or len(return_config_file) > 1:
            print_output = False
            multiPod = True
        else:
            print_output = False
            multiPod = False
        # setting backup to work done to 0
        user1.total_exec = len(pod_name_list)
        user1.total_work_done = 0
        # zip related parameter
        if user1.zip_require is None:
            user1.zip_require = False
        # setting user selected option
        user1.set_option_selected(return_config_file, list_main_menu,
                                  list_appslog_option, list_os_option,
                                  list_cluster_option, list_db_option)

        print('Selected : {0}'.format(user1.selected_opt))
        print('{0:<10} {1:<15} {2:<10} {3:<10} {4:<10} {5}'
              .format('pod', 'node', 'start', 'status', 'elapsed', 'end'))

        for podname in pod_name_list:
            zipname = '{0}_{1}_{2}.zip'.format(podname, user1.ticket_no, datetime.strftime(datetime.now(), '%d%m%Y%H%M%S'))
            zipname = os.path.join(user1.log_dir, zipname)
            user1.zip_file_list.append(zipname)
            # fixiing error code with pipe and space issue
            if re.findall(r'\|| ', error_code):
                error_code = re.sub(r'\|', '_pipe_', error_code)
                error_code = re.sub(r' ', '_space_', error_code)

            log.debug('''Return conf: {0}
                          pod name: {1}
                          start_time: {2}
                          end_time: {3}
                          error_code:{4}
                          multiPod: {5}
                          print_target:{6}
                          Zip require: {7}
                          zipname: {8}'''
                      .format(return_config_file, podname, start_time,
                              end_time, error_code, multiPod, print_output,
                              user1.zip_require, zipname))

            user1.submit_child_req(return_config_file, podname, start_time,
                                   end_time, zipname, p_error_code=error_code,
                                   multi_pod=multiPod,
                                   print_target=print_output)

        # exit if user say
        if is_cmdline:
            sys.exit(0)
#
