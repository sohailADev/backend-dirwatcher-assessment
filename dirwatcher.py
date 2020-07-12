import signal
import time
import sys
import os
import argparse
import logging

exit_flag = False
global_files = {}
logger = logging.getLogger(__name__)


def dir_watcher(dir, magic_word, ext):
    # looking for files in dir
    global global_files
    list_of_files = os.listdir(dir)
    detect_added_files(list_of_files, dir, ext)
    detect_removed_files(list_of_files, dir)
    for file in list_of_files:
        global_files[file] = scan_single_file(
            file, dir, global_files[file], magic_word, ext)


def scan_single_file(file, dir, start_line, magic_word, ext):
    list_of_lines = []
    line_no = 0
    with open(f"{dir}/{file}", "r") as myfile:
        for line in myfile:
            list_of_lines.append(line.strip())
        for line_no, line in enumerate(list_of_lines):
            if line_no >= start_line:
                if magic_word in line:
                    logger.info(
                        f"{magic_word} found in line number {line_no+1}"
                        f"in file named {file}"
                    )
    return line_no + 1


def detect_added_files(list_file, dir, ext):
    global global_files
    for file in list_file:
        if file.endswith(ext) and file not in global_files:
            logger.info(f'File {file}  added  to dirctory {dir}')
            global_files[file] = 0


def detect_removed_files(list_file, dir):
    global global_files
    for file in list(global_files):
        if file not in list_file:
            logger.info(f'File {file} has been  removed from {dir}')
            del global_files[file]


def signal_handler(sig_num, frame):
    """
    This is a handler for SIGTERM and SIGINT. Other signals can be mapped here as well (SIGHUP?)
    Basically, it just sets a global flag, and main() will exit its loop if the signal is trapped.
    :param sig_num: The integer signal number that was trapped from the OS.
    :param frame: Not used
    :return None
    """
    # log the associated signal name
    logger.warning('Received ' + signal.Signals(sig_num).name)
    logger.error("Program is interupted by user with keyboard ")
    global exit_flag
    exit_flag = True


def create_parser():
    """Creates an argument parser object."""
    parser = argparse.ArgumentParser()
    parser.add_argument('dir', help='Directory path to watch')
    parser.add_argument('magic_word', help='String to watch for')
    parser.add_argument(
        '-e', '--ext', help='Text file extension to watch e.g. .txt, .log', default=".txt")
    parser.add_argument('-i', '--interval',
                        help='Number of seconds between polling', default=1)

    return parser

# def long_running_program():
#     while exit_flag == False:


def main(args):
    """Parses args, scans for URLs, gets images from URLs."""
    LOG_FORMAT = "%(asctime)2s %(name)2s %(levelname)-8s%(message)s"
    logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)

    parser = create_parser()
    if not args:
        parser.print_usage()
        sys.exit(1)
    parsed_args = parser.parse_args(args)
    polling_interval = int(parsed_args.interval or 1)
    watching_dir = parsed_args.dir
    file_ext = parsed_args.ext
    magic_word = parsed_args.magic_word
    start_time = time.time()
    logger.info(
        f"\n------------------------------------------------------------------"
        f"\n       Running {__name__}                                         "
        f"\n       Started on {start_time:.1f}                                    "
        f"\n------------------------------------------------------------------"
    )
    logger.info(f'looking directory in: {watching_dir},'
                f'for file extension {file_ext},'
                f'for Magic word{magic_word}'
                f'for every interval {polling_interval}'
                )

    # Hook into these two signals from the OS
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    # signal.signal(signal.SIGKILL, signal_handler)
    # Now my signal_handler will get called if OS sends
    # either of these to my process.
    while not exit_flag:
        try:
            time.sleep(polling_interval)
            # call  directory watching function
            dir_watcher(watching_dir, magic_word, file_ext)
        except KeyboardInterrupt:

            logger.error("Program is inturpeted by keyboard")
            break
        except Exception:
            # This is an UNHANDLED exception
            # Log an ERROR level message here
            logger.error(f"No such directory as {watching_dir}")

        # put a sleep inside my while loop so I don't peg the cpu usage at 100%
        time.sleep(polling_interval)

    # final exit point happens here
    # Log a message that we are shutting down
    # Include the overall uptime since program start
    end_time = time.time() - start_time
    logger.info(
        f"\n"
        f"----------------------------------------------------------------"
        f"       Stopped  {__file__}                                      "
        f"       Started on {end_time}                                    "
        f"----------------------------------------------------------------"
    )
    logger.shutdown()


if __name__ == '__main__':
    main(sys.argv[1:])
