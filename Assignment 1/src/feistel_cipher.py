#!/usr/bin/python

##############################################################################
# @file    FeistelCipher.py
# @author  Stian Sandve
# @version V1.0.0
# @date    9-Sep-2014
# @brief   This class provides encryption and depcryption functions for
# Feistel cipher.
###############################################################################

import ConfigParser
import time
import logging


class FeistelCipher(object):

    def __init__(self):
        self.logger = None
        self.init_logging()

    def init_logging(self):
        cfg = ConfigParser.ConfigParser()
        cfg.read('config.cfg')
        logging_enabled = cfg.getboolean('Logging', 'enabled')
        logging_level = cfg.get('Logging', 'level')
        log_to_file = cfg.getboolean('Logging', 'log_to_file')
        log_to_console = cfg.getboolean('Logging', 'log_to_console')

        if logging_level.lower() == "critical":
            level = logging.CRITICAL
        elif logging_level.lower() == "info":
            level = logging.INFO
        elif logging_level.lower() == "warning":
            level = logging.WARNING
        elif logging_level.lower() == "error":
            level = logging.ERROR
        else:
            level = logging.DEBUG

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(level)
        log_formatter = logging.Formatter("[%(levelname)s]: %(message)s")

        if log_to_file:
            # Truncate existing log.
            with open('feistel_cipher.log', 'w'):
                pass
            file_handler = logging.FileHandler("feistel_cipher.log")
            file_handler.setFormatter(log_formatter)
            self.logger.addHandler(file_handler)
        if log_to_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(log_formatter)
            self.logger.addHandler(console_handler)

        if not logging_enabled:
            logging.disable(logging.CRITICAL)

        self.logger.info("\n---------- Logging started %s, %s ----------\n",
                         time.strftime("%d.%m.%y"), time.strftime("%H:%M:%S"))