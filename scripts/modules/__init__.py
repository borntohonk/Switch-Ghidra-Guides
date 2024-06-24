import logging

def logging_configuration(logger):
    sh_formatter = logging.Formatter(fmt='%(asctime)s %(process)d %(name)s %(levelname)s %(funcName)s %(message)s',
                                     datefmt='%d-%b-%y %H:%M:%S')
    sh = logging.StreamHandler()
    sh.setLevel(level=logging.INFO)
    sh.setFormatter(sh_formatter)

    logger.setLevel(logging.DEBUG)
    logger.addHandler(sh)
