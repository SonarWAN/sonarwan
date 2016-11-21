import logging

logger = logging.getLogger('SonarWAN')
logger.setLevel(logging.INFO)

# create file handler
fh = logging.FileHandler('sonarwan.log')
fh.setLevel(logging.INFO)

# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

# add the handler to logger
logger.addHandler(fh)
