import logging
from colorlog import ColoredFormatter


LOG_LEVEL = logging.DEBUG
LOG_FORMAT_CONSOLE = "%(log_color)s%(asctime)s [%(levelname)-5.5s] %(message)s"
LOG_FORMAT_FILE = "%(asctime)s [%(levelname)-5.5s] %(message)s"
logging.root.setLevel(LOG_LEVEL)

formatter_console = ColoredFormatter(
	LOG_FORMAT_CONSOLE,
	datefmt=None,
	reset=True,
	log_colors={
		'DEBUG':    'cyan',
		'INFO':     'green',
		'WARNING':  'bold_yellow',
		'ERROR':    'bold_red',
		'CRITICAL': 'red,bg_white',
	},
	secondary_log_colors={},
	style='%'
)

handler_stream = logging.StreamHandler()
handler_stream.setLevel(LOG_LEVEL)
handler_stream.setFormatter(formatter_console)

log = logging.getLogger(__name__)
log.setLevel(LOG_LEVEL)
log.addHandler(handler_stream)