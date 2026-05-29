import logging
from io import StringIO
import os

log_buffer = StringIO()

log_handler = logging.StreamHandler(log_buffer)

log_handler.setFormatter(
    logging.Formatter('%(levelname)s:%(message)s')
)

root_logger = logging.getLogger()

root_logger.setLevel(logging.INFO)

root_logger.addHandler(log_handler)

logging.getLogger('werkzeug').handlers = []

def cleanup_files(files):

    for file in files:

        try:

            if file and os.path.exists(file):
                os.remove(file)

        except Exception as e:
            logging.error(f"Cleanup error: {e}")