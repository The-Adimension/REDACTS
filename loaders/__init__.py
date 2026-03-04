"""REDACTS Loaders module - Source import from ZIP, FTP, HTTP, local."""

from .zip_loader import ZipLoader
from .ftp_loader import FTPLoader
from .http_loader import HTTPLoader
from .local_loader import LocalLoader
from .base import BaseLoader, detect_loader, detect_redcap_root
