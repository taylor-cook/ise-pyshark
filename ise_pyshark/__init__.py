from . import _version
import logging

__version__ = _version.get_versions()['version']

from .endpointsdb import endpointsdb
from .ouidb import ouidb
from .parser import parser
from .apis import apis
from .eps import eps

logger = logging.getLogger(__name__)
from . import _version
__version__ = _version.get_versions()['version']
