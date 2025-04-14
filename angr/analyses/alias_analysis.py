import logging

from enum import Enum
from . import Analysis




_l = logging.getLogger(name=__name__)


class AliasType(Enum):
    NoAlias = 0
    MayAlias = 1
    MustAlias = 2