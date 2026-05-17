"""
API Routes Package
==================
Contains all API route modules for the ACDS backend.
"""

from . import auth
from . import threats
from . import dashboard
from . import feedback
from . import reports
from . import testing
from . import demo
from . import malware
from . import malware_demo
from . import logs

__all__ = ['auth', 'threats', 'dashboard', 'feedback', 'reports', 'testing', 'demo', 'malware', 'malware_demo', 'logs']
