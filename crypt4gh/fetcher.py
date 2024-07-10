
import logging
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

LOG = logging.getLogger(__name__)

class Fetcher():
    
    __slots__ = ('response')

    def __init__(self, link):
        try:
            LOG.info('Fetching URI: %s', link)
            self.response = urlopen(link)
        except HTTPError as e:
            LOG.error('%r', e)
            raise ValueError(f'HTTP Error {e.code}')
        except URLError as e:
            LOG.error('%r', e)
            raise ValueError(e.reason)

    def read(self, size=-1):
        if size < 0:
            return self.response.read()
        return self.response.read(size)

    def close(self):
        return self.response.close()
        
    def seek(self, offset, whence):
        return self.response.seek(offset, whence=whence)

