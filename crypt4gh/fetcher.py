import logging
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

LOG = logging.getLogger(__name__)

#
# Works for http URI but also of the form file:///absolute/path
#
class URLFetcher():
    
    __slots__ = ('response')

    def __init__(self, link):
        try:
            self.response = urlopen(link)
            LOG.debug('URI Code: %s', self.response.status)
            LOG.debug('URI Info: %d headers', len(self.response.headers))
            for k,v in self.response.headers.items():
                LOG.debug('   * %s: %s', k, v)
        except HTTPError as e:
            LOG.error('%r', e)
            raise ValueError(f'HTTP Error {e.code}')
        except URLError as e:
            LOG.error('%r', e)
            raise ValueError(e.reason)

    # def read(self, size=-1):
    #     if size < 0:
    #         return self.response.read()
    #     return self.response.read(size)

    def readinto(self, data):
        n = self.response.readinto(data)
        # LOG.debug('fetched: %s', data[:n])
        return n

    def close(self):
        return self.response.close()


def fetcher(link):

    LOG.info('Fetching URI: %s', link)

    if link.startswith('s3://'):
        return NotImplementedError('S3 URI require more thoughts ... and parameters')

    return URLFetcher(link)
