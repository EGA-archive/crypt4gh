import logging
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

import boto3

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

    def read(self, size=-1):
        if size < 0:
            return self.response.read()
        return self.response.read(size)

    def readinto(self, data):
        return self.response.readinto(data)

    def close(self):
        return self.response.close()


#
# s3:// URI 
#
class S3Fetcher():
    
    __slots__ = ('client',
                 'bucket',
                 'name',
                 #'response',
                 'body')

    def __init__(self, link):
        self.client = boto3.client('s3')
        self.bucket = 'amzn-s3-demo-bucket'
        self.name = 'OBJECT_NAME'
        response = self.client.get_object(Bucket=self.bucket,
                                          Key=self.name)
        self.body = response.get('Body')
        if not self.body:
            raise ValueError(f'Could not retrieve: {link}')

    def read(self, size=-1):
        if size < 0:
            return self.body.read()
        return self.body.read(size)

    def readinto(self, data):
        # https://docs.aws.amazon.com/botocore/latest/reference/response.html#botocore.response.StreamingBody
        return self.body.readinto(data)

    def close(self):
        self.body.close()
        self.client.close()


def fetcher(link):

    LOG.info('Fetching URI: %s', link)

    if link.startswith('s3://'):
        return S3Fetcher(link)

    return URLFetcher(link)
