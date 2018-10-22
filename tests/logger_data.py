TEST_LOGGER = '''\
version: 1
root:
  level: NOTSET
  handlers: [noHandler]

loggers:
  lega:
    level: INFO
    handlers: [console]
    propagate: true
    qualname: lega

handlers:
  noHandler:
    class: logging.NullHandler
    level: NOTSET
  console:
    class: logging.StreamHandler
    formatter: simple
    stream: ext://sys.stdout

formatters:
  simple:
    format: '[{name:^10}][{levelname:^6}] (L{lineno}) {message}'
    style: '{'
'''
