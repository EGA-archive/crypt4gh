# Configure tests to print the docstrings (and class+function names if no docstrings)

def pytest_itemcollected(item):
    par = item.parent.obj
    node = item.obj
    # First line only
    prefix = par.__doc__.split('\n',1)[0].strip() if par.__doc__ else par.__class__.__name__
    suffix = node.__doc__.split('\n',1)[0].strip() if node.__doc__ else node.__name__
    if prefix or suffix:
        item._nodeid = ' | '.join((prefix, suffix))
