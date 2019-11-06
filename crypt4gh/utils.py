import logging

from .header import parse_edit_list_packet

LOG = logging.getLogger(__name__)

class ProcessingOver(Exception):
    pass

#
# This could be implemented using the oracle below and passing [offset, limit] or just [offset]
# We still keep this version as is seems simpler
def limited_output(offset=0, limit=None, process=None):
    '''Generator that receives clear text and does not process more than limit bytes (if limit is not None).

    Raises ProcessingOver if the limit is reached'''

    LOG.debug('Slicing from %s | Keeping %s bytes', offset, 'all' if limit is None else limit)

    if not callable(process):
        raise ValueError('process_output is not callable')

    assert( 
        (isinstance(offset, int) and offset >= 0)
        and
        (limit is None
         or
         (isinstance(limit, int) and limit > 0))
    )

    while True:
        data = yield
        data_len = len(data)

        if data_len < offset: # not enough data to chop off
            offset -= data_len
            continue # ignore output

        if limit is None:
            process(data[offset:])  # no copying here if offset=0!
        else:

            if limit < (data_len - offset): # should stop early
                process(data[offset:limit+offset])
                raise ProcessingOver()
            else:
                process(data[offset:])  # no copying here if offset=0!
                limit -= (data_len - offset)

        offset = 0 # reset offset



# def edit_list_oracle(edit_packet):
#     '''Generator receiving a data length value and yielding a tuple, of the form:

#     - None: the data is not used
#     - []: the data is entirely used
#     - [items]: the data is used and sliced
#       items is of the form: (x,y)
#       * if y is None: the data is sliced with [x:] (and it should be the last item of the list)
#       * if y is not None: the data is sliced with [x:y]

#     edit_packet cannot be None
    
#     '''

#     assert(edit_packet)

#     edits = collections.deque(parse_edit_list_packet(edit_packet))
#     # We want O(1) operations when popping the first elements


def edit_list_oracle(edits):
    data_len = yield # first stop

    skip = edits.popleft()
    keep = edits.popleft() if edits else None

    while True:

        #assert data_len, "You should not advance the generator with a 0-length"
        while data_len <= 0:
            data_len = yield None

        if data_len <= skip:
            skip -= data_len
            data_len = yield None
            continue

        # now data_len > skip so we should slice the data segment

        if keep is None: # to EOF
            # We should output to the end of the stream
            # Say yes all the time, except the first skip
            data_len = yield ([(skip, None)] if skip else [])
            while True:
                yield []

        # else, we should now read only some bytes
        if data_len - skip <= keep: # we still have bytes to read
            keep -= (data_len-skip)
            data_len = yield ([(skip, None)] if skip else [])
            skip = 0

            while data_len <= keep:
                keep -= data_len
                data_len = yield [] # keep all
                

        # data_len >  skip + keep: we need to pull the other (skip,keep) from the edit list
        pos = skip + keep
        slices = [(skip, pos)] if pos else []

        while True:

            if not edits: 
                if slices:
                    yield slices
                raise ProcessingOver() # game over

            skip = edits.popleft()
            assert( skip > 0 )
            keep = edits.popleft() if edits else None

            if pos + skip < data_len: # we need to skip some part
                if keep is None:
                    slices.append( (pos+skip, None) )
                    skip = 0
                    break

                if pos+skip+keep <= data_len:
                    slices.append( (pos+skip, pos+skip+keep) )
                    pos = pos + skip + keep
                    # skip = 0
                    continue
                
                # pos+skip+keep > data_len
                keep -= (data_len - pos - skip)
                skip = 0
                # loop

            else:
                # we don't add anything to the slices, and exit the while loop
                # skip for the next coming data
                skip -= (data_len - pos)
                break
                
        data_len = yield slices


if __name__ == '__main__':

    all_edit_lists = [
        [10,1,
         20,2,
         30 + 65536 -10 -1 -20 -2, 3,
         40 + 65536 -30 -3, 4,
         50 + 65536 -40 -4, 5,
         60 + 65536 -50 -5
        ],

        [2 * 65536 + 100, 200, 100 ], # to EOF

        [2 * 65536 + 100, 200, 100, 4 ],

        [65535, 65538],

        [1,1,1,1,1,1],
        [1,1,1,1,1,1,1],

        [0, 65536],
    ]

    import collections

    entire_file = [65536 for i in range(6)]
    entire_file.append(100)

    for edits in all_edit_lists:
        print( "Edit List: ", edits )

        edits = collections.deque(edits)
        oracle = edit_list_oracle(edits)
        next(oracle)

        try:
            for segment in entire_file:
                print( f"Sending {segment} bytes | slices: ", oracle.send(segment) )
        except ProcessingOver:
            pass


