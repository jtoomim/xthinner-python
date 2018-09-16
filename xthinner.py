#!/usr/bin/env python
import json, cStringIO, traceback, sys, os, urllib2, random


blockfilename = '000000000000000001c37467f0843dd9e09536c21938c5c20551191788a70541'
mempoolfilenames = ['00000000000000000008658cdaba34569f00748085df3923cb5287e55a2fe27c', 
                    '000000000000000000328e4b6f34904c9525e4815c1a32a9e55a3ec6b0e5afa6',
                    '00000000000000000175b9186c4004b77ea9dc61976f4d7aed140d10919d0c05']
debug = '--debug' in sys.argv or '-d' in sys.argv

def maybedownload(fn):
    if not os.path.exists(fn):
        print "downloading block %s" % fn
        response = urllib2.urlopen('http://toom.im/files/%s' % fn)
        html = response.read()
        with open(fn, 'w') as f:
            f.write(html)

def fetchtxsfromfile(fn):
    maybedownload(fn)
    with open(fn, 'r') as f:
        raw = f.read()
    block = json.loads(raw)
    return [tx.decode('hex') for tx in block['tx']]
def buildmempool(fns):
    mempool = []
    for fn in fns:
        mempool.extend(fetchtxsfromfile(fn))
    mempool.sort()
    return mempool

def make_bitmap(bitlist):
    """
    Generates a bitmap for which values in counts equal 1, plus a list of the residuals
    """
    bits = [1<<(i%8) if bitlist[i] == 1 else 0 for i in range(len(bitlist))]
    byts = [chr(sum(bits[8*i:8*(i+1)])) for i in range((len(bits)+7)/8)]
    ''.join(byts)
    return ''.join(byts)

def unmake_bitmap(bitmap):
    n_vals = []
    for byte in map(ord, bitmap):
        for n in range(8):
            n_vals.append(byte & 1<<n)
    return n_vals


def encode_xthinner(block, mempool, checksumpositions=[], checksumintervals=[]):
    # The encoding scheme is basically encoding the transactions as a prefix tree
    # except that we omit all bytes that are not necessary to disambiguate a tx 
    # from the recipient's mempool.
    # The algorithm for encoding our tree uses a stack which we interact with in four 
    # possible operations per transaction:
    # 1. We can pop 1 or more bytes off the stack.
    # 2. We can push 1 or more bytes onto the stack
    # 3. We can commit to a transaction that uses the prefix encoded in the stack.
    # 4. We can accumulate into zero or more checksum bytes
    # For the pop stage, we encode a 1 for every pop we do after the first, and a 0 when done
    # for the push stage, we encode a 1 for every push we do after the first, and a 0 when done
    # For the commit stage, we encode nothing, as it's implicit as the 0 from the push stage.

    # Finally, we encode 1-byte error detection checksums at a few different levels
    # E.g. sum a byte from every 8 tx into a 1st-order checksum
    # and sum a byte from every 32 tx into a 2nd-order checksum
    # and sum a byte from every 128 tx into a 3rd-order checksum

    stack = []
    blockposition = 0
    mempoolposition = 0
    pops = []
    pushes = []
    pushbytes = []
    assert len(checksumpositions) == len(checksumintervals)
    checksums     = [0  for i in range(len(checksumpositions))]
    donechecksums = [[] for i in range(len(checksumpositions))]
    mempool.append(chr(0)*32) # OOB-protection dummy hash
    for tx in block:
        # 1. We pop bytes off the stack that don't match our current tx
        # First pop is a freebie (unless we're just getting started)
        if debug: print "%s is next tx" % tx.encode('hex')
        if stack: stack.pop()
        try:
          for i in range(len(stack)):
            if stack[i] != tx[i]:
                for j in range(len(stack)-i):
                    stack.pop()
                    pops.append(1)
                if debug: print "%s popped %i bytes" % (''.join([s.encode('hex') for s in stack]), i)
                break
        except:
          traceback.print_exc()
          print "i=%i, stack=%s, tx=%s" % (i, ''.join(stack).encode('hex'), tx.encode('hex'))
          sys.exit(1)
        if debug and pops and pops[-1] == 0: # missed debug message from 0 bytes popped
                    print "%s popped 1 byte" % (''.join([s.encode('hex') for s in stack]))
        pops.append(0) # end of pop stage

        # 2. We push bytes onto the stack in order to disambiguate between neighboring
        # mempool transactions (assuming mempool is sorted)
        # 2(a). Where is this transaction in the mempool?
        #mempoolposition = mempool.find(tx) # fixme: O(n); we should do a linear search from previous position instead
        while mempool[mempoolposition] != tx:
            mempoolposition += 1

        # 2(b) First push is a freebie
        stack.append(tx[len(stack)])
        pushbytes.append(stack[-1])

        # 2(c).  Push enough bytes so that we can disambiguate between mempool neighbors
        i = 0 # for debug only
        if debug: print "%s is mempoolprev" % mempool[mempoolposition-1].encode('hex')
        if debug: print "%s is mempoolnext" % mempool[mempoolposition+1].encode('hex')
        while ''.join(stack) in (mempool[mempoolposition-1][:len(stack)], 
                                 mempool[mempoolposition+1][:len(stack)]):
            pushes.append(1)
            stack.append(tx[len(stack)])
            pushbytes.append(stack[-1])
            i += 1 # for debug only
        pushes.append(0)
        if debug: print "%s pushed %i bytes: %s" % (''.join([s.encode('hex') for s in stack]), i+1, ''.join([s.encode('hex') for s in stack[-i:]]))

        # 3. Commit the transaction
        # This page is intentionally left blank

        # 4. Calculate checksums
        for i in range(len(checksumpositions)):
            checksums[i] ^= ord(tx[checksumpositions[i]])
            if blockposition % checksumintervals[i] == 0 or blockposition == len(block):
                donechecksums[i].append(checksums[i])
                checksums[i] = 0

        blockposition += 1
        mempoolposition += 1
    mempool.pop() # get rid of OOB-prevention dummy tx

    bitpops = make_bitmap(pops)
    bitpushes = make_bitmap(pushes)
    if debug:
        print pops
        print pushes
        print [s.encode('hex') for s in pushbytes]
        for s in [s.encode('hex') for s in block[:10]]:
            print s
    print "Encoding finished! %i pops, %i pushes, %i pushbytes, %i checksum bytes" % (len(pops), len(pushes), len(pushbytes), sum(map(len, donechecksums)))
    return bitpops, bitpushes, pushbytes, donechecksums, len(block), checksumpositions, checksumintervals

def decode_xthinner(encoding, mempool):
    print "Beginning decode"
    pops = unmake_bitmap(encoding[0])
    pushes = unmake_bitmap(encoding[1])
    pushbytes = encoding[2]
    popi = 0 # pop index
    pushi = 0
    pushbi = 0
    donechecksums = encoding[3]
    txcount = encoding[4]
    checksumpositions = encoding[5]
    checksumintervals = encoding[6]
    checksums = [0  for i in range(len(checksumpositions))]
    badchecksums = [[]  for i in range(len(checksumpositions))]
    expectbadchecksums = [0 for i in range(len(checksumpositions))]
    block = []
    stack = []
    mempoolposition = 0
    rerequests = []
    mempool.append(chr(255)*32) # OOB-protection dummy hash


    for blockposition in range(txcount):
        # 1. Pop bytes off the stack
        if stack: stack.pop()
        pop = pops[popi]
        popi += 1
        while pop:
            stack.pop()
            pop = pops[popi]
            popi += 1
        if debug: print "%s after pops" % (''.join([s.encode('hex') for s in stack]))

        # 2. Push bytes onto the stack
        stack.append(pushbytes[pushbi])
        pushbi += 1
        push = pushes[pushi]
        pushi += 1
        while push:
            stack.append(pushbytes[pushbi])
            pushbi += 1
            push = pushes[pushi]
            pushi += 1
        if debug: print "%s after pushes" % (''.join([s.encode('hex') for s in stack]))
        

        # 3. Commit the transaction to the block
        while mempoolposition < len(mempool)-1 and ''.join(stack) > mempool[mempoolposition]:
            mempoolposition += 1
        # Check for ambiguities (multiple possible matches to stack)
        if mempoolposition < len(mempool)-2 and mempool[mempoolposition+1][:len(stack)] == ''.join(stack):
            block.append(''.join(stack)) # We can't get the whole TXID, so we'll just insert this placeholder
            rerequests.append(len(block)) # We'll have to ask the block sender to tell us the full TXID at this pos
            if debug: print "%s is ambiguous with %s" % (''.join([s.encode('hex') for s in stack]), mempool[mempoolposition+1].encode('hex'))
        else:
            block.append(mempool[mempoolposition])
            if debug: print "%s uniquely matches with %s (pos=%i)" % (''.join([s.encode('hex') for s in stack]), mempool[mempoolposition].encode('hex'), mempoolposition)
            for i in range(len(checksumpositions)):
                checksums[i] ^= ord(block[-1][checksumpositions[i]])

        # 4. Check checksums
        for i in range(len(checksumpositions)):
            if blockposition % checksumintervals[i] == 0:
                if not donechecksums[i][blockposition//checksumintervals[i]] == checksums[i]:
                    if debug: print "Checksum error at blockposition %i, checksumposition %i" % (blockposition, i)
                    badchecksums[i].append(blockposition)
                checksums[i] = 0

        if debug: print "Remaining: %i pops, %i pushes, %i pushbytes, %i checksum bytes" % (len(pops), len(pushes), len(pushbytes), sum(map(len, donechecksums)))
            


    # 4. Check checksums
    for i in range(len(checksumpositions)):
        if blockposition % checksumintervals[i] == 0 or blockposition == txcount-1:
            if not donechecksums[i][blockposition//checksumintervals[i]] == checksums[i]:
                if debug: print "Checksum error at blockposition %i, checksumposition %i" % (blockposition, i)
                badchecksums[i].append(blockposition)
            checksums[i] = 0

    mempool.pop() # get rid of OOB-prevention dummy tx
    assert len(pushbytes) == pushbi
    if debug: print "Recovered %i of %i transactions in block" % (len(block) - len(rerequests), len(block))
    return block, rerequests


if __name__ == '__main__':

    if '-h' in sys.argv or '--help' in sys.argv:
        print """Usage:
        bitcoin-cli getblock somehash > someblock
        # edit the filenames into the  blockfilenames or mempoolfilenames variables in the code, then3
        python xthinner.py
        """
        sys.exit()

    block = fetchtxsfromfile(blockfilename)
    coinbase = block.pop(0)
    mempool = buildmempool(mempoolfilenames + [blockfilename])
    print "%i tx in block, %i tx in mempool (%2.0f%%)" % (len(block), len(mempool), 100.*len(block)/len(mempool))
    block.sort()
    encoding = encode_xthinner(block, mempool, [random.randint(6, 32) for i in range(4)], [8, 64, 256, 1024])
    print "Encoding is %i bytes total" % (sum(map(len, encoding[:3] + tuple(encoding[3]) + encoding[6:])) + 4)
    decoded, rerequests = decode_xthinner(encoding, mempool)
    print "Does decoded match original block?\t", decoded == block

