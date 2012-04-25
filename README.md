This is experimental code for lower-latency replication.  It avoids locks
altogether, and gets network xattr ("changelog") updates out of the latency
path.  It consists of three parts.

* hsrepl: a client-side translator that sits above AFR, and processes data
  writes (only!) using its own protocol.  All other operations are passed to
  AFR for the same processing as always.

* helper: a server-side translator that does conflict detection for hsrepl,
  and also does an xattr increment automatically as part of a (special)
  write.

* other: various changes (mostly at the RPC level) to support hsrepl/helper.

Note that this is only intended to help for synchronous writes.  In the vast
majority of cases, writes are asynchronous and this isn't needed.  However,
there are some particularly demanding and important cases - e.g. hosting
virtual-machine images or applications with embedded database functionality -
which do expect synchronous behavior and can benefit from lower-latency
replication.  The only major limitation right now is that the code only works
for two-way replication.

If you're feeling *very* adventurous, the "cluster.hsrepl" volume option will
take care of inserting the hsrepl and helper translators.  I welcome feedback
on how much benefit it provides for various configurations and workloads (in
my own testing it was as much as 2x).  However, remember that it's very young
code and work is still in progress.  There are no guarantees.  If that's a
problem for you, you'd do better to wait until it's finished.
