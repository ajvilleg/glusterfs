#!/usr/bin/python

# GlusterFS uses four terms to describe the "character" of each node, based on
# which nodes it "accuses" (also "indicts") of having incomplete operations.
#
#	INNOCENT: accuses nobody
#	IGNORANT: no xattr, imputed zero value means same as INNOCENT
#	FOOL: accuses self
#	WISE: accuses someone else
#
# In the regular self-heal code, FOOL effectively overrides WISE.  Here we do
# the exact opposite, which is why we can heal cases that regular self-heal
# can't.
#
# Yes, there are jokes to be made about the psycho-social implications of
# letting folly trump wisdom or vice versa.

import atexit
import optparse
import os
import pipes
import shutil
import struct
import subprocess
import sys
import tempfile

import volfilter
import xattr

# This is here so that scripts (especially test scripts) can import without
# having to copy and paste code that "reaches" in to set these values.
class StubOpt:
	def __init__ (self):
		self.aggressive = False
		self.host = "localhost"
		self.verbose = False
options = StubOpt()

# It's just more convenient to have named fields.
class Brick:
	def __init__ (self, path, name, spath):
		self.path = path
		self.name = name
		self.spath = spath
	def __repr__ (self):
		return "Brick(%s,%s)" % (self.name,self.spath)

def get_bricks (host, vol):
	t = pipes.Template()
	t.prepend("gluster --remote-host=%s system getspec %s"%(host,vol),".-")
	return t.open(None,"r")

def generate_stanza (vf, all_xlators, cur_subvol):
	list = []
	for sv in cur_subvol.subvols:
		generate_stanza(vf,all_xlators,sv)
		list.append(sv.name)
	vf.write("volume %s\n"%cur_subvol.name)
	vf.write("  type %s\n"%cur_subvol.type)
	for kvpair in cur_subvol.opts.iteritems():
		vf.write("  option %s %s\n"%kvpair)
	if list:
		vf.write("  subvolumes %s\n"%string.join(list))
	vf.write("end-volume\n\n")

def mount_brick (localpath, all_xlators, dht_subvol):
	# Generate a volfile.
	vf_name = localpath + ".vol"
	vf = open(vf_name,"w")
	generate_stanza(vf,all_xlators,dht_subvol)
	vf.flush()
	vf.close()

	# Create a brick directory and mount the brick there.
	os.mkdir(localpath)
	subprocess.call(["glusterfs","-f",vf_name,localpath])

def all_are_same (rel_path):
	t = pipes.Template()
	t.prepend("md5sum %s/%s"%(bricks[0].path,rel_path),".-")
	first_sum = t.open(None,"r").readline().split(" ")[0]
	for b in bricks[1:]:
		t = pipes.Template()
		t.prepend("md5sum %s/%s"%(b.path,rel_path),".-")
		curr_sum = t.open(None,"r").readline().split(" ")[0]
		if curr_sum != first_sum:
			return False
	print "all files are the same for %s" % rel_path
	return True

class CopyFailExc (Exception):
	pass

def copy_contents (rel_path, source):
	srcfd = os.open("%s/%s"%(source.path,rel_path),os.O_RDONLY)
	dstfd_list = []
	for b in bricks:
		if b == source:
			continue
		dstfd = os.open("%s/%s"%(b.path,rel_path),os.O_WRONLY)
		dstfd_list.append(dstfd)
	try:
		wrote = 0
		while True:
			buf = os.read(srcfd,65536)
			if not buf:
				break
			bsz = len(buf)
			for dstfd in dstfd_list:
				n = os.write(dstfd,buf)
				if n < bsz:
					raise CopyFailExc(dstfd,n,bsz)
			wrote += len(buf)
		if options.verbose:
			print "copied %d bytes" % wrote
		for dstfd in dstfd_list:
			os.ftruncate(dstfd,wrote)
	except CopyFailExc as e:
		print "failed write: %s" % repr(e)
	for dstfd in dstfd_list:
		os.close(dstfd)
	os.close(srcfd)

def clear_xattrs (rel_path):
	for fbrick in bricks:
		abs_path = "%s/%s" % (fbrick.path, rel_path)
		for xbrick in bricks:
			xname = "trusted.afr.%s" % xbrick.name
			value = xattr.get(abs_path,xname)
			if value != -1:
				counts = struct.unpack(">III",value)
				value = struct.pack(">III",0,counts[1],counts[2])
				xattr.set(abs_path,xname,value)

# Return True if we healed, False if we weren't able to, None if we never even
# needed to.  Note that None evaluated as a boolean is false.
def heal_file (rel_path):

	# First, collect all of the xattr information.
	accusations = 0
	matrix = {}
	for viewer in bricks:
		tmp = {}
		abs_path = "%s/%s" % (viewer.path, rel_path)
		for target in bricks:
			xname = "trusted.afr.%s" % target.name
			value = xattr.get(abs_path,xname)
			if value == -1:
				counts = (0,0,0)
			else:
				counts = struct.unpack(">III",value)
			if options.verbose:
				print "%s:%s = %s" % (abs_path, xname, repr(counts))
			# For now, don't try to heal with pending metadata/entry ops.
			if counts[1]:
				print "Can't heal %s (%s metadata count for %s = %d)" % (
					abs_path, viewer.spath, target.spath, count[1])
				return False
			if counts[2]:
				print "Can't heal %s (%s entry count for %s = %d)" % (
					rel_path, viewer.spath, target.spath, count[1])
				return False
			if counts[0] != 0:
				accusations += 1
			tmp[target.name] = counts[0]
		matrix[viewer.name] = tmp
	# Might as well bail out early in this case.
	if accusations == 0:
		print "No heal needed for %s (no accusations)" % rel_path
		return None
	# If a node accuses itself, its accusations of others are suspect.  Whether
	# they stand depends on how the two counts that lead to the accusations
	# compare:
	#
	#	count for other node is greater: accusation stands
	#	two counts are equal: accusation is withdrawn
	#	count for self is greater: accusation is reversed
	#
	# Note that we have to do this to break accusation loops before we check
	# for split brain, so those have to be separate loops.
	if options.aggressive:
		for viewer in bricks:
			own_count = matrix[viewer.name][viewer.name]
			if not own_count:
				continue
			withdrawn = 0
			for target in bricks:
				if viewer == target:
					continue
				other_count = matrix[viewer.name][target.name]
				if other_count <= own_count:
					if options.verbose:
						print "withdrawing accusation %s => %s" % (
							viewer.spath, target.spath)
					matrix[viewer.name][target.name] = 0
					if other_count < own_count:
						if options.verbose:
							print "  reversing it as well"
						matrix[target.name][viewer.name] += 1
					withdrawn += 1
			# If all of our accusations of others stand, remove any self
			# accusation.
			if not withdrawn and matrix[viewer.name][viewer.name]:
				if options.verbose:
					print "clearing self-accusation for %s" % viewer.spath
				matrix[viewer.name][viewer.name] = 0
	# Always rule out regular split brain (mutual accusation).  If we're not
	# being aggressive, rule out internal split brain (accusation of self plus
	# others) as well.
	for viewer in bricks:
		for target in bricks:
			if viewer == target:
				continue
			if not matrix[viewer.name][target.name]:
				continue
			# Check for mutual accusation.
			if matrix[target.name][viewer.name]:
				print "Can't heal %s (%s and %s accuse each other)" % (
					rel_path, viewer.spath, target.spath)
				return False
			# Check for self+other accusation.
			if options.aggressive:
				continue
			if matrix[viewer.name][viewer.name]:
				print "Can't heal %s (%s accuses self+%s)" % (
					rel_path, viewer.spath, target.spath)
				return False
	# Any node that's no longer accused by anyone can be a source.  As a
	# tie-breaker, we choose the node that seems furthest ahead by virtue of
	# accusing others most strongly.
	source = None
	score = -1
	for candidate in bricks:
		for viewer in bricks:
			# If anyone accuses, candidate is rejected.
			if matrix[viewer.name][candidate.name]:
				break
		else:
			new_score = 0
			for target in bricks:
				if target != candidate:
					new_score += matrix[candidate.name][target.name]
					new_score += matrix[target.name][target.name]
			if new_score > score:
				source = candidate
				score = new_score
	# Did we get a valid source?
	if score > 0:
		print "Heal %s from %s to others" % (rel_path, source.spath)
		copy_contents(rel_path,source)
		clear_xattrs(rel_path)
		return True
	elif score == 0:
		print "Can't heal %s (accusations cancel out)" % rel_path
		print matrix
		return False
	else:
		print "Can't heal %s (no pristine source)" % rel_path
		return False

if __name__ == "__main__":

	my_usage = "%prog [options] volume brick path [...]"
	parser = optparse.OptionParser(usage=my_usage)
	parser.add_option("-a", "--aggressive", dest="aggressive",
					  default=False, action="store_true",
					  help="heal even for certain split-brain scenarios")
	parser.add_option("-H", "--host", dest="host",
					  default="localhost", action="store",
					  help="specify a server (for fetching volfile)")
	parser.add_option("-v", "--verbose", dest="verbose",
					  default=False, action="store_true",
					  help="verbose output")
	options, args = parser.parse_args()

	try:
		volume = args[0]
		brick_host, brick_path = args[1].split(":")
		paths = args[2:]
	except:
		parser.print_help()
		sys.exit(1)

	# Make sure stuff gets cleaned up, even if there are exceptions.
	orig_dir = os.getcwd()
	work_dir = tempfile.mkdtemp()
	bricks = []
	def cleanup_workdir ():
		os.chdir(orig_dir)
		if options.verbose:
			print "Cleaning up %s" % work_dir
		delete_ok = True
		for b in bricks:
			if subprocess.call(["umount",b.path]):
				# It would be really bad to delete without unmounting.
				print "Could not unmount %s" % b.path
				delete_ok = False
		if delete_ok:
			shutil.rmtree(work_dir)
	atexit.register(cleanup_workdir)
	os.chdir(work_dir)

	volfile_pipe = get_bricks(options.host,volume)
	all_xlators, last_xlator = volfilter.load(volfile_pipe)
	for client_vol in all_xlators.itervalues():
		if client_vol.type != "protocol/client":
			continue
		if client_vol.opts["remote-host"] == brick_host:
			if client_vol.opts["remote-subvolume"] == brick_path:
				break
	else:
		print "Client volume not found"
		sys.exit(1)
	if options.verbose:
		print "client volume is %s" % client_vol.name

	# TBD: enhance volfilter to save the parent
	for afr_vol in all_xlators.itervalues():
		if client_vol in afr_vol.subvols:
			break
	else:
		print "AFR volume not found"
		sys.exit(1)
	if options.verbose:
		print "AFR volume is %s" % afr_vol.name

	if len(afr_vol.subvols) > 2:
		print "More than two-way replication is not supported yet"
		sys.exit(1)

	# Mount each brick individually, so we can issue brick-specific calls.
	if options.verbose:
		print "Mounting subvolumes..."
	index = 0
	for sv in afr_vol.subvols:
		lpath = "%s/brick%s" % (work_dir, index)
		index += 1
		mount_brick(lpath,all_xlators,sv)
		spath = "%s:%s" % (sv.opts["remote-host"], sv.opts["remote-subvolume"])
		bricks.append(Brick(lpath,sv.name,spath))

	# Do the real work.
	for p in paths:
		if heal_file(p):
			continue
		if all_are_same(p):
			clear_xattrs(p)

