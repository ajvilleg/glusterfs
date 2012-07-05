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
import string
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
		self.gfid_mismatch = False
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

def mount_brick (localpath, all_xlators, a_subvol):
	# Generate a volfile.
	vf_name = localpath + ".vol"
	vf = open(vf_name,"w")
	generate_stanza(vf,all_xlators,a_subvol)
	if options.gfid_mismatch:
		vf.write("volume %s-flipper\n"%a_subvol.name)
		vf.write("  type features/flipper\n")
		vf.write("  subvolumes %s\n"%a_subvol.name)
		vf.write("end-volume\n")
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
	return True

class CopyFailExc (Exception):
	pass

def clear_one_xattr (abs_path, xbrick):
		xname = "trusted.afr.%s" % xbrick.name
		value = xattr.get(abs_path,xname)
		if value != -1:
			counts = struct.unpack(">III",value)
			value = struct.pack(">III",0,counts[1],counts[2])
			xattr.set(abs_path,xname,value)

def clear_xattrs (rel_path):
	for fbrick in bricks:
		abs_path = "%s/%s" % (fbrick.path, rel_path)
		for xbrick in bricks:
			clear_one_xattr(abs_path,xbrick)

def remove_dups (rel_path, source):
	src_path = "%s/%s" % (source.path, rel_path)
	for b in bricks:
		if b == source:
			continue
		abs_path = "%s/%s" % (b.spath, rel_path)
		try:
			if options.verbose:
				"Unlinking %s" % abs_path
			os.unlink("%s/%s"%(b.path,rel_path))
		except OSError:
			print "Could not unlink %s" % abs_path

def fix_gfid (rel_path):
	abs_path = "%s/%s" % (bricks[0].path, rel_path)
	gfid = xattr.get(abs_path,"busted.gfid")
	if gfid == -1:
		print "Can't fix GFID (first missing)"
		return
	for b in bricks[1:]:
		abs_path = "%s/%s" % (bricks[0].path, rel_path)
		try:
			if options.verbose:
				print "Unlinking %s" % abs_path
			os.unlink(abs_path)
		except OSError:
			print "Failed to fix GFID on %s" % abs_path

# Possible return values:
#	"not needed"
#	"healed"
#	"heal failed"
#	"unsafe"
#	"gfid mismatch"
def heal_file (rel_path):

	# Sanity check for gfid mismatch.
	# This code is inoperative while requests for trusted.gfid are blocked.
	if options.gfid_mismatch:
		first_gfid = None
		for b in bricks:
			abs_path = "%s/%s" % (b.path, rel_path)
			gfid = xattr.get(abs_path,"busted.gfid")
			if gfid == -1:
				print "Couldn't get GFID on %s" % abs_path
				return "gfid mismatch"
			if not first_gfid:
				first_gfid = gfid
			elif gfid != first_gfid:
				print "GFID mismatch on %s" % abs_path
				return "gfid mismatch"

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
				print "FAILED TO GET %s:%s" % (abs_path, xname)
				counts = (0,0,0)
			else:
				counts = struct.unpack(">III",value)
			if options.verbose:
				print "%s:%s = %s" % (abs_path, xname, repr(counts))
			# For now, don't try to heal with pending metadata/entry ops.
			if counts[1]:
				print "Can't heal %s (%s metadata count for %s = %d)" % (
					abs_path, viewer.spath, target.spath, counts[1])
				return "unsafe"
			if counts[2]:
				print "Can't heal %s (%s entry count for %s = %d)" % (
					rel_path, viewer.spath, target.spath, counts[1])
				return "unsafe"
			if counts[0] != 0:
				accusations += 1
			tmp[target.name] = counts[0]
		matrix[viewer.name] = tmp
	# Might as well bail out early in this case.
	if accusations == 0:
		print "No heal needed for %s (no accusations)" % rel_path
		return "not needed"
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
				return "heal failed"
			# Check for self+other accusation.
			if options.aggressive:
				continue
			if matrix[viewer.name][viewer.name]:
				print "Can't heal %s (%s accuses self+%s)" % (
					rel_path, viewer.spath, target.spath)
				return "heal failed"
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
		remove_dups(rel_path,source)
		clear_xattrs(rel_path)
		return "healed"
	elif score == 0:
		print "Can't heal %s (accusations cancel out)" % rel_path
		print matrix
		return "heal failed"
	else:
		print "Can't heal %s (no pristine source)" % rel_path
		return "heal failed"

def touch_file (p, mode):
        abs_path = "%s/%s" % (parent_vol.path, p)
        if options.verbose:
                print "Touching %s (%s)" % (abs_path, mode)
        try:
                os.stat(abs_path)
        except OSError:
                print "Touching %s failed?!?" % abs_path

if __name__ == "__main__":

	my_usage = "%prog [options] volume brick path [...]"
	parser = optparse.OptionParser(usage=my_usage)
	parser.add_option("-a", "--aggressive", dest="aggressive",
					  default=False, action="store_true",
					  help="heal even for certain split-brain scenarios")
	parser.add_option("-g", "--gfid-mismatch", dest="gfid_mismatch",
					  default=False, action="store_true",
					  help="check for and (if aggressive) fix GFID mismatches")
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
	parent_vol = None
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
		if parent_vol:
			if subprocess.call(["umount",parent_vol.path]):
				print "Could not unmount %s" % parent_vol.path
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

	if options.verbose:
		print "Mounting parent volume..."
        lpath = "%s/parent" % work_dir
        mount_brick(lpath,all_xlators,afr_vol)
        parent_vol = Brick(lpath,afr_vol.name,"<parent>")

	# Do the real work.
	for p in paths:
		result = heal_file(p)
		if result == "healed":
			touch_file(p,"normal")
		if result in ("not needed", "healed", "unsafe"):
			continue
		if not all_are_same(p):
			print "Copies of %s diverge" % p
			continue
		if result == "gfid mismatch":
			if not options.aggressive:
				continue
			fix_gfid(p)
		clear_xattrs(p)
		touch_file(p,"aggressive")

