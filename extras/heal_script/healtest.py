#!/usr/bin/python

import atexit
import os
import shutil
import struct
import tempfile

import xattr
import healer

# Name, xattr values, aggr_mode, expected result, expected content
# Expected content is not used unless the expected result is True.
tests = (
	# Basic tests with no fool+wise nodes.
	( "noop",			(0,0,0,0), False,	"not needed",	None ),
	( "normal failure",	(0,1,0,1), False,	"healed",		"test-client-0" ),
	( "stale accuse",	(0,1,0,0), False,	"healed",		"test-client-0" ),
	( "admit guilt",	(0,0,0,1), False,	"healed",		"test-client-0" ),
	( "split brain",	(0,1,1,0), False,	"heal failed",	None ),
	( "two fools",		(1,0,0,1), False,	"heal failed",	None ),
	( "two fools aggr",	(1,0,0,1), True,	"heal failed",	None ),
	# Tests with fool+wise nodes but no mutual accusation.
	( "fool+wise",		(1,1,0,0), False,	"heal failed",	None ),
	( "fw stand",		(1,2,0,0), True,	"healed",		"test-client-0" ),
	( "fw withdraw",	(1,1,0,0), True,	"healed",		"test-client-1" ),
	( "fw reverse",		(2,1,0,0), True,	"healed",		"test-client-1" ),
	( "fw+fool",		(1,1,0,1), False,	"heal failed",	None ),
	( "fw+fool aggr",	(1,1,0,1), True,	"heal failed",	None ),
	# Tests with mutual accusation (classic split brain).
	( "fw+accuse",		(1,1,1,0), False,	"heal failed",	None ),
	( "fw+accuse aggr",	(1,1,1,0), True,	"healed",		"test-client-1" ),
)

# TBD: unsafe (non-zero meta/entry count), gfid mismatch
# more than two nodes (including tie-breaker).

def create_files (name, xa_values, fnum):
	index = 0
	for b in bricks:
		abs_path = "%s/%s" % (b.path, name)
		fp = open(abs_path,"w")
		fp.write(b.name)
		xattr.set(abs_path,"trusted.gfid","bogus GFID %d"%fnum)
		for b2 in bricks:
			xname = "trusted.afr.%s" % b2.name
			value = struct.pack(">III",xa_values[index],0,0)
			index += 1
			xattr.set(abs_path,xname,value)

def check_content (name, content):
	found = 0
	for b in bricks:
		abs_path = "%s/%s" % (b.path, name)
		try:
			fp = open(abs_path,"r")
		except IOError:
			continue
		if fp.readlines() != [content]:
			return False
		found += 1
	return (found > 0)

def check_xattrs (name):
	for b in bricks:
		abs_path = "%s/%s" % (b.path, name)
		for b2 in bricks:
			xname = "trusted.afr.test-%s" % b2.name
			value = xattr.get(abs_path,xname)
			if value == -1:
				continue
			counts = struct.unpack(">III",value)
			if counts[0]:
				print "%s:%s = %d" % (abs_path, xname, counts[0])
				return False
	return True

def run_test (index, xa_values, aggr_mode, exp_result, content):
	fname = "test%d" % index
	create_files(fname,xa_values,index)
	healer.options.aggressive = aggr_mode
	act_result = healer.heal_file(fname)
	if act_result != exp_result:
		print "WRONG RESULT"
		return False
	if act_result == "healed":
		if not check_content(fname,content):
			print "DATA MISMATCH"
			return False
		if not check_xattrs(fname):
			print "XATTRS NOT CLEARED"
	return True

# Make sure stuff gets cleaned up, even if there are exceptions.
orig_dir = os.getcwd()
work_dir = tempfile.mkdtemp(prefix=orig_dir+"/test_")
bricks = []
def cleanup_workdir ():
	os.chdir(orig_dir)
	shutil.rmtree(work_dir)
atexit.register(cleanup_workdir)
os.chdir(work_dir)

for index in (0,1):
	lpath = "%s/brick%d" % (work_dir, index)
	sv_name = "test-client-%d" % index
	spath = "server-%d:/export" % index
	os.mkdir(lpath)
	bricks.append(healer.Brick(lpath,sv_name,spath))
healer.bricks = bricks

#healer.options.verbose = True

passed = 0
failed = 0
index = 0
for name, xa_values, aggr_mode, result, content in tests:
	if run_test(index,xa_values,aggr_mode,result,content):
		print "PASSED %s" % name
		passed += 1
	else:
		print "FAILED %s" % name
		failed += 1
		#break
	index += 1

if failed:
	print "Overall result: FAIL (%d passed, %d failed)" % (passed, failed)
else:
	print "Overall result: OK (%d passed, %d failed)" % (passed, failed)


